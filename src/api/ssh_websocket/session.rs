use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use futures::{stream::SplitStream, StreamExt};
use std::{env, net::TcpStream, io::{Read, Write}, time::Duration};
use tokio::sync::mpsc::UnboundedSender;
use ssh2::Session as Ssh2Session;
use warp::ws::{Message, WebSocket};
use log::{info, error};
use crate::host_key::HostKeyService;

use super::super::ssh_websocket::get_ws_stdout;

pub struct Session {
    addr: String,
    user: String,
    pwd: String,
    key: String,
    auth_type: AuthType,
    cols: u32,
    rows: u32,
}

#[derive(Debug, Clone)]
enum AuthType {
    Password,
    Key,
}

#[derive(Debug, Deserialize)]
struct SSHData {
    #[serde(rename = "type")]
    msg_type: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct Size {
    #[serde(rename = "type")]
    msg_type: String,
    cols: u32,
    rows: u32,
}

impl Session {
    pub fn new() -> Session {
        Session {
            addr: String::new(),
            user: String::new(),
            pwd: String::new(),
            key: String::new(),
            auth_type: AuthType::Password,
            cols: 80,
            rows: 24,
        }
    }

    fn connect(&self) -> anyhow::Result<Ssh2Session> {
        // 建立 TCP 连接
        let tcp = TcpStream::connect(&self.addr)?;
        tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(30)))?;

        // 创建 SSH 会话
        let mut sess = Ssh2Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        // 认证
        match self.auth_type {
            AuthType::Password => {
                sess.userauth_password(&self.user, &self.pwd)?;
            }
            AuthType::Key => {
                // 将私钥写入临时文件
                let temp_dir = env::temp_dir();
                let key_path = temp_dir.join(format!("ssh_key_{}", std::process::id()));
                std::fs::write(&key_path, &self.key)?;

                let passphrase = if self.pwd.is_empty() { None } else { Some(&self.pwd[..]) };
                sess.userauth_pubkey_file(&self.user, None, &key_path, passphrase)?;

                // 删除临时文件
                let _ = std::fs::remove_file(&key_path);
            }
        }

        if !sess.authenticated() {
            return Err(anyhow!("认证失败"));
        }

        Ok(sess)
    }

    pub async fn run(
        &mut self,
        mut user_rx: SplitStream<WebSocket>,
        tx: &UnboundedSender<Message>,
        host_key_service: HostKeyService,
    ) -> anyhow::Result<u32> {
        // 第一阶段：接收连接参数
        while let Some(result) = user_rx.next().await {
            let msg = result?;

            if let Ok(text) = msg.to_str() {
                if let Ok(data) = serde_json::from_str::<SSHData>(text) {
                    match data.msg_type.as_str() {
                        "addr" => {
                            if let Ok(b) = general_purpose::STANDARD.decode(&data.data) {
                                self.addr = String::from_utf8(b)?;
                            }
                        }
                        "login" => {
                            if let Ok(b) = general_purpose::STANDARD.decode(&data.data) {
                                self.user = String::from_utf8(b)?;
                            }
                        }
                        "password" => {
                            if let Ok(b) = general_purpose::STANDARD.decode(&data.data) {
                                self.pwd = String::from_utf8(b)?;
                                self.auth_type = AuthType::Password;
                            }
                        }
                        "key" => {
                            if let Ok(b) = general_purpose::STANDARD.decode(&data.data) {
                                self.key = String::from_utf8(b)?;
                                self.auth_type = AuthType::Key;
                            }
                        }
                        "connect" => {
                            // 收到连接命令，退出参数接收循环
                            break;
                        }
                        _ => {}
                    }
                } else if let Ok(size) = serde_json::from_str::<Size>(text) {
                    if size.msg_type == "resize" {
                        self.cols = size.cols;
                        self.rows = size.rows;
                    }
                }
            }
        }

        // 克隆必要的数据以便在 blocking 任务中使用
        let addr = self.addr.clone();
        let user = self.user.clone();
        let pwd = self.pwd.clone();
        let key = self.key.clone();
        let auth_type = self.auth_type.clone();
        let cols = self.cols;
        let rows = self.rows;
        let tx_clone = tx.clone();

        // 在 blocking 线程中建立 SSH 连接
        let sess = tokio::task::spawn_blocking(move || {
            let session = Session {
                addr,
                user,
                pwd,
                key,
                auth_type,
                cols,
                rows,
            };
            session.connect()
        }).await??;

        info!("SSH 连接成功: {}@{}", self.user, self.addr);

        // 创建通道用于在 blocking 任务和 async 任务之间传递数据
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (resize_tx, mut resize_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();

        // 在 blocking 线程中处理 SSH 会话
        let ssh_handle = tokio::task::spawn_blocking(move || {
            let mut channel = sess.channel_session().map_err(|e| anyhow!("创建通道失败: {}", e))?;

            // 请求 PTY
            channel.request_pty(
                &env::var("TERM").unwrap_or("xterm".into()),
                None,
                Some((cols, rows, 0, 0))
            ).map_err(|e| anyhow!("请求 PTY 失败: {}", e))?;

            // 启动 shell
            channel.shell().map_err(|e| anyhow!("启动 shell 失败: {}", e))?;

            // 设置非阻塞模式
            sess.set_blocking(false);

            let mut buffer = [0u8; 4096];

            loop {
                // 检查是否有调整大小的请求
                if let Ok((cols, rows)) = resize_rx.try_recv() {
                    let _ = channel.request_pty_size(cols, rows, None, None);
                }

                // 检查是否有输入数据
                if let Ok(data) = stdin_rx.try_recv() {
                    if let Err(e) = channel.write_all(&data) {
                        error!("写入 SSH 通道失败: {}", e);
                        break;
                    }
                }

                // 读取 SSH 输出
                match channel.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let data = &buffer[..n];
                        match String::from_utf8(data.to_vec()) {
                            Ok(text) => {
                                let msg = get_ws_stdout(text);
                                let _ = tx_clone.send(msg);
                            }
                            Err(_) => {
                                // 如果不是有效的 UTF-8，使用 lossy 转换
                                let text = String::from_utf8_lossy(data).into_owned();
                                let msg = get_ws_stdout(text);
                                let _ = tx_clone.send(msg);
                            }
                        }
                    }
                    Ok(_) => {
                        // 没有数据，继续
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                        // 超时，继续
                    }
                    Err(e) => {
                        error!("读取 SSH 通道失败: {}", e);
                        break;
                    }
                }

                // 检查通道是否已关闭
                if channel.eof() {
                    break;
                }

                std::thread::sleep(Duration::from_millis(10));
            }

            let exit_status = channel.exit_status().unwrap_or(0);
            let text = format!("\r\n会话结束，退出码: {}\r\n", exit_status);
            let msg = get_ws_stdout(text);
            let _ = tx_clone.send(msg);

            Ok::<u32, anyhow::Error>(exit_status as u32)
        });

        // 处理来自 WebSocket 的消息
        while let Some(result) = user_rx.next().await {
            if let Err(e) = result {
                error!("WebSocket 接收错误: {}", e);
                break;
            }

            let msg = result.unwrap();

            if let Ok(text) = msg.to_str() {
                if let Ok(data) = serde_json::from_str::<SSHData>(text) {
                    if data.msg_type == "stdin" {
                        if let Ok(b) = general_purpose::STANDARD.decode(&data.data) {
                            let _ = stdin_tx.send(b);
                        }
                    }
                } else if let Ok(size) = serde_json::from_str::<Size>(text) {
                    if size.msg_type == "resize" {
                        let _ = resize_tx.send((size.cols, size.rows));
                    }
                }
            }

            // 检查 SSH 任务是否已完成
            if ssh_handle.is_finished() {
                break;
            }
        }

        // 等待 SSH 任务完成
        let code = ssh_handle.await??;

        Ok(code)
    }
}

