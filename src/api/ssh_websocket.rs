mod session;

use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use futures::{StreamExt, SinkExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::ws::{Message, WebSocket};
use log::{info, error};
use warp::{Filter, Rejection, Reply};
use crate::auth::AuthService;
use crate::audit::{AuditService, AuditAction};
use crate::host_key::HostKeyService;

use session::Session;

pub fn route_ssh_websocket(
    auth_service: AuthService,
    audit_service: AuditService,
    host_key_service: HostKeyService,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "ssh")
        .and(warp::ws())
        .and(warp::query::<AuthQuery>())
        .and(with_auth_service(auth_service))
        .and(with_audit_service(audit_service))
        .and(with_host_key_service(host_key_service))
        .map(|ws: warp::ws::Ws, query: AuthQuery, auth_service: AuthService, audit_service: AuditService, host_key_service: HostKeyService| {
            ws.on_upgrade(move |socket| ws_start(socket, query, auth_service, audit_service, host_key_service))
        })
}

fn with_auth_service(
    service: AuthService,
) -> impl Filter<Extract = (AuthService,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

fn with_audit_service(
    service: AuditService,
) -> impl Filter<Extract = (AuditService,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

fn with_host_key_service(
    service: HostKeyService,
) -> impl Filter<Extract = (HostKeyService,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

#[derive(Debug, serde::Deserialize)]
struct AuthQuery {
    token: Option<String>,
}

async fn ws_start(
    ws: WebSocket,
    query: AuthQuery,
    auth_service: AuthService,
    audit_service: AuditService,
    host_key_service: HostKeyService,
) {
    info!("WebSocket 连接建立");

    // Verify token if provided
    let user_info = if let Some(token) = query.token {
        match auth_service.verify_token(&token) {
            Ok(claims) => Some((claims.sub, claims.username)),
            Err(_) => {
                error!("Invalid token");
                return;
            }
        }
    } else {
        None
    };

    // 分离 WebSocket 为发送和接收通道
    let (mut ws_tx, ws_rx) = ws.split();

    // 创建无界通道用于缓冲消息
    let (tx, rx) = mpsc::unbounded_channel();
    let mut rx = UnboundedReceiverStream::new(rx);

    // 启动异步任务将消息从通道发送到 WebSocket
    tokio::task::spawn(async move {
        while let Some(message) = rx.next().await {
            if let Err(e) = ws_tx.send(message).await {
                error!("WebSocket 发送错误: {}", e);
                break;
            }
        }
    });

    // 创建 SSH 会话
    let mut ssh = Session::new();

    let result = ssh.run(ws_rx, &tx, host_key_service.clone()).await;

    // Log SSH session
    if let Some((user_id, username)) = user_info {
        let success = result.is_ok();
        audit_service.log(
            &user_id,
            &username,
            if success { AuditAction::SshDisconnect } else { AuditAction::SshConnect },
            "ssh",
            result.as_ref().err().map(|e| e.to_string()),
            None,
            success,
        );
    }

    if let Err(e) = result {
        error!("SSH 会话错误: {}", e);
        let msg = get_ws_stderr(e.to_string());
        let _ = tx.send(msg);
    }

    info!("WebSocket 连接关闭");
}

pub fn get_ws_stdout(s: String) -> Message {
    let s = general_purpose::STANDARD.encode(s);
    let json = json!({"type": "stdout", "data": s});
    let text = json.to_string();
    Message::text(text)
}

pub fn get_ws_stderr(s: String) -> Message {
    let s = general_purpose::STANDARD.encode(s);
    let json = json!({"type": "stderr", "data": s});
    let text = json.to_string();
    Message::text(text)
}

