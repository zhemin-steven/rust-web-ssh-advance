/**
 * Web SSH Server
 * Author: steven
 * A simple web-based SSH server using Rust, warp, and ssh2
 */

mod api;
mod auth;
mod ssh_config;
mod audit;
mod host_key;
mod crypto;

use std::net::SocketAddr;
use std::sync::Arc;
use warp::Filter;
use log::info;
use std::fs;
use std::io::{self, Write};
use auth::AuthService;
use ssh_config::SshConfigService;
use audit::AuditService;
use host_key::HostKeyService;
use crypto::CryptoService;

/// Get master password from multiple sources (priority order):
/// 1. Environment variable: WEBSSH_MASTER_PASSWORD
/// 2. File: ./master_password.txt
/// 3. Interactive input (stdin)
fn get_master_password() -> String {
    // 1. Try environment variable
    if let Ok(password) = std::env::var("WEBSSH_MASTER_PASSWORD") {
        if !password.is_empty() {
            info!("Master password loaded from environment variable");
            return password;
        }
    }

    // 2. Try password file
    if let Ok(password) = fs::read_to_string("master_password.txt") {
        let password = password.trim().to_string();
        if !password.is_empty() {
            info!("Master password loaded from master_password.txt");
            return password;
        }
    }

    // 3. Interactive input
    println!("\n===========================================");
    println!("  WebSSH Server - Master Password");
    println!("===========================================\n");
    println!("Enter master password to decrypt SSH configurations:");
    println!("(First time: set a strong password. Subsequent: use the same password)");
    println!("\nTip: For non-interactive mode, use:");
    println!("  - Environment variable: export WEBSSH_MASTER_PASSWORD='your_password'");
    println!("  - Password file: echo 'your_password' > master_password.txt\n");

    io::stdout().flush().unwrap();

    rpassword::read_password()
        .expect("Failed to read password")
}

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Get master password from multiple sources
    let master_password = get_master_password();

    if master_password.is_empty() {
        eprintln!("Error: Master password cannot be empty");
        std::process::exit(1);
    }

    info!("Initializing encryption service...");

    // Initialize services
    let auth_service = AuthService::new();
    let crypto_service = Arc::new(CryptoService::new(&master_password));
    let ssh_config_service = SshConfigService::new(crypto_service.clone());
    let audit_service = AuditService::new();
    let host_key_service = HostKeyService::new();

    info!("Default admin account: admin / admin");
    println!("\n✅ Services initialized successfully!");

    // Server address
    let socket_address: SocketAddr = "0.0.0.0:18022".parse().unwrap();

    // Setup routes
    let ws_ssh = api::ssh_websocket::route_ssh_websocket(
        auth_service.clone(),
        audit_service.clone(),
        host_key_service.clone(),
    );
    let auth_routes = api::auth::route_auth(auth_service.clone(), audit_service.clone());
    let config_routes = api::config::route_config(
        auth_service.clone(),
        ssh_config_service.clone(),
        audit_service.clone(),
    );
    let audit_routes = api::audit::route_audit(auth_service.clone(), audit_service.clone());
    let files = api::files::route_files();
    let not_found = api::not_found::route_404();

    let routes = auth_routes
        .or(config_routes)
        .or(audit_routes)
        .or(ws_ssh)
        .or(files)
        .or(not_found);

    info!("Server listening on http://0.0.0.0:18022");
    println!("WebSSH Server running at http://127.0.0.1:18022");

    // Start web server
    warp::serve(routes).run(socket_address).await;
}

