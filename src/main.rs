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
use auth::AuthService;
use ssh_config::SshConfigService;
use audit::AuditService;
use host_key::HostKeyService;
use crypto::CryptoService;

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Prompt for master password
    println!("\n===========================================");
    println!("  WebSSH Server - Master Password");
    println!("===========================================\n");
    println!("Enter master password to decrypt SSH configurations:");
    println!("(First time: set a strong password. Subsequent: use the same password)\n");

    let master_password = rpassword::read_password()
        .expect("Failed to read password");

    if master_password.is_empty() {
        eprintln!("Error: Master password cannot be empty");
        std::process::exit(1);
    }

    println!("\nInitializing encryption service...");

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

