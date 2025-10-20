/**
 * SSH Configuration API Routes
 * Author: steven
 */

use warp::{Filter, Rejection, Reply, reply};
use crate::auth::AuthService;
use crate::ssh_config::{SshConfigService, CreateSshConfigRequest};
use crate::audit::{AuditService, AuditAction};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn route_config(
    auth_service: AuthService,
    config_service: SshConfigService,
    audit_service: AuditService,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let create = warp::path!("api" / "configs")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_config_service(config_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_create_config);

    let list = warp::path!("api" / "configs")
        .and(warp::get())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and(with_config_service(config_service.clone()))
        .and_then(handle_list_configs);

    let get = warp::path!("api" / "configs" / String)
        .and(warp::get())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and(with_config_service(config_service.clone()))
        .and_then(handle_get_config);

    let update = warp::path!("api" / "configs" / String)
        .and(warp::put())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_config_service(config_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_update_config);

    let delete = warp::path!("api" / "configs" / String)
        .and(warp::delete())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service))
        .and(with_config_service(config_service))
        .and(with_audit_service(audit_service))
        .and_then(handle_delete_config);

    create.or(list).or(get).or(update).or(delete)
}

fn with_auth_service(
    service: AuthService,
) -> impl Filter<Extract = (AuthService,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

fn with_config_service(
    service: SshConfigService,
) -> impl Filter<Extract = (SshConfigService,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

fn with_audit_service(
    service: AuditService,
) -> impl Filter<Extract = (AuditService,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

async fn handle_create_config(
    auth_header: Option<String>,
    req: CreateSshConfigRequest,
    auth_service: AuthService,
    config_service: SshConfigService,
    audit_service: AuditService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    match config_service.create_config(&claims.sub, req) {
        Ok(config) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::CreateConfig,
                &config.name,
                None,
                None,
                true,
            );
            Ok(reply::json(&config))
        }
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_list_configs(
    auth_header: Option<String>,
    auth_service: AuthService,
    config_service: SshConfigService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    let configs = config_service.list_configs(&claims.sub);
    Ok(reply::json(&configs))
}

async fn handle_get_config(
    config_id: String,
    auth_header: Option<String>,
    auth_service: AuthService,
    config_service: SshConfigService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    match config_service.get_config(&config_id, &claims.sub) {
        Ok(config) => Ok(reply::json(&config)),
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_update_config(
    config_id: String,
    auth_header: Option<String>,
    req: CreateSshConfigRequest,
    auth_service: AuthService,
    config_service: SshConfigService,
    audit_service: AuditService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    match config_service.update_config(&config_id, &claims.sub, req) {
        Ok(config) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::UpdateConfig,
                &config.name,
                None,
                None,
                true,
            );
            Ok(reply::json(&config))
        }
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_delete_config(
    config_id: String,
    auth_header: Option<String>,
    auth_service: AuthService,
    config_service: SshConfigService,
    audit_service: AuditService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    match config_service.delete_config(&config_id, &claims.sub) {
        Ok(_) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::DeleteConfig,
                &config_id,
                None,
                None,
                true,
            );
            Ok(reply::json(&serde_json::json!({"success": true})))
        }
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

fn extract_token(auth_header: Option<String>) -> Option<String> {
    auth_header.and_then(|h| {
        if h.starts_with("Bearer ") {
            Some(h[7..].to_string())
        } else {
            None
        }
    })
}

