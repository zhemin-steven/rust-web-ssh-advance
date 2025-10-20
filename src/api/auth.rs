/**
 * Authentication API Routes
 * Author: steven
 */

use warp::{Filter, Rejection, Reply, reply};
use crate::auth::{AuthService, LoginRequest, UserRole};
use crate::audit::{AuditService, AuditAction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: UserRole,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChangePasswordRequest {
    old_password: String,
    new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EnableTotpRequest {
    secret: String,
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DisableTotpRequest {
    password: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn route_auth(
    auth_service: AuthService,
    audit_service: AuditService,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let login = warp::path!("api" / "auth" / "login")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_login);

    let verify = warp::path!("api" / "auth" / "verify")
        .and(warp::get())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and_then(handle_verify);

    let create_user = warp::path!("api" / "auth" / "users")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_create_user);

    let list_users = warp::path!("api" / "auth" / "users")
        .and(warp::get())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and_then(handle_list_users);

    let delete_user = warp::path!("api" / "auth" / "users" / String)
        .and(warp::delete())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_delete_user);

    let change_password = warp::path!("api" / "auth" / "change-password")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_change_password);

    let setup_totp = warp::path!("api" / "auth" / "totp" / "setup")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and_then(handle_setup_totp);

    let enable_totp = warp::path!("api" / "auth" / "totp" / "enable")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_enable_totp);

    let disable_totp = warp::path!("api" / "auth" / "totp" / "disable")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_disable_totp);

    let totp_status = warp::path!("api" / "auth" / "totp" / "status")
        .and(warp::get())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and_then(handle_totp_status);

    login.or(verify).or(create_user).or(list_users).or(delete_user)
        .or(change_password).or(setup_totp).or(enable_totp).or(disable_totp).or(totp_status)
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

async fn handle_login(
    req: LoginRequest,
    auth_service: AuthService,
    audit_service: AuditService,
) -> Result<impl Reply, Rejection> {
    match auth_service.login(&req.username, &req.password, req.totp_code.as_deref()) {
        Ok(response) => {
            audit_service.log(
                "system",
                &req.username,
                AuditAction::Login,
                "web",
                None,
                None,
                true,
            );
            Ok(reply::json(&response))
        }
        Err(e) => {
            audit_service.log(
                "system",
                &req.username,
                AuditAction::Login,
                "web",
                Some(e.clone()),
                None,
                false,
            );
            Ok(reply::json(&ErrorResponse { error: e }))
        }
    }
}

async fn handle_verify(
    auth_header: Option<String>,
    auth_service: AuthService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "No token provided".to_string() })),
    };

    match auth_service.verify_token(&token) {
        Ok(claims) => Ok(reply::json(&claims)),
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_create_user(
    auth_header: Option<String>,
    req: CreateUserRequest,
    auth_service: AuthService,
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

    if claims.role != UserRole::Admin {
        return Ok(reply::json(&ErrorResponse { error: "Admin access required".to_string() }));
    }

    match auth_service.create_user(&req.username, &req.password, req.role) {
        Ok(user) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::CreateUser,
                &req.username,
                None,
                None,
                true,
            );
            Ok(reply::json(&user))
        }
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_list_users(
    auth_header: Option<String>,
    auth_service: AuthService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    if claims.role != UserRole::Admin {
        return Ok(reply::json(&ErrorResponse { error: "Admin access required".to_string() }));
    }

    let users = auth_service.list_users();
    Ok(reply::json(&users))
}

async fn handle_delete_user(
    username: String,
    auth_header: Option<String>,
    auth_service: AuthService,
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

    if claims.role != UserRole::Admin {
        return Ok(reply::json(&ErrorResponse { error: "Admin access required".to_string() }));
    }

    match auth_service.delete_user(&username) {
        Ok(_) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::DeleteUser,
                &username,
                None,
                None,
                true,
            );
            Ok(reply::json(&serde_json::json!({"success": true})))
        }
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_change_password(
    auth_header: Option<String>,
    req: ChangePasswordRequest,
    auth_service: AuthService,
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

    match auth_service.change_password(&claims.username, &req.old_password, &req.new_password) {
        Ok(_) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::ChangePassword,
                &claims.username,
                None,
                None,
                true,
            );
            Ok(reply::json(&serde_json::json!({"success": true, "message": "Password changed successfully"})))
        }
        Err(e) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::ChangePassword,
                &claims.username,
                Some(e.clone()),
                None,
                false,
            );
            Ok(reply::json(&ErrorResponse { error: e }))
        }
    }
}

async fn handle_setup_totp(
    auth_header: Option<String>,
    auth_service: AuthService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    match auth_service.setup_totp(&claims.username) {
        Ok(response) => Ok(reply::json(&response)),
        Err(e) => Ok(reply::json(&ErrorResponse { error: e })),
    }
}

async fn handle_enable_totp(
    auth_header: Option<String>,
    req: EnableTotpRequest,
    auth_service: AuthService,
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

    match auth_service.enable_totp(&claims.username, &req.secret, &req.code) {
        Ok(_) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::EnableTotp,
                &claims.username,
                None,
                None,
                true,
            );
            Ok(reply::json(&serde_json::json!({"success": true, "message": "2FA enabled successfully"})))
        }
        Err(e) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::EnableTotp,
                &claims.username,
                Some(e.clone()),
                None,
                false,
            );
            Ok(reply::json(&ErrorResponse { error: e }))
        }
    }
}

async fn handle_disable_totp(
    auth_header: Option<String>,
    req: DisableTotpRequest,
    auth_service: AuthService,
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

    match auth_service.disable_totp(&claims.username, &req.password, &req.code) {
        Ok(_) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::DisableTotp,
                &claims.username,
                None,
                None,
                true,
            );
            Ok(reply::json(&serde_json::json!({"success": true, "message": "2FA disabled successfully"})))
        }
        Err(e) => {
            audit_service.log(
                &claims.sub,
                &claims.username,
                AuditAction::DisableTotp,
                &claims.username,
                Some(e.clone()),
                None,
                false,
            );
            Ok(reply::json(&ErrorResponse { error: e }))
        }
    }
}

async fn handle_totp_status(
    auth_header: Option<String>,
    auth_service: AuthService,
) -> Result<impl Reply, Rejection> {
    let token = match extract_token(auth_header) {
        Some(t) => t,
        None => return Ok(reply::json(&ErrorResponse { error: "Unauthorized".to_string() })),
    };

    let claims = match auth_service.verify_token(&token) {
        Ok(c) => c,
        Err(e) => return Ok(reply::json(&ErrorResponse { error: e })),
    };

    match auth_service.get_totp_status(&claims.username) {
        Ok(enabled) => Ok(reply::json(&serde_json::json!({"enabled": enabled}))),
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

