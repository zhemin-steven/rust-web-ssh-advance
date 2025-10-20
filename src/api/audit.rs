/**
 * Audit Log API Routes
 * Author: steven
 */

use warp::{Filter, Rejection, Reply, reply};
use crate::auth::{AuthService, UserRole};
use crate::audit::AuditService;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn route_audit(
    auth_service: AuthService,
    audit_service: AuditService,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let list = warp::path!("api" / "audit" / "logs")
        .and(warp::get())
        .and(warp::query::<ListLogsQuery>())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service.clone()))
        .and(with_audit_service(audit_service.clone()))
        .and_then(handle_list_logs);

    let user_activity = warp::path!("api" / "audit" / "activity")
        .and(warp::get())
        .and(warp::query::<ActivityQuery>())
        .and(warp::header::optional::<String>("authorization"))
        .and(with_auth_service(auth_service))
        .and(with_audit_service(audit_service))
        .and_then(handle_user_activity);

    list.or(user_activity)
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

#[derive(Debug, serde::Deserialize)]
struct ListLogsQuery {
    limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct ActivityQuery {
    limit: Option<usize>,
}

async fn handle_list_logs(
    query: ListLogsQuery,
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

    let logs = if claims.role == UserRole::Admin {
        audit_service.get_logs(query.limit, None)
    } else {
        audit_service.get_logs(query.limit, Some(&claims.sub))
    };

    Ok(reply::json(&logs))
}

async fn handle_user_activity(
    query: ActivityQuery,
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

    let limit = query.limit.unwrap_or(50).min(500);
    let logs = audit_service.get_user_activity(&claims.sub, limit);

    Ok(reply::json(&logs))
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

