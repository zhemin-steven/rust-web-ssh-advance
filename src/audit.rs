/**
 * Audit Log Module
 * Author: steven
 */

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::Utc;
use std::fs;
use std::path::Path;

const MAX_LOGS: usize = 1000;
const AUDIT_FILE: &str = "data/audit_logs.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: i64,
    pub user_id: String,
    pub username: String,
    pub action: AuditAction,
    pub target: String,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AuditAction {
    Login,
    Logout,
    SshConnect,
    SshDisconnect,
    SshCommand,
    CreateConfig,
    UpdateConfig,
    DeleteConfig,
    CreateUser,
    DeleteUser,
    ChangePassword,
    EnableTotp,
    DisableTotp,
}

pub struct AuditService {
    logs: Arc<RwLock<VecDeque<AuditLog>>>,
}

impl AuditService {
    pub fn new() -> Self {
        // Create data directory if it doesn't exist
        if let Some(parent) = Path::new(AUDIT_FILE).parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Load logs from file
        let logs = Self::load_from_file();

        AuditService {
            logs: Arc::new(RwLock::new(logs)),
        }
    }

    fn load_from_file() -> VecDeque<AuditLog> {
        if Path::new(AUDIT_FILE).exists() {
            if let Ok(content) = fs::read_to_string(AUDIT_FILE) {
                if let Ok(logs) = serde_json::from_str::<Vec<AuditLog>>(&content) {
                    log::info!("Loaded {} audit logs from file", logs.len());
                    return logs.into_iter().collect();
                }
            }
        }
        VecDeque::with_capacity(MAX_LOGS)
    }

    fn save_to_file(&self) {
        let logs = self.logs.read().unwrap();
        let logs_vec: Vec<&AuditLog> = logs.iter().collect();
        if let Ok(content) = serde_json::to_string_pretty(&logs_vec) {
            if let Err(e) = fs::write(AUDIT_FILE, content) {
                log::error!("Failed to save audit logs: {}", e);
            }
        }
    }

    pub fn log(
        &self,
        user_id: &str,
        username: &str,
        action: AuditAction,
        target: &str,
        details: Option<String>,
        ip_address: Option<String>,
        success: bool,
    ) {
        {
            let mut logs = self.logs.write().unwrap();

            let log = AuditLog {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now().timestamp(),
                user_id: user_id.to_string(),
                username: username.to_string(),
                action,
                target: target.to_string(),
                details,
                ip_address,
                success,
            };

            if logs.len() >= MAX_LOGS {
                logs.pop_front();
            }

            logs.push_back(log);
        }

        // Save to file asynchronously to avoid blocking
        self.save_to_file();
    }

    pub fn get_logs(&self, limit: Option<usize>, user_id: Option<&str>) -> Vec<AuditLog> {
        let logs = self.logs.read().unwrap();
        
        let filtered: Vec<AuditLog> = if let Some(uid) = user_id {
            logs.iter()
                .filter(|log| log.user_id == uid)
                .cloned()
                .collect()
        } else {
            logs.iter().cloned().collect()
        };

        let limit = limit.unwrap_or(100).min(1000);
        filtered.into_iter().rev().take(limit).collect()
    }

    pub fn get_user_activity(&self, user_id: &str, limit: usize) -> Vec<AuditLog> {
        let logs = self.logs.read().unwrap();
        
        logs.iter()
            .filter(|log| log.user_id == user_id)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn search_logs(&self, query: &str, limit: usize) -> Vec<AuditLog> {
        let logs = self.logs.read().unwrap();
        
        logs.iter()
            .filter(|log| {
                log.username.contains(query)
                    || log.target.contains(query)
                    || log.details.as_ref().map_or(false, |d| d.contains(query))
            })
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Clone for AuditService {
    fn clone(&self) -> Self {
        AuditService {
            logs: Arc::clone(&self.logs),
        }
    }
}

