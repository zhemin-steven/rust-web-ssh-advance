/**
 * SSH Host Key Verification Module
 * Author: steven
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostKey {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub fingerprint: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub trusted: bool,
}

pub struct HostKeyService {
    keys: Arc<RwLock<HashMap<String, HostKey>>>,
}

impl HostKeyService {
    pub fn new() -> Self {
        HostKeyService {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn get_host_id(host: &str, port: u16) -> String {
        format!("{}:{}", host, port)
    }

    pub fn verify_host_key(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> HostKeyVerification {
        let host_id = Self::get_host_id(host, port);
        let mut keys = self.keys.write().unwrap();

        if let Some(stored_key) = keys.get_mut(&host_id) {
            stored_key.last_seen = Utc::now().timestamp();

            if stored_key.fingerprint == fingerprint {
                if stored_key.trusted {
                    HostKeyVerification::Trusted
                } else {
                    HostKeyVerification::Known
                }
            } else {
                HostKeyVerification::Changed {
                    old_fingerprint: stored_key.fingerprint.clone(),
                    new_fingerprint: fingerprint.to_string(),
                }
            }
        } else {
            let now = Utc::now().timestamp();
            let host_key = HostKey {
                host: host.to_string(),
                port,
                key_type: key_type.to_string(),
                fingerprint: fingerprint.to_string(),
                first_seen: now,
                last_seen: now,
                trusted: false,
            };
            keys.insert(host_id, host_key);
            HostKeyVerification::Unknown
        }
    }

    pub fn trust_host_key(&self, host: &str, port: u16) -> Result<(), String> {
        let host_id = Self::get_host_id(host, port);
        let mut keys = self.keys.write().unwrap();

        keys.get_mut(&host_id)
            .map(|key| {
                key.trusted = true;
            })
            .ok_or_else(|| "Host key not found".to_string())
    }

    pub fn remove_host_key(&self, host: &str, port: u16) -> Result<(), String> {
        let host_id = Self::get_host_id(host, port);
        let mut keys = self.keys.write().unwrap();

        keys.remove(&host_id)
            .ok_or_else(|| "Host key not found".to_string())?;

        Ok(())
    }

    pub fn list_host_keys(&self) -> Vec<HostKey> {
        let keys = self.keys.read().unwrap();
        keys.values().cloned().collect()
    }

    pub fn get_host_key(&self, host: &str, port: u16) -> Option<HostKey> {
        let host_id = Self::get_host_id(host, port);
        let keys = self.keys.read().unwrap();
        keys.get(&host_id).cloned()
    }
}

impl Clone for HostKeyService {
    fn clone(&self) -> Self {
        HostKeyService {
            keys: Arc::clone(&self.keys),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HostKeyVerification {
    Trusted,
    Known,
    Unknown,
    Changed {
        old_fingerprint: String,
        new_fingerprint: String,
    },
}

