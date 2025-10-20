/**
 * SSH Configuration Management Module
 * Author: steven
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::Utc;
use std::fs;
use std::path::Path;
use crate::crypto::CryptoService;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SshConfig {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub auth_type: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSshConfigRequest {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub auth_type: String,
}

const CONFIG_FILE: &str = "data/ssh_configs.json";

pub struct SshConfigService {
    configs: Arc<RwLock<HashMap<String, SshConfig>>>,
    crypto: Arc<CryptoService>,
}

impl SshConfigService {
    pub fn new(crypto: Arc<CryptoService>) -> Self {
        // Create data directory if it doesn't exist
        if let Some(parent) = Path::new(CONFIG_FILE).parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Load configs from file
        let configs = Self::load_from_file(&crypto);

        SshConfigService {
            configs: Arc::new(RwLock::new(configs)),
            crypto,
        }
    }

    fn load_from_file(crypto: &CryptoService) -> HashMap<String, SshConfig> {
        if Path::new(CONFIG_FILE).exists() {
            if let Ok(content) = fs::read_to_string(CONFIG_FILE) {
                if let Ok(mut configs) = serde_json::from_str::<HashMap<String, SshConfig>>(&content) {
                    // Decrypt passwords
                    for config in configs.values_mut() {
                        if let Some(encrypted_password) = &config.password {
                            if let Ok(decrypted) = crypto.decrypt(encrypted_password) {
                                config.password = Some(decrypted);
                            } else {
                                log::warn!("Failed to decrypt password for config: {}", config.name);
                                config.password = None;
                            }
                        }
                    }
                    log::info!("Loaded {} SSH configs from file", configs.len());
                    return configs;
                }
            }
        }
        HashMap::new()
    }

    fn save_to_file(&self) {
        let configs = self.configs.read().unwrap();

        // Encrypt passwords before saving
        let mut configs_to_save: HashMap<String, SshConfig> = HashMap::new();
        for (key, config) in configs.iter() {
            let mut config_copy = config.clone();
            if let Some(password) = &config.password {
                match self.crypto.encrypt(password) {
                    Ok(encrypted) => config_copy.password = Some(encrypted),
                    Err(e) => {
                        log::error!("Failed to encrypt password for config {}: {}", config.name, e);
                        config_copy.password = None;
                    }
                }
            }
            configs_to_save.insert(key.clone(), config_copy);
        }

        if let Ok(content) = serde_json::to_string_pretty(&configs_to_save) {
            if let Err(e) = fs::write(CONFIG_FILE, content) {
                log::error!("Failed to save SSH configs: {}", e);
            }
        }
    }

    pub fn create_config(&self, user_id: &str, req: CreateSshConfigRequest) -> Result<SshConfig, String> {
        let config_id = Uuid::new_v4().to_string();
        let config = SshConfig {
            id: config_id.clone(),
            user_id: user_id.to_string(),
            name: req.name,
            host: req.host,
            port: req.port,
            username: req.username,
            password: req.password,
            auth_type: req.auth_type,
            created_at: Utc::now().timestamp(),
            last_used: None,
        };

        {
            let mut configs = self.configs.write().unwrap();
            configs.insert(config_id, config.clone());
        }

        self.save_to_file();
        Ok(config)
    }

    pub fn list_configs(&self, user_id: &str) -> Vec<SshConfig> {
        let configs = self.configs.read().unwrap();
        configs
            .values()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect()
    }

    pub fn get_config(&self, config_id: &str, user_id: &str) -> Result<SshConfig, String> {
        let configs = self.configs.read().unwrap();
        
        configs
            .get(config_id)
            .filter(|c| c.user_id == user_id)
            .cloned()
            .ok_or_else(|| "Config not found".to_string())
    }

    pub fn update_last_used(&self, config_id: &str) {
        {
            let mut configs = self.configs.write().unwrap();

            if let Some(config) = configs.get_mut(config_id) {
                config.last_used = Some(Utc::now().timestamp());
            }
        }

        self.save_to_file();
    }

    pub fn delete_config(&self, config_id: &str, user_id: &str) -> Result<(), String> {
        {
            let mut configs = self.configs.write().unwrap();

            let config = configs.get(config_id)
                .ok_or_else(|| "Config not found".to_string())?;

            if config.user_id != user_id {
                return Err("Unauthorized".to_string());
            }

            configs.remove(config_id);
        }

        self.save_to_file();
        Ok(())
    }

    pub fn update_config(&self, config_id: &str, user_id: &str, req: CreateSshConfigRequest) -> Result<SshConfig, String> {
        let result = {
            let mut configs = self.configs.write().unwrap();

            let config = configs.get_mut(config_id)
                .ok_or_else(|| "Config not found".to_string())?;

            if config.user_id != user_id {
                return Err("Unauthorized".to_string());
            }

            config.name = req.name;
            config.host = req.host;
            config.port = req.port;
            config.username = req.username;
            config.password = req.password;
            config.auth_type = req.auth_type;

            Ok(config.clone())
        };

        if result.is_ok() {
            self.save_to_file();
        }

        result
    }
}

impl Clone for SshConfigService {
    fn clone(&self) -> Self {
        SshConfigService {
            configs: Arc::clone(&self.configs),
            crypto: Arc::clone(&self.crypto),
        }
    }
}

