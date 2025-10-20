/**
 * Authentication Module
 * Author: steven
 */

use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Utc, Duration};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use std::fs;
use std::path::Path;
use totp_lite::{totp_custom, Sha1};
use rand::Rng;

const JWT_SECRET: &str = "your-secret-key-change-this-in-production";
const TOKEN_EXPIRATION_HOURS: i64 = 24;
const USERS_FILE: &str = "data/users.json";
const ADMIN_USER_ID: &str = "00000000-0000-0000-0000-000000000001"; // Fixed ID for admin

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: i64,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: UserRole,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub role: UserRole,
    pub requires_totp: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code: String,
    pub manual_entry: String,
}

pub struct AuthService {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl AuthService {
    pub fn new() -> Self {
        // Create data directory if it doesn't exist
        if let Some(parent) = Path::new(USERS_FILE).parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Load users from file or create default admin
        let users = Self::load_from_file();

        AuthService {
            users: Arc::new(RwLock::new(users)),
        }
    }

    fn load_from_file() -> HashMap<String, User> {
        if Path::new(USERS_FILE).exists() {
            if let Ok(content) = fs::read_to_string(USERS_FILE) {
                if let Ok(users) = serde_json::from_str::<HashMap<String, User>>(&content) {
                    log::info!("Loaded {} users from file", users.len());
                    return users;
                }
            }
        }

        // Create default admin user if file doesn't exist
        let mut users = HashMap::new();
        let admin_password_hash = hash("admin", DEFAULT_COST).unwrap();
        users.insert(
            "admin".to_string(),
            User {
                id: ADMIN_USER_ID.to_string(),
                username: "admin".to_string(),
                password_hash: admin_password_hash,
                role: UserRole::Admin,
                created_at: Utc::now().timestamp(),
                totp_secret: None,
                totp_enabled: false,
            },
        );

        // Save default admin to file
        if let Ok(content) = serde_json::to_string_pretty(&users) {
            let _ = fs::write(USERS_FILE, content);
        }

        users
    }

    fn save_to_file(&self) {
        let users = self.users.read().unwrap();
        if let Ok(content) = serde_json::to_string_pretty(&*users) {
            if let Err(e) = fs::write(USERS_FILE, content) {
                log::error!("Failed to save users: {}", e);
            }
        }
    }

    pub fn login(&self, username: &str, password: &str, totp_code: Option<&str>) -> Result<LoginResponse, String> {
        let users = self.users.read().unwrap();

        let user = users.get(username)
            .ok_or_else(|| "Invalid username or password".to_string())?;

        if !verify(password, &user.password_hash).map_err(|_| "Authentication failed")? {
            return Err("Invalid username or password".to_string());
        }

        // Check if 2FA is enabled
        if user.totp_enabled {
            if let Some(secret) = &user.totp_secret {
                // If 2FA is enabled, TOTP code is required
                let code = totp_code.ok_or_else(|| "TOTP code required".to_string())?;

                // Verify TOTP code
                if !Self::verify_totp(secret, code) {
                    return Err("Invalid TOTP code".to_string());
                }
            } else {
                return Err("2FA configuration error".to_string());
            }
        }

        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(TOKEN_EXPIRATION_HOURS))
            .unwrap()
            .timestamp();

        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            role: user.role.clone(),
            exp: expiration,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_ref()),
        )
        .map_err(|_| "Failed to generate token".to_string())?;

        Ok(LoginResponse {
            token,
            username: user.username.clone(),
            role: user.role.clone(),
            requires_totp: false,
        })
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, String> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET.as_ref()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|_| "Invalid token".to_string())
    }

    pub fn create_user(&self, username: &str, password: &str, role: UserRole) -> Result<User, String> {
        {
            let mut users = self.users.write().unwrap();

            if users.contains_key(username) {
                return Err("Username already exists".to_string());
            }

            let user_id = Uuid::new_v4().to_string();
            let password_hash = hash(password, DEFAULT_COST)
                .map_err(|_| "Failed to hash password".to_string())?;

            let user = User {
                id: user_id,
                username: username.to_string(),
                password_hash,
                role,
                created_at: Utc::now().timestamp(),
                totp_secret: None,
                totp_enabled: false,
            };

            users.insert(username.to_string(), user.clone());
        }

        self.save_to_file();

        let users = self.users.read().unwrap();
        Ok(users.get(username).unwrap().clone())
    }

    pub fn list_users(&self) -> Vec<User> {
        let users = self.users.read().unwrap();
        users.values().cloned().collect()
    }

    pub fn delete_user(&self, username: &str) -> Result<(), String> {
        {
            let mut users = self.users.write().unwrap();

            if username == "admin" {
                return Err("Cannot delete admin user".to_string());
            }

            users.remove(username)
                .ok_or_else(|| "User not found".to_string())?;
        }

        self.save_to_file();
        Ok(())
    }

    pub fn change_password(&self, username: &str, old_password: &str, new_password: &str) -> Result<(), String> {
        {
            let mut users = self.users.write().unwrap();

            let user = users.get_mut(username)
                .ok_or_else(|| "User not found".to_string())?;

            // Verify old password
            if !verify(old_password, &user.password_hash).map_err(|_| "Authentication failed")? {
                return Err("Current password is incorrect".to_string());
            }

            // Hash new password
            let new_password_hash = hash(new_password, DEFAULT_COST)
                .map_err(|_| "Failed to hash password".to_string())?;

            // Update password
            user.password_hash = new_password_hash;
        }

        self.save_to_file();
        Ok(())
    }

    /// Generate a random TOTP secret (20 bytes, Base32 encoded)
    fn generate_totp_secret() -> String {
        let mut rng = rand::thread_rng();
        let secret: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret)
    }

    /// Verify TOTP code with time skew tolerance
    fn verify_totp(secret: &str, code: &str) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Decode base32 secret
        let secret_bytes = match base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret) {
            Some(bytes) => bytes,
            None => return false,
        };

        // Get current Unix timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Normalize input code (remove spaces, ensure 6 digits)
        let code = code.trim().replace(" ", "");
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Check current time and ±60 seconds for clock skew tolerance
        for offset in [-60i64, -30, 0, 30, 60] {
            let t = (now as i64 + offset) as u64;
            let totp = totp_custom::<Sha1>(30, 6, &secret_bytes, t);
            if totp == code {
                return true;
            }
        }

        false
    }

    /// Setup 2FA for a user - generates secret and QR code
    pub fn setup_totp(&self, username: &str) -> Result<TotpSetupResponse, String> {
        let secret = Self::generate_totp_secret();

        // Generate otpauth URL for QR code
        let issuer = "WebSSH";
        let otpauth_url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            issuer, username, secret, issuer
        );

        let qr_code = Self::generate_qr_code(&otpauth_url)?;

        Ok(TotpSetupResponse {
            secret: secret.clone(),
            qr_code,
            manual_entry: format!("Account: {}\nSecret: {}", username, secret),
        })
    }

    /// Enable 2FA for a user after verifying TOTP code
    pub fn enable_totp(&self, username: &str, secret: &str, code: &str) -> Result<(), String> {
        if !Self::verify_totp(secret, code) {
            return Err("Invalid TOTP code".to_string());
        }

        {
            let mut users = self.users.write().unwrap();
            let user = users.get_mut(username)
                .ok_or_else(|| "User not found".to_string())?;

            user.totp_secret = Some(secret.to_string());
            user.totp_enabled = true;
        }

        self.save_to_file();
        Ok(())
    }

    /// Disable 2FA for a user after verifying password and TOTP code
    pub fn disable_totp(&self, username: &str, password: &str, code: &str) -> Result<(), String> {
        {
            let users = self.users.read().unwrap();
            let user = users.get(username)
                .ok_or_else(|| "User not found".to_string())?;

            // Verify password
            if !verify(password, &user.password_hash).map_err(|_| "Authentication failed")? {
                return Err("Invalid password".to_string());
            }

            // Verify TOTP code
            if let Some(secret) = &user.totp_secret {
                if !Self::verify_totp(secret, code) {
                    return Err("Invalid TOTP code".to_string());
                }
            } else {
                return Err("2FA is not enabled".to_string());
            }
        }

        {
            let mut users = self.users.write().unwrap();
            let user = users.get_mut(username)
                .ok_or_else(|| "User not found".to_string())?;

            user.totp_secret = None;
            user.totp_enabled = false;
        }

        self.save_to_file();
        Ok(())
    }

    /// Get 2FA status for a user
    pub fn get_totp_status(&self, username: &str) -> Result<bool, String> {
        let users = self.users.read().unwrap();
        let user = users.get(username)
            .ok_or_else(|| "User not found".to_string())?;
        Ok(user.totp_enabled)
    }

    /// Generate QR code as base64-encoded SVG
    fn generate_qr_code(data: &str) -> Result<String, String> {
        use qrcode::QrCode;
        use qrcode::render::svg;
        use base64::{Engine as _, engine::general_purpose};

        let code = QrCode::new(data.as_bytes())
            .map_err(|e| format!("Failed to generate QR code: {}", e))?;

        let svg_string = code.render::<svg::Color>()
            .min_dimensions(200, 200)
            .build();

        let svg_base64 = general_purpose::STANDARD.encode(svg_string.as_bytes());
        Ok(format!("data:image/svg+xml;base64,{}", svg_base64))
    }
}

impl Clone for AuthService {
    fn clone(&self) -> Self {
        AuthService {
            users: Arc::clone(&self.users),
        }
    }
}

