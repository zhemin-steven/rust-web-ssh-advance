/**
 * Cryptography Module for Password Encryption
 * Author: steven
 * 
 * Uses AES-256-GCM for encrypting SSH passwords
 */

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use pbkdf2::pbkdf2;
use hmac;

const SALT_FILE: &str = "data/.encryption_salt";
const NONCE_SIZE: usize = 12; // 96 bits for GCM
const KEY_SIZE: usize = 32; // 256 bits
const PBKDF2_ITERATIONS: u32 = 600_000; // OWASP recommended minimum

pub struct CryptoService {
    cipher: Aes256Gcm,
}

impl CryptoService {
    /// Create a new CryptoService with a master password
    pub fn new(master_password: &str) -> Self {
        // Create data directory if it doesn't exist
        if let Some(parent) = Path::new(SALT_FILE).parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Load or generate salt
        let salt = Self::load_or_generate_salt();

        // Derive key from master password using PBKDF2
        let key = Self::derive_key(master_password, &salt);
        let cipher = Aes256Gcm::new(&key.into());

        log::info!("Initialized CryptoService with master password");
        CryptoService { cipher }
    }

    fn load_or_generate_salt() -> [u8; 32] {
        if Path::new(SALT_FILE).exists() {
            // Load existing salt
            if let Ok(hex_salt) = fs::read_to_string(SALT_FILE) {
                if let Ok(salt_bytes) = hex::decode(hex_salt.trim()) {
                    if salt_bytes.len() == 32 {
                        let mut salt = [0u8; 32];
                        salt.copy_from_slice(&salt_bytes);
                        log::info!("Loaded encryption salt from file");
                        return salt;
                    }
                }
            }
        }

        // Generate new random salt
        let salt: [u8; 32] = rand::random();

        // Save salt to file
        let hex_salt = hex::encode(salt);
        if let Err(e) = fs::write(SALT_FILE, hex_salt) {
            log::error!("Failed to save encryption salt: {}", e);
        } else {
            log::info!("Generated and saved new encryption salt");
        }

        salt
    }

    fn derive_key(master_password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        pbkdf2::<hmac::Hmac<Sha256>>(
            master_password.as_bytes(),
            salt,
            PBKDF2_ITERATIONS,
            &mut key,
        );
        key
    }

    /// Encrypt a password
    /// Returns base64-encoded string: nonce(12 bytes) + ciphertext
    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        // Generate random nonce
        let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Combine nonce + ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        // Encode as base64
        Ok(general_purpose::STANDARD.encode(&result))
    }

    /// Decrypt a password
    /// Input is base64-encoded string: nonce(12 bytes) + ciphertext
    pub fn decrypt(&self, encrypted: &str) -> Result<String, String> {
        // Decode from base64
        let data = general_purpose::STANDARD.decode(encrypted)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        if data.len() < NONCE_SIZE {
            return Err("Invalid encrypted data".to_string());
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext)
            .map_err(|e| format!("UTF-8 decode failed: {}", e))
    }
}

impl Clone for CryptoService {
    fn clone(&self) -> Self {
        // Note: This is a workaround for cloning the cipher
        // In production, you should store the master password or key separately
        // For now, we'll panic if clone is called, as it requires the master password
        panic!("CryptoService cannot be cloned without the master password. Use Arc<CryptoService> instead.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let crypto = CryptoService::new("test-master-password");
        let password = "my-secret-password-123";

        let encrypted = crypto.encrypt(password).unwrap();
        assert_ne!(encrypted, password);

        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, password);
    }

    #[test]
    fn test_different_nonces() {
        let crypto = CryptoService::new("test-master-password");
        let password = "same-password";

        let encrypted1 = crypto.encrypt(password).unwrap();
        let encrypted2 = crypto.encrypt(password).unwrap();

        // Same password should produce different ciphertexts due to random nonce
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same password
        assert_eq!(crypto.decrypt(&encrypted1).unwrap(), password);
        assert_eq!(crypto.decrypt(&encrypted2).unwrap(), password);
    }

    #[test]
    fn test_different_master_passwords() {
        let crypto1 = CryptoService::new("password1");
        let crypto2 = CryptoService::new("password2");
        let password = "my-secret";

        let encrypted1 = crypto1.encrypt(password).unwrap();

        // Different master password should fail to decrypt
        assert!(crypto2.decrypt(&encrypted1).is_err());

        // Same master password should succeed
        assert_eq!(crypto1.decrypt(&encrypted1).unwrap(), password);
    }
}

