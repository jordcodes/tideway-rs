//! Cookie-based session store
//!
//! Stores session data in encrypted cookies. Session data is serialized
//! to JSON, encrypted using the `cookie` crate's authenticated encryption,
//! and stored in HTTP cookies.
//!
//! The encryption uses XChaCha20-Poly1305 (via the `cookie` crate's `private` feature)
//! which provides both confidentiality and integrity protection.

use crate::error::{Result, TidewayError};
use crate::traits::session::{SessionData, SessionStore};
use async_trait::async_trait;
use cookie::{Cookie, CookieJar, Key, SameSite};
use std::sync::Arc;

/// Cookie-based session store
///
/// Stores session data in encrypted HTTP cookies. Suitable for stateless
/// applications where session data is small.
///
/// # Security
///
/// Session data is encrypted using XChaCha20-Poly1305 authenticated encryption
/// via the `cookie` crate's private cookies. This provides:
/// - **Confidentiality**: Session data cannot be read by clients
/// - **Integrity**: Tampered cookies are rejected
/// - **Authentication**: Only cookies created with the same key are accepted
#[derive(Clone)]
pub struct CookieSessionStore {
    key: Arc<Key>,
    config: crate::session::SessionConfig,
}

impl CookieSessionStore {
    /// Create a new cookie session store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No `encryption_key` is provided and `allow_insecure_key` is `false`
    /// - The `encryption_key` is not valid hex or not exactly 64 bytes (128 hex chars)
    ///
    /// # Security
    ///
    /// Always provide a stable encryption key in production. Generate one with:
    /// ```bash
    /// openssl rand -hex 64
    /// ```
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tideway::session::{SessionConfig, CookieSessionStore};
    ///
    /// let config = SessionConfig {
    ///     encryption_key: Some("your-128-char-hex-key-here".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// // This will fail fast if no key is provided
    /// let store = CookieSessionStore::new(&config)
    ///     .expect("Session encryption key is required");
    /// ```
    pub fn new(config: &crate::session::SessionConfig) -> Result<Self> {
        let key = if let Some(ref key_str) = config.encryption_key {
            // Parse hex-encoded key (128 hex chars = 64 bytes = 512 bits)
            // The cookie crate requires 64 bytes for its private cookie encryption
            let key_bytes = hex::decode(key_str)
                .map_err(|e| TidewayError::internal(format!("Invalid encryption key format: {}", e)))?;

            if key_bytes.len() != 64 {
                return Err(TidewayError::internal(
                    "Encryption key must be 64 bytes (128 hex characters). Generate with: openssl rand -hex 64"
                ));
            }

            Key::from(&key_bytes)
        } else if config.allow_insecure_key {
            // Development mode: generate a random key with loud warning
            tracing::error!(
                "┌──────────────────────────────────────────────────────────────────────────────┐"
            );
            tracing::error!(
                "│ SECURITY WARNING: Using randomly generated session encryption key!          │"
            );
            tracing::error!(
                "│                                                                              │"
            );
            tracing::error!(
                "│ This is INSECURE and should NEVER be used in production:                    │"
            );
            tracing::error!(
                "│   • Sessions will be invalidated on every server restart                    │"
            );
            tracing::error!(
                "│   • Sessions won't work across multiple server instances                    │"
            );
            tracing::error!(
                "│   • Session cookies may be vulnerable to forgery                            │"
            );
            tracing::error!(
                "│                                                                              │"
            );
            tracing::error!(
                "│ To fix: Set SESSION_ENCRYPTION_KEY or config.session.encryption_key         │"
            );
            tracing::error!(
                "│ Generate a key with: openssl rand -hex 64                                   │"
            );
            tracing::error!(
                "└──────────────────────────────────────────────────────────────────────────────┘"
            );
            Key::generate()
        } else {
            // Production mode: return error - caller should fail fast
            return Err(TidewayError::internal(
                "Cookie sessions require an encryption key. \
                Set SESSION_ENCRYPTION_KEY environment variable or config.session.encryption_key. \
                Generate a key with: openssl rand -hex 64. \
                For development only, set SESSION_ALLOW_INSECURE_KEY=true."
            ));
        };

        Ok(Self {
            key: Arc::new(key),
            config: config.clone(),
        })
    }

    /// Encrypt session data and return the encrypted cookie value
    ///
    /// Uses the `cookie` crate's private cookies for authenticated encryption.
    /// The returned string is the encrypted, base64-encoded cookie value.
    pub fn encrypt(&self, data: &SessionData) -> Result<String> {
        let serialized = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize session: {}", e)))?;

        // Create a cookie jar and add the cookie as a private (encrypted) cookie
        let mut jar = CookieJar::new();
        let cookie = Cookie::new(self.config.cookie_name.clone(), serialized);
        jar.private_mut(&self.key).add(cookie);

        // Extract the encrypted cookie value
        let encrypted_cookie = jar
            .get(&self.config.cookie_name)
            .ok_or_else(|| TidewayError::internal("Failed to encrypt session cookie"))?;

        Ok(encrypted_cookie.value().to_string())
    }

    /// Decrypt session data from an encrypted cookie value
    ///
    /// Returns `None` if the cookie is invalid, tampered with, or encrypted
    /// with a different key.
    pub fn decrypt(&self, encrypted_value: &str) -> Result<Option<SessionData>> {
        // Create a jar with the encrypted cookie
        let mut jar = CookieJar::new();
        let cookie = Cookie::new(self.config.cookie_name.clone(), encrypted_value.to_string());
        jar.add_original(cookie);

        // Try to decrypt using private cookies
        let decrypted = jar.private(&self.key).get(&self.config.cookie_name);

        match decrypted {
            Some(cookie) => {
                let data: SessionData = serde_json::from_str(cookie.value())
                    .map_err(|e| TidewayError::internal(format!("Failed to deserialize session: {}", e)))?;
                Ok(Some(data))
            }
            None => {
                // Decryption failed - invalid or tampered cookie
                Ok(None)
            }
        }
    }

    /// Build a complete HTTP cookie with all attributes set
    ///
    /// This creates a cookie ready to be set in an HTTP response.
    pub fn build_cookie(&self, data: &SessionData) -> Result<Cookie<'static>> {
        let encrypted_value = self.encrypt(data)?;

        let cookie = Cookie::build((self.config.cookie_name.clone(), encrypted_value))
            .path(self.config.cookie_path.clone())
            .http_only(self.config.cookie_http_only)
            .secure(self.config.cookie_secure)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(
                self.config.default_ttl().as_secs() as i64
            ))
            .build();

        Ok(cookie)
    }
}

#[async_trait]
impl SessionStore for CookieSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>> {
        // For cookie-based sessions, the session_id is the encrypted cookie value
        // Decrypt and return the session data, or None if decryption fails
        self.decrypt(session_id)
    }

    async fn save(&self, _session_id: &str, data: SessionData) -> Result<()> {
        // For cookie-based sessions, saving validates that data can be encrypted
        // The actual cookie setting happens at the HTTP layer via build_cookie()
        self.encrypt(&data)?;
        Ok(())
    }

    async fn delete(&self, _session_id: &str) -> Result<()> {
        // Deleting a cookie means setting it with max_age=0
        // This is handled at the HTTP layer, so we just return Ok
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        // Cookie sessions don't need cleanup - expired cookies are handled by the browser
        Ok(0)
    }

    fn is_healthy(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionConfig;
    use std::time::Duration;

    fn test_config() -> SessionConfig {
        SessionConfig {
            // 64 bytes = 128 hex chars (required by cookie crate for private cookies)
            encryption_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            allow_insecure_key: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = test_config();
        let store = CookieSessionStore::new(&config).unwrap();

        let mut data = SessionData::new(Duration::from_secs(3600));
        data.set("user_id".to_string(), "12345".to_string());
        data.set("role".to_string(), "admin".to_string());

        // Encrypt
        let encrypted = store.encrypt(&data).unwrap();

        // The encrypted value should NOT contain the plaintext
        assert!(!encrypted.contains("12345"));
        assert!(!encrypted.contains("admin"));

        // Decrypt
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_some());

        let decrypted_data = decrypted.unwrap();
        assert_eq!(decrypted_data.get("user_id"), Some(&"12345".to_string()));
        assert_eq!(decrypted_data.get("role"), Some(&"admin".to_string()));
    }

    #[test]
    fn test_tampered_cookie_rejected() {
        let config = test_config();
        let store = CookieSessionStore::new(&config).unwrap();

        let mut data = SessionData::new(Duration::from_secs(3600));
        data.set("user_id".to_string(), "12345".to_string());

        let encrypted = store.encrypt(&data).unwrap();

        // Tamper with the cookie - modify some characters
        let mut tampered = encrypted.clone();
        if tampered.len() > 10 {
            // Replace characters in the middle
            let bytes: Vec<char> = tampered.chars().collect();
            let mut modified: Vec<char> = bytes.clone();
            modified[5] = if bytes[5] == 'a' { 'b' } else { 'a' };
            tampered = modified.into_iter().collect();
        }

        // Tampered cookie should fail decryption
        let result = store.decrypt(&tampered).unwrap();
        assert!(result.is_none(), "Tampered cookie should not decrypt");
    }

    #[test]
    fn test_different_key_cannot_decrypt() {
        let config1 = SessionConfig {
            encryption_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            allow_insecure_key: false,
            ..Default::default()
        };
        let config2 = SessionConfig {
            encryption_key: Some("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string()),
            allow_insecure_key: false,
            ..Default::default()
        };

        let store1 = CookieSessionStore::new(&config1).unwrap();
        let store2 = CookieSessionStore::new(&config2).unwrap();

        let mut data = SessionData::new(Duration::from_secs(3600));
        data.set("secret".to_string(), "sensitive_data".to_string());

        // Encrypt with key 1
        let encrypted = store1.encrypt(&data).unwrap();

        // Try to decrypt with key 2 - should fail
        let result = store2.decrypt(&encrypted).unwrap();
        assert!(result.is_none(), "Different key should not decrypt");
    }

    #[test]
    fn test_invalid_key_length_rejected() {
        let config = SessionConfig {
            encryption_key: Some("too_short".to_string()),
            allow_insecure_key: false,
            ..Default::default()
        };

        let result = CookieSessionStore::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_rejected() {
        let config = SessionConfig {
            // Contains 'g' which is not valid hex
            encryption_key: Some("0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            allow_insecure_key: false,
            ..Default::default()
        };

        let result = CookieSessionStore::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_key_without_insecure_flag_rejected() {
        let config = SessionConfig {
            encryption_key: None,
            allow_insecure_key: false,
            ..Default::default()
        };

        let result = CookieSessionStore::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_garbage_input_returns_none() {
        let config = test_config();
        let store = CookieSessionStore::new(&config).unwrap();

        // Random garbage should not decrypt
        let result = store.decrypt("not_a_valid_encrypted_cookie").unwrap();
        assert!(result.is_none());

        // Empty string
        let result = store.decrypt("").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_build_cookie_has_correct_attributes() {
        let config = test_config();
        let store = CookieSessionStore::new(&config).unwrap();

        let mut data = SessionData::new(Duration::from_secs(3600));
        data.set("test".to_string(), "value".to_string());

        let cookie = store.build_cookie(&data).unwrap();

        assert_eq!(cookie.name(), config.cookie_name);
        assert_eq!(cookie.path(), Some(config.cookie_path.as_str()));
        assert_eq!(cookie.http_only(), Some(config.cookie_http_only));
        assert_eq!(cookie.secure(), Some(config.cookie_secure));
    }

    #[tokio::test]
    async fn test_session_store_trait() {
        let config = test_config();
        let store = CookieSessionStore::new(&config).unwrap();

        let mut data = SessionData::new(Duration::from_secs(3600));
        data.set("session_key".to_string(), "session_value".to_string());

        // Save validates encryption works
        store.save("unused", data.clone()).await.unwrap();

        // Get encrypted value
        let encrypted = store.encrypt(&data).unwrap();

        // Load using encrypted value as session_id
        let loaded = store.load(&encrypted).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().get("session_key"), Some(&"session_value".to_string()));

        // Invalid session_id returns None
        let loaded = store.load("invalid").await.unwrap();
        assert!(loaded.is_none());
    }
}
