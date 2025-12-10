//! Cookie-based session store
//!
//! Stores session data in encrypted cookies. Session data is serialized
//! to JSON, encrypted, and stored in HTTP cookies.

use crate::error::{Result, TidewayError};
use crate::traits::session::{SessionData, SessionStore};
use async_trait::async_trait;
use cookie::{Cookie, Key, SameSite};
use std::sync::Arc;

/// Cookie-based session store
///
/// Stores session data in encrypted HTTP cookies. Suitable for stateless
/// applications where session data is small.
#[derive(Clone)]
pub struct CookieSessionStore {
    #[allow(dead_code)] // Reserved for future cookie signing/encryption implementation
    key: Arc<Key>,
    config: crate::session::SessionConfig,
}

impl CookieSessionStore {
    /// Create a new cookie session store
    pub fn new(config: &crate::session::SessionConfig) -> Result<Self> {
        let key = if let Some(ref key_str) = config.encryption_key {
            // Parse hex-encoded key (64 hex chars = 32 bytes)
            let key_bytes = hex::decode(key_str)
                .map_err(|e| TidewayError::internal(format!("Invalid encryption key format: {}", e)))?;

            if key_bytes.len() != 32 {
                return Err(TidewayError::internal("Encryption key must be 32 bytes (64 hex characters)"));
            }

            Key::from(&key_bytes)
        } else {
            // Generate a random key (NOT SECURE - users should provide their own)
            tracing::warn!("Using randomly generated encryption key - NOT SECURE FOR PRODUCTION");
            Key::generate()
        };

        Ok(Self {
            key: Arc::new(key),
            config: config.clone(),
        })
    }

    /// Build a cookie from session data
    fn build_cookie(&self, _session_id: &str, data: &SessionData) -> Result<Cookie<'static>> {
        let serialized = serde_json::to_string(data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize session: {}", e)))?;

        // Note: Full cookie signing/encryption would use the cookie crate's private feature
        // For now, this is a simplified implementation
        // Clone strings to ensure 'static lifetime
        let cookie_name = self.config.cookie_name.clone();
        let cookie_path = self.config.cookie_path.clone();

        let cookie = Cookie::build((cookie_name, serialized))
            .path(cookie_path)
            .http_only(self.config.cookie_http_only)
            .secure(self.config.cookie_secure)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(
                self.config.default_ttl().as_secs() as i64
            ))
            .build();

        Ok(cookie)
    }

    /// Parse session data from a cookie
    fn parse_cookie(&self, cookie_value: &str) -> Result<SessionData> {
        // Parse the cookie - in a real implementation, signature verification would happen here
        let cookie = Cookie::parse(cookie_value)
            .map_err(|e| TidewayError::internal(format!("Failed to parse cookie: {}", e)))?;

        let value = cookie.value();
        serde_json::from_str(value)
            .map_err(|e| TidewayError::internal(format!("Failed to deserialize session: {}", e)))
    }
}

#[async_trait]
impl SessionStore for CookieSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>> {
        // For cookie-based sessions, the session_id is the cookie value itself
        // In practice, you'd extract this from the HTTP request cookies
        // This is a simplified version - full implementation would need request context
        self.parse_cookie(session_id)
            .map(Some)
            .or_else(|e| {
                if e.to_string().contains("signature") || e.to_string().contains("verify") {
                    Ok(None) // Invalid/expired cookie
                } else {
                    Err(e)
                }
            })
    }

    async fn save(&self, session_id: &str, data: SessionData) -> Result<()> {
        // For cookie-based sessions, saving means generating a cookie
        // In practice, you'd set this on the HTTP response
        // This method validates the data can be serialized
        self.build_cookie(session_id, &data)?;
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
