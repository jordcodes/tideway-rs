use crate::utils::get_env_with_prefix;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Session backend type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionBackend {
    /// In-memory session store (default, for dev/testing)
    #[default]
    InMemory,
    /// Cookie-based session store (encrypted cookies)
    #[cfg(feature = "sessions")]
    Cookie,
}

/// Session configuration
///
/// The `Debug` output redacts `encryption_key`.
#[derive(Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    /// Session backend type
    #[serde(default)]
    pub backend: SessionBackend,

    /// Default session TTL (in seconds)
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: u64,

    /// Cookie name (for cookie backend)
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Cookie domain (optional, for cookie backend)
    #[serde(default)]
    pub cookie_domain: Option<String>,

    /// Cookie path (for cookie backend)
    #[serde(default = "default_cookie_path")]
    pub cookie_path: String,

    /// Cookie secure flag (HTTPS only, for cookie backend)
    #[serde(default = "default_secure")]
    pub cookie_secure: bool,

    /// Cookie http_only flag (for cookie backend)
    #[serde(default = "default_http_only")]
    pub cookie_http_only: bool,

    /// Encryption key for cookie sessions (64 bytes hex-encoded)
    ///
    /// **REQUIRED** for cookie-based sessions in production.
    /// Generate a secure key with: `openssl rand -hex 64`
    #[serde(default)]
    pub encryption_key: Option<String>,

    /// Allow insecure random session keys (FOR DEVELOPMENT ONLY)
    ///
    /// When `true`, allows cookie sessions without a configured encryption key.
    /// This is **INSECURE** and should NEVER be enabled in production:
    /// - Sessions will break across server restarts
    /// - Sessions won't work in multi-instance deployments
    /// - Attackers may be able to forge session cookies
    ///
    /// Default: `false`
    #[serde(default)]
    pub allow_insecure_key: bool,
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("backend", &self.backend)
            .field("default_ttl_seconds", &self.default_ttl_seconds)
            .field("cookie_name", &self.cookie_name)
            .field("cookie_domain", &self.cookie_domain)
            .field("cookie_path", &self.cookie_path)
            .field("cookie_secure", &self.cookie_secure)
            .field("cookie_http_only", &self.cookie_http_only)
            .field(
                "encryption_key",
                &self.encryption_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allow_insecure_key", &self.allow_insecure_key)
            .finish()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            backend: SessionBackend::default(),
            default_ttl_seconds: default_ttl_seconds(),
            cookie_name: default_cookie_name(),
            cookie_domain: None,
            cookie_path: default_cookie_path(),
            cookie_secure: default_secure(),
            cookie_http_only: default_http_only(),
            encryption_key: None,
            allow_insecure_key: false,
        }
    }
}

impl SessionConfig {
    /// Load session configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(backend) = get_env_with_prefix("SESSION_BACKEND") {
            config.backend = match backend.to_lowercase().as_str() {
                "cookie" => {
                    #[cfg(feature = "sessions")]
                    {
                        SessionBackend::Cookie
                    }
                    #[cfg(not(feature = "sessions"))]
                    {
                        tracing::warn!(
                            "Cookie sessions requested but sessions feature not enabled, using in-memory"
                        );
                        SessionBackend::InMemory
                    }
                }
                _ => SessionBackend::InMemory,
            };
        }

        if let Some(ttl) = get_env_with_prefix("SESSION_TTL_SECONDS") {
            match ttl.parse() {
                Ok(seconds) => config.default_ttl_seconds = seconds,
                Err(_) => tracing::warn!(
                    value = %ttl,
                    "Invalid SESSION_TTL_SECONDS, using default ({})",
                    default_ttl_seconds()
                ),
            }
        }

        if let Some(name) = get_env_with_prefix("SESSION_COOKIE_NAME") {
            config.cookie_name = name;
        }

        if let Some(domain) = get_env_with_prefix("SESSION_COOKIE_DOMAIN") {
            config.cookie_domain = Some(domain);
        }

        if let Some(path) = get_env_with_prefix("SESSION_COOKIE_PATH") {
            config.cookie_path = path;
        }

        if let Some(secure) = get_env_with_prefix("SESSION_COOKIE_SECURE") {
            match secure.parse() {
                Ok(value) => config.cookie_secure = value,
                Err(_) => {
                    tracing::warn!(
                        value = %secure,
                        "Invalid SESSION_COOKIE_SECURE (expected true/false), defaulting to true for security"
                    );
                    config.cookie_secure = true;
                }
            }
        }

        if let Some(http_only) = get_env_with_prefix("SESSION_COOKIE_HTTP_ONLY") {
            match http_only.parse() {
                Ok(value) => config.cookie_http_only = value,
                Err(_) => {
                    tracing::warn!(
                        value = %http_only,
                        "Invalid SESSION_COOKIE_HTTP_ONLY (expected true/false), defaulting to true for security"
                    );
                    config.cookie_http_only = true;
                }
            }
        }

        if let Some(key) = get_env_with_prefix("SESSION_ENCRYPTION_KEY") {
            config.encryption_key = Some(key);
        }

        if let Some(allow) = get_env_with_prefix("SESSION_ALLOW_INSECURE_KEY") {
            match allow.parse() {
                Ok(value) => config.allow_insecure_key = value,
                Err(_) => {
                    tracing::warn!(
                        value = %allow,
                        "Invalid SESSION_ALLOW_INSECURE_KEY (expected true/false), defaulting to false for security"
                    );
                    config.allow_insecure_key = false;
                }
            }
        }

        config
    }

    /// Get default TTL as Duration
    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.default_ttl_seconds)
    }
}

fn default_ttl_seconds() -> u64 {
    3600 * 24 // 24 hours
}

fn default_cookie_name() -> String {
    "tideway_session".to_string()
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn default_secure() -> bool {
    true
}

fn default_http_only() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_encryption_key() {
        let config = SessionConfig {
            encryption_key: Some("deadbeef-session-key".to_string()),
            ..SessionConfig::default()
        };
        let debug = format!("{config:?}");

        assert!(!debug.contains("deadbeef-session-key"), "{debug}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("tideway_session"));
    }

    #[test]
    fn debug_shows_missing_encryption_key() {
        let debug = format!("{:?}", SessionConfig::default());
        assert!(debug.contains("encryption_key: None"), "{debug}");
    }
}
