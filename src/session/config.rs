use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::utils::get_env_with_prefix;

/// Session backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionBackend {
    /// In-memory session store (default, for dev/testing)
    InMemory,
    /// Cookie-based session store (encrypted cookies)
    #[cfg(feature = "sessions")]
    Cookie,
}

impl Default for SessionBackend {
    fn default() -> Self {
        Self::InMemory
    }
}

/// Session configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Encryption key for cookie sessions (32 bytes hex-encoded)
    ///
    /// **REQUIRED** for cookie-based sessions in production.
    /// Generate a secure key with: `openssl rand -hex 32`
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
                        tracing::warn!("Cookie sessions requested but sessions feature not enabled, using in-memory");
                        SessionBackend::InMemory
                    }
                }
                _ => SessionBackend::InMemory,
            };
        }

        if let Some(ttl) = get_env_with_prefix("SESSION_TTL_SECONDS") {
            if let Ok(seconds) = ttl.parse() {
                config.default_ttl_seconds = seconds;
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
            config.cookie_secure = secure.parse().unwrap_or(true);
        }

        if let Some(http_only) = get_env_with_prefix("SESSION_COOKIE_HTTP_ONLY") {
            config.cookie_http_only = http_only.parse().unwrap_or(true);
        }

        if let Some(key) = get_env_with_prefix("SESSION_ENCRYPTION_KEY") {
            config.encryption_key = Some(key);
        }

        if let Some(allow) = get_env_with_prefix("SESSION_ALLOW_INSECURE_KEY") {
            config.allow_insecure_key = allow.parse().unwrap_or(false);
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
