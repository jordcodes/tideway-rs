use serde::{Deserialize, Serialize, ser::SerializeStruct};
use std::fmt;

/// Database configuration
///
/// # Security Note
///
/// Both `Debug` and `Serialize` implementations for this struct redact the database URL
/// to prevent accidental logging of credentials. Use [`redacted_url()`]
/// to get a safe-to-log version of the URL.
///
/// **Important**: The raw URL is only accessible via the `url` field directly.
/// All formatted output (Debug, JSON serialization) will show redacted credentials.
#[derive(Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Database connection URL
    /// Format: postgres://user:password@host:port/database
    ///
    /// **Security Warning**: This field contains credentials.
    /// Never log this value directly. Use [`redacted_url()`] instead.
    pub url: String,

    /// Maximum number of connections in the pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum number of idle connections in the pool
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,

    /// Idle timeout in seconds (0 = no timeout)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,

    /// Run migrations on startup
    #[serde(default = "default_auto_migrate")]
    pub auto_migrate: bool,
}

fn default_max_connections() -> u32 {
    10
}

fn default_min_connections() -> u32 {
    1
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    600 // 10 minutes
}

fn default_auto_migrate() -> bool {
    false
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/myapp".to_string(),
            max_connections: default_max_connections(),
            min_connections: default_min_connections(),
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            auto_migrate: default_auto_migrate(),
        }
    }
}

impl DatabaseConfig {
    /// Load from environment variable DATABASE_URL
    pub fn from_env() -> Result<Self, std::env::VarError> {
        let url = std::env::var("DATABASE_URL")?;
        Ok(Self {
            url,
            ..Default::default()
        })
    }

    /// Parse additional config from environment
    pub fn with_env_overrides(mut self) -> Self {
        if let Ok(max_conn) = std::env::var("DATABASE_MAX_CONNECTIONS") {
            if let Ok(value) = max_conn.parse() {
                self.max_connections = value;
            }
        }

        if let Ok(min_conn) = std::env::var("DATABASE_MIN_CONNECTIONS") {
            if let Ok(value) = min_conn.parse() {
                self.min_connections = value;
            }
        }

        if let Ok(timeout) = std::env::var("DATABASE_CONNECT_TIMEOUT") {
            if let Ok(value) = timeout.parse() {
                self.connect_timeout = value;
            }
        }

        if let Ok(auto_migrate) = std::env::var("DATABASE_AUTO_MIGRATE") {
            self.auto_migrate = auto_migrate.parse().unwrap_or(false);
        }

        self
    }

    /// Get a redacted version of the database URL safe for logging
    ///
    /// This replaces the password portion of the URL with `[REDACTED]`.
    /// The scheme, host, port, and database name are preserved.
    ///
    /// # Examples
    ///
    /// - `postgres://user:secret@host:5432/db` → `postgres://user:[REDACTED]@host:5432/db`
    /// - `postgres://host:5432/db` → `postgres://host:5432/db` (no password)
    pub fn redacted_url(&self) -> String {
        redact_database_url(&self.url)
    }
}

/// Redact credentials from a database URL
///
/// Replaces the password in URLs of the form `scheme://user:password@host/path`
/// with `[REDACTED]`. Safe for logging and error messages.
pub fn redact_database_url(url: &str) -> String {
    // Try to parse as URL, fall back to simple redaction
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.password().is_some() {
            // Replace password with redacted marker
            let _ = parsed.set_password(Some("[REDACTED]"));
        }
        parsed.to_string()
    } else {
        // Fallback: simple regex-like replacement for common patterns
        // Matches user:password@ pattern
        if let Some(at_pos) = url.find('@') {
            if let Some(colon_pos) = url[..at_pos].rfind(':') {
                // Check if there's a scheme before this (://user:pass@)
                if let Some(scheme_end) = url.find("://") {
                    if colon_pos > scheme_end + 3 {
                        // Found password pattern
                        return format!(
                            "{}[REDACTED]{}",
                            &url[..colon_pos + 1],
                            &url[at_pos..]
                        );
                    }
                }
            }
        }
        // Can't identify password, return as-is (might not contain one)
        url.to_string()
    }
}

/// Custom Debug implementation that redacts the database URL
///
/// This prevents accidental logging of database credentials.
impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &self.redacted_url())
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("connect_timeout", &self.connect_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("auto_migrate", &self.auto_migrate)
            .finish()
    }
}

/// Custom Serialize implementation that redacts the database URL
///
/// This prevents credential leakage through JSON logging, structured logging,
/// monitoring tools, or any other serialization-based output.
impl Serialize for DatabaseConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DatabaseConfig", 6)?;
        state.serialize_field("url", &self.redacted_url())?;
        state.serialize_field("max_connections", &self.max_connections)?;
        state.serialize_field("min_connections", &self.min_connections)?;
        state.serialize_field("connect_timeout", &self.connect_timeout)?;
        state.serialize_field("idle_timeout", &self.idle_timeout)?;
        state.serialize_field("auto_migrate", &self.auto_migrate)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_url_with_password() {
        let url = "postgres://myuser:supersecret@localhost:5432/mydb";
        let redacted = redact_database_url(url);
        eprintln!("Original: {}", url);
        eprintln!("Redacted: {}", redacted);
        assert!(redacted.contains("[REDACTED]") || redacted.contains("%5BREDACTED%5D"),
            "Expected redaction marker, got: {}", redacted);
        assert!(!redacted.contains("supersecret"), "Password leaked: {}", redacted);
        assert!(redacted.contains("myuser"));
        assert!(redacted.contains("localhost"));
    }

    #[test]
    fn test_redact_url_without_password() {
        let url = "postgres://localhost:5432/mydb";
        let redacted = redact_database_url(url);
        assert_eq!(redacted, url);
    }

    #[test]
    fn test_redact_url_with_user_no_password() {
        let url = "postgres://myuser@localhost:5432/mydb";
        let redacted = redact_database_url(url);
        // No password to redact
        assert!(!redacted.contains("[REDACTED]"));
        assert!(redacted.contains("myuser"));
    }

    #[test]
    fn test_debug_does_not_leak_password() {
        let config = DatabaseConfig {
            url: "postgres://admin:hunter2@db.example.com:5432/production".to_string(),
            ..Default::default()
        };

        let debug_output = format!("{:?}", config);
        assert!(!debug_output.contains("hunter2"), "Password leaked in debug output!");
        // URL library may encode brackets as %5B and %5D
        assert!(debug_output.contains("REDACTED"), "Missing redaction marker: {}", debug_output);
        assert!(debug_output.contains("admin")); // Username is OK
        assert!(debug_output.contains("db.example.com")); // Host is OK
    }

    #[test]
    fn test_redacted_url_method() {
        let config = DatabaseConfig {
            url: "postgres://user:pass123@host/db".to_string(),
            ..Default::default()
        };

        let redacted = config.redacted_url();
        assert!(!redacted.contains("pass123"));
        // URL library may encode brackets as %5B and %5D
        assert!(redacted.contains("REDACTED"), "Missing redaction marker: {}", redacted);
    }

    #[test]
    fn test_serialize_does_not_leak_password() {
        let config = DatabaseConfig {
            url: "postgres://admin:hunter2@db.example.com:5432/production".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("hunter2"), "Password leaked in JSON serialization: {}", json);
        assert!(json.contains("REDACTED"), "Missing redaction marker in JSON: {}", json);
        assert!(json.contains("admin"), "Username should be preserved");
        assert!(json.contains("db.example.com"), "Host should be preserved");
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_note() {
        // Note: Due to security redaction, serialize -> deserialize will NOT
        // preserve the original password. This is intentional.
        // Users should store raw URLs separately if needed for reconnection.
        let config = DatabaseConfig {
            url: "postgres://user:secret@host/db".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DatabaseConfig = serde_json::from_str(&json).unwrap();

        // The deserialized URL will have [REDACTED] instead of the password
        assert!(deserialized.url.contains("REDACTED"));
        assert!(!deserialized.url.contains("secret"));
    }
}
