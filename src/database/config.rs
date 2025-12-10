use serde::{Deserialize, Serialize};

/// Database configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// Database connection URL
    /// Format: postgres://user:password@host:port/database
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
}
