use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[cfg(feature = "openapi")]
use crate::openapi::OpenApiConfig;

use crate::compression::CompressionConfig;
use crate::cors::CorsConfig;
use crate::dev::DevConfig;
use crate::ratelimit::RateLimitConfig;
use crate::request_logging::RequestLoggingConfig;
use crate::security::SecurityConfig;
use crate::timeout::TimeoutConfig;
use crate::utils::get_env_with_prefix;

#[cfg(feature = "jobs")]
use crate::jobs::JobsConfig;

/// Main configuration for a Tideway application
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    pub compression: CompressionConfig,
    pub security: SecurityConfig,
    pub timeout: TimeoutConfig,
    pub request_logging: RequestLoggingConfig,
    pub cors: CorsConfig,
    pub rate_limit: RateLimitConfig,
    pub dev: DevConfig,
    #[cfg(feature = "openapi")]
    #[serde(skip)]
    pub openapi: OpenApiConfig,
    #[cfg(feature = "metrics")]
    #[serde(skip)]
    pub metrics: crate::metrics::MetricsConfig,
    #[cfg(feature = "jobs")]
    pub jobs: JobsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Maximum request body size in bytes (default: 10MB)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_json")]
    pub json: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            logging: LoggingConfig::default(),
            compression: CompressionConfig::default(),
            security: SecurityConfig::default(),
            timeout: TimeoutConfig::default(),
            request_logging: RequestLoggingConfig::default(),
            cors: CorsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            dev: DevConfig::default(),
            #[cfg(feature = "openapi")]
            openapi: OpenApiConfig::default(),
            #[cfg(feature = "metrics")]
            metrics: crate::metrics::MetricsConfig::default(),
            #[cfg(feature = "jobs")]
            jobs: JobsConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            max_body_size: default_max_body_size(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json: default_json(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_json() -> bool {
    false
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB default
}

impl ServerConfig {
    pub fn addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.host, self.port).parse()
    }
}

/// Builder for Config with environment variable and file support
#[must_use = "builder does nothing until you call build()"]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.config.server.host = host.into();
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.config.server.port = port;
        self
    }

    /// Set the maximum request body size in bytes
    ///
    /// This sets a global default limit for all request bodies (JSON, form data, etc.).
    /// Individual routes can override this limit using `DefaultBodyLimit::max()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tideway::config::ConfigBuilder;
    ///
    /// let config = ConfigBuilder::new()
    ///     .with_max_body_size(50 * 1024 * 1024) // 50MB
    ///     .build()?;
    /// ```
    pub fn with_max_body_size(mut self, max_body_size: usize) -> Self {
        self.config.server.max_body_size = max_body_size;
        self
    }

    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.config.logging.level = level.into();
        self
    }

    pub fn with_json_logging(mut self, enabled: bool) -> Self {
        self.config.logging.json = enabled;
        self
    }

    pub fn with_cors(mut self, cors: CorsConfig) -> Self {
        self.config.cors = cors;
        self
    }

    pub fn with_cors_enabled(mut self, enabled: bool) -> Self {
        self.config.cors.enabled = enabled;
        self
    }

    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.config.rate_limit = rate_limit;
        self
    }

    pub fn with_compression(mut self, compression: CompressionConfig) -> Self {
        self.config.compression = compression;
        self
    }

    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.config.security = security;
        self
    }

    pub fn with_timeout(mut self, timeout: TimeoutConfig) -> Self {
        self.config.timeout = timeout;
        self
    }

    pub fn with_request_logging(mut self, request_logging: RequestLoggingConfig) -> Self {
        self.config.request_logging = request_logging;
        self
    }

    #[cfg(feature = "metrics")]
    pub fn with_metrics(mut self, metrics: crate::metrics::MetricsConfig) -> Self {
        self.config.metrics = metrics;
        self
    }

    pub fn with_dev_config(mut self, dev: DevConfig) -> Self {
        self.config.dev = dev;
        self
    }

    pub fn with_dev_mode(mut self, enabled: bool) -> Self {
        self.config.dev.enabled = enabled;
        self
    }

    #[cfg(feature = "jobs")]
    pub fn with_jobs_config(mut self, jobs: JobsConfig) -> Self {
        self.config.jobs = jobs;
        self
    }

    /// Load configuration from environment variables with TIDEWAY_ prefix
    pub fn from_env(mut self) -> Self {
        if let Some(host) = get_env_with_prefix("HOST") {
            self.config.server.host = host;
        }
        // Check TIDEWAY_PORT first, fall back to PORT (for Railway/Heroku compatibility)
        if let Some(port) = get_env_with_prefix("PORT") {
            if let Ok(p) = port.parse() {
                self.config.server.port = p;
            }
        }
        if let Some(max_body_size) = get_env_with_prefix("MAX_BODY_SIZE") {
            if let Ok(size) = max_body_size.parse() {
                self.config.server.max_body_size = size;
            }
        }
        if let Some(level) = get_env_with_prefix("LOG_LEVEL") {
            self.config.logging.level = level;
        }
        if let Some(json) = get_env_with_prefix("LOG_JSON") {
            self.config.logging.json = json.parse().unwrap_or(false);
        }

        // Load CORS config
        self.config.cors = CorsConfig::from_env();

        // Load rate limit config
        self.config.rate_limit = RateLimitConfig::from_env();

        // Load compression config
        self.config.compression = CompressionConfig::from_env();

        // Load security config
        self.config.security = SecurityConfig::from_env();

        // Load timeout config
        self.config.timeout = TimeoutConfig::from_env();

        // Load request logging config
        self.config.request_logging = RequestLoggingConfig::from_env();

        // Load OpenAPI config
        #[cfg(feature = "openapi")]
        {
            self.config.openapi = OpenApiConfig::from_env();
        }

        // Load metrics config
        #[cfg(feature = "metrics")]
        {
            self.config.metrics = crate::metrics::MetricsConfig::from_env();
        }

        // Load dev config
        self.config.dev = DevConfig::from_env();

        // Load jobs config
        #[cfg(feature = "jobs")]
        {
            self.config.jobs = JobsConfig::from_env();
        }

        self
    }

    /// Build the configuration, validating all settings
    ///
    /// # Errors
    ///
    /// Returns an error if any configuration is invalid:
    /// - Invalid server address (host:port)
    /// - Invalid log level
    /// - Invalid timeout values
    /// - Invalid rate limit settings
    /// - Other configuration validation failures
    pub fn build(self) -> crate::error::Result<Config> {
        // Validate server address
        self.config.server.addr()
            .map_err(|e| crate::error::TidewayError::bad_request(
                format!("Invalid server address {}:{} - {}",
                    self.config.server.host,
                    self.config.server.port,
                    e
                )
            ))?;

        // Validate log level
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.config.logging.level.to_lowercase().as_str()) {
            return Err(crate::error::TidewayError::bad_request(
                format!("Invalid log level: {}. Must be one of: {}",
                    self.config.logging.level,
                    valid_log_levels.join(", ")
                )
            ));
        }

        // Validate timeout values (only if enabled)
        if self.config.timeout.enabled && self.config.timeout.timeout_seconds == 0 {
            return Err(crate::error::TidewayError::bad_request(
                "Request timeout must be greater than 0 when enabled"
            ));
        }

        // Validate rate limit settings (only if enabled)
        if self.config.rate_limit.enabled {
            if self.config.rate_limit.max_requests == 0 {
                return Err(crate::error::TidewayError::bad_request(
                    "Rate limit max_requests must be greater than 0 when enabled"
                ));
            }

            if self.config.rate_limit.window_seconds == 0 {
                return Err(crate::error::TidewayError::bad_request(
                    "Rate limit window_seconds must be greater than 0 when enabled"
                ));
            }

            // Validate strategy
            if self.config.rate_limit.strategy != "global" && self.config.rate_limit.strategy != "per_ip" {
                return Err(crate::error::TidewayError::bad_request(
                    format!("Rate limit strategy must be 'global' or 'per_ip', got: {}",
                        self.config.rate_limit.strategy
                    )
                ));
            }
        }

        // Validate port is in valid range
        if self.config.server.port == 0 {
            return Err(crate::error::TidewayError::bad_request(
                "Server port must be greater than 0"
            ));
        }

        // Validate max body size
        if self.config.server.max_body_size == 0 {
            return Err(crate::error::TidewayError::bad_request(
                "Maximum body size must be greater than 0"
            ));
        }

        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
