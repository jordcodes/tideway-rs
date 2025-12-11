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

#[allow(clippy::derivable_impls)] // Cannot derive due to conditional #[cfg] fields
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
    /// use tideway::ConfigBuilder;
    ///
    /// let config = ConfigBuilder::new()
    ///     .with_max_body_size(50 * 1024 * 1024) // 50MB
    ///     .build()
    ///     .unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    // ============ Default config tests ============

    #[test]
    fn test_config_default() {
        let config = Config::default();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8000);
        assert_eq!(config.server.max_body_size, 10 * 1024 * 1024);
        assert_eq!(config.logging.level, "info");
        assert!(!config.logging.json);
    }

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();

        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8000);
        assert_eq!(config.max_body_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();

        assert_eq!(config.level, "info");
        assert!(!config.json);
    }

    #[test]
    fn test_server_config_addr() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
            max_body_size: 1024,
        };

        let addr = config.addr().unwrap();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_server_config_addr_invalid() {
        let config = ServerConfig {
            host: "not-a-valid-host".to_string(),
            port: 3000,
            max_body_size: 1024,
        };

        assert!(config.addr().is_err());
    }

    // ============ ConfigBuilder tests ============

    #[test]
    fn test_config_builder_new() {
        let builder = ConfigBuilder::new();
        let config = builder.build().unwrap();

        // Should have default values
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8000);
    }

    #[test]
    fn test_config_builder_default() {
        let builder = ConfigBuilder::default();
        let config = builder.build().unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8000);
    }

    #[test]
    fn test_config_builder_with_host() {
        let config = ConfigBuilder::new()
            .with_host("127.0.0.1")
            .build()
            .unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
    }

    #[test]
    fn test_config_builder_with_port() {
        let config = ConfigBuilder::new()
            .with_port(3000)
            .build()
            .unwrap();

        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn test_config_builder_with_max_body_size() {
        let config = ConfigBuilder::new()
            .with_max_body_size(50 * 1024 * 1024)
            .build()
            .unwrap();

        assert_eq!(config.server.max_body_size, 50 * 1024 * 1024);
    }

    #[test]
    fn test_config_builder_with_log_level() {
        let config = ConfigBuilder::new()
            .with_log_level("debug")
            .build()
            .unwrap();

        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_config_builder_with_json_logging() {
        let config = ConfigBuilder::new()
            .with_json_logging(true)
            .build()
            .unwrap();

        assert!(config.logging.json);
    }

    #[test]
    fn test_config_builder_with_cors_enabled() {
        let config = ConfigBuilder::new()
            .with_cors_enabled(true)
            .build()
            .unwrap();

        assert!(config.cors.enabled);
    }

    #[test]
    fn test_config_builder_with_dev_mode() {
        let config = ConfigBuilder::new()
            .with_dev_mode(true)
            .build()
            .unwrap();

        assert!(config.dev.enabled);
    }

    #[test]
    fn test_config_builder_chaining() {
        let config = ConfigBuilder::new()
            .with_host("127.0.0.1")
            .with_port(4000)
            .with_max_body_size(1024)
            .with_log_level("warn")
            .with_json_logging(true)
            .with_cors_enabled(true)
            .with_dev_mode(true)
            .build()
            .unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 4000);
        assert_eq!(config.server.max_body_size, 1024);
        assert_eq!(config.logging.level, "warn");
        assert!(config.logging.json);
        assert!(config.cors.enabled);
        assert!(config.dev.enabled);
    }

    // ============ Validation tests ============

    #[test]
    fn test_config_builder_invalid_host() {
        let result = ConfigBuilder::new()
            .with_host("not-valid-ip-address")
            .build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid server address"));
    }

    #[test]
    fn test_config_builder_invalid_log_level() {
        let result = ConfigBuilder::new()
            .with_log_level("invalid_level")
            .build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid log level"));
    }

    #[test]
    fn test_config_builder_valid_log_levels() {
        for level in &["trace", "debug", "info", "warn", "error"] {
            let result = ConfigBuilder::new()
                .with_log_level(*level)
                .build();
            assert!(result.is_ok(), "Log level '{}' should be valid", level);
        }
    }

    #[test]
    fn test_config_builder_log_level_case_insensitive() {
        for level in &["TRACE", "Debug", "INFO", "Warn", "ERROR"] {
            let result = ConfigBuilder::new()
                .with_log_level(*level)
                .build();
            assert!(result.is_ok(), "Log level '{}' should be valid (case insensitive)", level);
        }
    }

    #[test]
    fn test_config_builder_port_zero_invalid() {
        let mut builder = ConfigBuilder::new();
        builder.config.server.port = 0;
        let result = builder.build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("port must be greater than 0"));
    }

    #[test]
    fn test_config_builder_max_body_size_zero_invalid() {
        let result = ConfigBuilder::new()
            .with_max_body_size(0)
            .build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("body size must be greater than 0"));
    }

    #[test]
    fn test_config_builder_timeout_zero_when_enabled() {
        let mut builder = ConfigBuilder::new();
        builder.config.timeout.enabled = true;
        builder.config.timeout.timeout_seconds = 0;
        let result = builder.build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("timeout must be greater than 0"));
    }

    #[test]
    fn test_config_builder_timeout_zero_when_disabled_ok() {
        let mut builder = ConfigBuilder::new();
        builder.config.timeout.enabled = false;
        builder.config.timeout.timeout_seconds = 0;
        let result = builder.build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_config_builder_rate_limit_max_requests_zero() {
        let mut builder = ConfigBuilder::new();
        builder.config.rate_limit.enabled = true;
        builder.config.rate_limit.max_requests = 0;
        builder.config.rate_limit.window_seconds = 60;
        let result = builder.build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("max_requests must be greater than 0"));
    }

    #[test]
    fn test_config_builder_rate_limit_window_zero() {
        let mut builder = ConfigBuilder::new();
        builder.config.rate_limit.enabled = true;
        builder.config.rate_limit.max_requests = 100;
        builder.config.rate_limit.window_seconds = 0;
        let result = builder.build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("window_seconds must be greater than 0"));
    }

    #[test]
    fn test_config_builder_rate_limit_invalid_strategy() {
        let mut builder = ConfigBuilder::new();
        builder.config.rate_limit.enabled = true;
        builder.config.rate_limit.max_requests = 100;
        builder.config.rate_limit.window_seconds = 60;
        builder.config.rate_limit.strategy = "invalid".to_string();
        let result = builder.build();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("strategy must be 'global' or 'per_ip'"));
    }

    #[test]
    fn test_config_builder_rate_limit_valid_strategies() {
        for strategy in &["global", "per_ip"] {
            let mut builder = ConfigBuilder::new();
            builder.config.rate_limit.enabled = true;
            builder.config.rate_limit.max_requests = 100;
            builder.config.rate_limit.window_seconds = 60;
            builder.config.rate_limit.strategy = strategy.to_string();
            let result = builder.build();
            assert!(result.is_ok(), "Strategy '{}' should be valid", strategy);
        }
    }

    #[test]
    fn test_config_builder_rate_limit_disabled_ignores_validation() {
        let mut builder = ConfigBuilder::new();
        builder.config.rate_limit.enabled = false;
        builder.config.rate_limit.max_requests = 0;
        builder.config.rate_limit.window_seconds = 0;
        builder.config.rate_limit.strategy = "invalid".to_string();
        let result = builder.build();

        // Should be ok because rate limit is disabled
        assert!(result.is_ok());
    }

    // ============ Serialization tests ============

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();

        assert!(json.contains("\"host\":\"0.0.0.0\""));
        assert!(json.contains("\"port\":8000"));
        assert!(json.contains("\"level\":\"info\""));
    }

    #[test]
    fn test_config_deserialization() {
        let json = r#"{
            "server": {"host": "localhost", "port": 3000, "max_body_size": 1024},
            "logging": {"level": "debug", "json": true},
            "compression": {"enabled": true, "gzip": true, "brotli": false, "level": 6, "brotli_quality": 4},
            "security": {"enabled": true, "hsts": true, "hsts_max_age": 31536000, "content_type_nosniff": true, "frame_options": "DENY"},
            "timeout": {"enabled": false, "timeout_seconds": 30},
            "request_logging": {"enabled": true, "level": "info", "include_headers": false, "include_body": false, "sensitive_headers": []},
            "cors": {"enabled": false, "allow_origins": [], "allow_methods": [], "allow_headers": [], "allow_credentials": false, "max_age": 0},
            "rate_limit": {"enabled": false, "max_requests": 100, "window_seconds": 60, "strategy": "global"},
            "dev": {"enabled": false}
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.server.max_body_size, 1024);
        assert_eq!(config.logging.level, "debug");
        assert!(config.logging.json);
    }

    // ============ Environment variable tests ============
    // Note: These tests run sequentially with #[serial] would be ideal,
    // but for now we test the env helper directly to avoid race conditions

    #[test]
    fn test_get_env_with_prefix_tideway_first() {
        unsafe {
            std::env::set_var("TIDEWAY_TEST_ENV_1", "prefixed");
            std::env::set_var("TEST_ENV_1", "unprefixed");
        }

        let value = get_env_with_prefix("TEST_ENV_1");
        assert_eq!(value, Some("prefixed".to_string()));

        unsafe {
            std::env::remove_var("TIDEWAY_TEST_ENV_1");
            std::env::remove_var("TEST_ENV_1");
        }
    }

    #[test]
    fn test_get_env_with_prefix_fallback() {
        unsafe {
            std::env::set_var("TEST_ENV_2", "fallback_value");
        }

        let value = get_env_with_prefix("TEST_ENV_2");
        assert_eq!(value, Some("fallback_value".to_string()));

        unsafe {
            std::env::remove_var("TEST_ENV_2");
        }
    }

    #[test]
    fn test_get_env_with_prefix_not_found() {
        let value = get_env_with_prefix("NONEXISTENT_TEST_VAR_12345");
        assert_eq!(value, None);
    }

    #[test]
    fn test_config_builder_from_env_integration() {
        // Use unique env var names to avoid conflicts with parallel tests
        unsafe {
            std::env::set_var("TIDEWAY_HOST", "10.0.0.1");
            std::env::set_var("TIDEWAY_LOG_LEVEL", "trace");
        }

        let config = ConfigBuilder::new()
            .from_env()
            .build()
            .unwrap();

        assert_eq!(config.server.host, "10.0.0.1");
        assert_eq!(config.logging.level, "trace");

        unsafe {
            std::env::remove_var("TIDEWAY_HOST");
            std::env::remove_var("TIDEWAY_LOG_LEVEL");
        }
    }
}
