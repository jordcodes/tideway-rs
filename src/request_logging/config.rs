use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// Request logging configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestLoggingConfig {
    /// Whether request logging is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Include request headers in logs
    #[serde(default = "default_include_headers")]
    pub include_headers: bool,

    /// Include response headers in logs
    #[serde(default)]
    pub include_response_headers: bool,

    /// Include request body preview (first N bytes)
    /// Set to 0 to disable body preview
    #[serde(default = "default_body_preview_size")]
    pub body_preview_size: usize,

    /// Log level for successful requests (2xx)
    #[serde(default = "default_success_level")]
    pub success_level: LogLevel,

    /// Log level for client errors (4xx)
    #[serde(default = "default_client_error_level")]
    pub client_error_level: LogLevel,

    /// Log level for server errors (5xx)
    #[serde(default = "default_server_error_level")]
    pub server_error_level: LogLevel,
}

/// Log level for request logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Trace level
    Trace,
    /// Debug level
    Debug,
    /// Info level
    Info,
    /// Warn level
    Warn,
    /// Error level
    Error,
}

impl Default for RequestLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            include_headers: default_include_headers(),
            include_response_headers: false,
            body_preview_size: default_body_preview_size(),
            success_level: LogLevel::Info,
            client_error_level: LogLevel::Warn,
            server_error_level: LogLevel::Error,
        }
    }
}

impl RequestLoggingConfig {
    /// Create a new RequestLoggingConfig builder
    pub fn builder() -> RequestLoggingConfigBuilder {
        RequestLoggingConfigBuilder::new()
    }

    /// Load request logging configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("REQUEST_LOGGING_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(include_headers) = get_env_with_prefix("REQUEST_LOGGING_INCLUDE_HEADERS") {
            config.include_headers = include_headers.parse().unwrap_or(false);
        }

        if let Some(include_response) = get_env_with_prefix("REQUEST_LOGGING_INCLUDE_RESPONSE_HEADERS") {
            config.include_response_headers = include_response.parse().unwrap_or(false);
        }

        if let Some(preview_size) = get_env_with_prefix("REQUEST_LOGGING_BODY_PREVIEW_SIZE") {
            if let Ok(size) = preview_size.parse() {
                config.body_preview_size = size;
            }
        }

        if let Some(level) = get_env_with_prefix("REQUEST_LOGGING_SUCCESS_LEVEL") {
            config.success_level = parse_log_level(&level);
        }

        if let Some(level) = get_env_with_prefix("REQUEST_LOGGING_CLIENT_ERROR_LEVEL") {
            config.client_error_level = parse_log_level(&level);
        }

        if let Some(level) = get_env_with_prefix("REQUEST_LOGGING_SERVER_ERROR_LEVEL") {
            config.server_error_level = parse_log_level(&level);
        }

        config
    }
}

fn parse_log_level(s: &str) -> LogLevel {
    match s.to_lowercase().as_str() {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => LogLevel::Info,
    }
}

/// Builder for RequestLoggingConfig
#[must_use = "builder does nothing until you call build()"]
pub struct RequestLoggingConfigBuilder {
    config: RequestLoggingConfig,
}

impl RequestLoggingConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: RequestLoggingConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn include_headers(mut self, include: bool) -> Self {
        self.config.include_headers = include;
        self
    }

    pub fn include_response_headers(mut self, include: bool) -> Self {
        self.config.include_response_headers = include;
        self
    }

    pub fn body_preview_size(mut self, size: usize) -> Self {
        self.config.body_preview_size = size;
        self
    }

    pub fn success_level(mut self, level: LogLevel) -> Self {
        self.config.success_level = level;
        self
    }

    pub fn client_error_level(mut self, level: LogLevel) -> Self {
        self.config.client_error_level = level;
        self
    }

    pub fn server_error_level(mut self, level: LogLevel) -> Self {
        self.config.server_error_level = level;
        self
    }

    pub fn build(self) -> RequestLoggingConfig {
        self.config
    }
}

impl Default for RequestLoggingConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_include_headers() -> bool {
    false
}

fn default_body_preview_size() -> usize {
    256 // First 256 bytes
}

fn default_success_level() -> LogLevel {
    LogLevel::Info
}

fn default_client_error_level() -> LogLevel {
    LogLevel::Warn
}

fn default_server_error_level() -> LogLevel {
    LogLevel::Error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RequestLoggingConfig::default();
        assert!(config.enabled);
        assert!(!config.include_headers);
        assert_eq!(config.body_preview_size, 256);
        assert_eq!(config.success_level, LogLevel::Info);
    }

    #[test]
    fn test_builder() {
        let config = RequestLoggingConfig::builder()
            .include_headers(true)
            .body_preview_size(512)
            .success_level(LogLevel::Debug)
            .build();

        assert!(config.include_headers);
        assert_eq!(config.body_preview_size, 512);
        assert_eq!(config.success_level, LogLevel::Debug);
    }
}

