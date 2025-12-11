//! Development mode configuration

use crate::utils::get_env_with_prefix;
use serde::{Deserialize, Serialize};

/// Development mode configuration
///
/// Controls development-specific features like enhanced error responses
/// and request/response dumping.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevConfig {
    /// Enable development mode (enhanced errors, request dumper, etc.)
    #[serde(default)]
    pub enabled: bool,
    /// Include stack traces in error responses
    #[serde(default)]
    pub include_stack_traces: bool,
    /// Enable request/response dumper middleware
    #[serde(default)]
    pub enable_request_dumper: bool,
    /// Only dump requests matching this path pattern (empty = all)
    #[serde(default)]
    pub dump_path_pattern: Option<String>,
}

impl DevConfig {
    /// Create dev config from environment variables
    ///
    /// Environment variables:
    /// - `TIDEWAY_DEV_MODE`: Enable dev mode (default: false)
    /// - `TIDEWAY_DEV_STACK_TRACES`: Include stack traces (default: false)
    /// - `TIDEWAY_DEV_DUMP_REQUESTS`: Enable request dumper (default: false)
    /// - `TIDEWAY_DEV_DUMP_PATH`: Path pattern to dump (default: all)
    pub fn from_env() -> Self {
        let enabled = get_env_with_prefix("DEV_MODE")
            .map(|v| v.parse().unwrap_or(false))
            .unwrap_or(false);

        let include_stack_traces = get_env_with_prefix("DEV_STACK_TRACES")
            .map(|v| v.parse().unwrap_or(false))
            .unwrap_or(false);

        let enable_request_dumper = get_env_with_prefix("DEV_DUMP_REQUESTS")
            .map(|v| v.parse().unwrap_or(false))
            .unwrap_or(false);

        let dump_path_pattern = get_env_with_prefix("DEV_DUMP_PATH");

        Self {
            enabled,
            include_stack_traces,
            enable_request_dumper,
            dump_path_pattern,
        }
    }

    /// Check if dev mode is enabled
    pub fn is_dev_mode(&self) -> bool {
        self.enabled
    }
}

/// Builder for DevConfig
#[must_use = "builder does nothing until you call build()"]
pub struct DevConfigBuilder {
    config: DevConfig,
}

impl DevConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: DevConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn with_stack_traces(mut self, include: bool) -> Self {
        self.config.include_stack_traces = include;
        self
    }

    pub fn with_request_dumper(mut self, enabled: bool) -> Self {
        self.config.enable_request_dumper = enabled;
        self
    }

    pub fn with_dump_path_pattern(mut self, pattern: Option<String>) -> Self {
        self.config.dump_path_pattern = pattern;
        self
    }

    pub fn build(self) -> DevConfig {
        self.config
    }
}

impl Default for DevConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
