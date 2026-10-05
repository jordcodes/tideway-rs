//! Development mode configuration

use crate::utils::{get_env_with_prefix, is_production_like_environment};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Development mode configuration
///
/// Controls development-specific features like request/response dumping,
/// richer error responses, and other dev-only diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevConfig {
    /// Enable development mode middleware and related diagnostics.
    #[serde(default)]
    pub enabled: bool,
    /// Include stack traces in dev error responses
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
        Self::default().with_env()
    }

    /// Apply environment overrides, preserving settings for absent variables.
    pub(crate) fn with_env(mut self) -> Self {
        if let Some(enabled) = get_env_with_prefix("DEV_MODE") {
            self.enabled = enabled.parse().unwrap_or(false);
        }

        if let Some(stack_traces) = get_env_with_prefix("DEV_STACK_TRACES") {
            self.include_stack_traces = stack_traces.parse().unwrap_or(false);
        }

        if let Some(dump_requests) = get_env_with_prefix("DEV_DUMP_REQUESTS") {
            self.enable_request_dumper = dump_requests.parse().unwrap_or(false);
        }

        if let Some(dump_path) = get_env_with_prefix("DEV_DUMP_PATH") {
            self.dump_path_pattern = Some(dump_path);
        }

        self
    }

    /// Check if dev mode is effectively enabled.
    ///
    /// Returns `false` in production-like environments (`ENV`, `ENVIRONMENT`,
    /// `APP_ENV`, or `TIDEWAY_ENV` set to `prod`/`production`) even when
    /// `enabled` is `true`, so dev diagnostics can never leak in production.
    pub fn is_dev_mode(&self) -> bool {
        if !self.enabled {
            return false;
        }
        if is_production_like_environment() {
            tracing::warn!(
                "Dev mode was requested but is disabled because the environment is production"
            );
            return false;
        }
        true
    }
}

/// Returns the config with all dev features turned off when dev mode is not
/// effectively enabled (e.g. it was requested in a production environment).
pub(crate) fn effective_config(config: Arc<DevConfig>) -> Arc<DevConfig> {
    if config.is_dev_mode() {
        return config;
    }
    Arc::new(DevConfig {
        enabled: false,
        include_stack_traces: false,
        enable_request_dumper: false,
        dump_path_pattern: config.dump_path_pattern.clone(),
    })
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
