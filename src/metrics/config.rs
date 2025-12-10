use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// Metrics configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Whether metrics collection is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Path for the metrics endpoint (default: /metrics)
    #[serde(default = "default_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            path: default_path(),
        }
    }
}

impl MetricsConfig {
    /// Create a new MetricsConfig builder
    pub fn builder() -> MetricsConfigBuilder {
        MetricsConfigBuilder::new()
    }

    /// Load metrics configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("METRICS_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(path) = get_env_with_prefix("METRICS_PATH") {
            config.path = path;
        }

        config
    }
}

/// Builder for MetricsConfig
#[must_use = "builder does nothing until you call build()"]
pub struct MetricsConfigBuilder {
    config: MetricsConfig,
}

impl MetricsConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: MetricsConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.config.path = path.into();
        self
    }

    pub fn build(self) -> MetricsConfig {
        self.config
    }
}

impl Default for MetricsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    false // Disabled by default (opt-in)
}

fn default_path() -> String {
    "/metrics".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MetricsConfig::default();
        assert!(!config.enabled); // Disabled by default
        assert_eq!(config.path, "/metrics");
    }

    #[test]
    fn test_builder() {
        let config = MetricsConfig::builder()
            .enabled(true)
            .path("/custom-metrics")
            .build();

        assert!(config.enabled);
        assert_eq!(config.path, "/custom-metrics");
    }
}

