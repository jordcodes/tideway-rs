use crate::utils::get_env_with_prefix;
use serde::{Deserialize, Serialize};

/// Metrics configuration for Tideway applications
#[derive(Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Whether metrics collection is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Path for the metrics endpoint (default: /metrics)
    #[serde(default = "default_path")]
    pub path: String,

    /// Bearer token required to scrape metrics. Without a nonempty token, no route is exposed.
    /// Loaded from TIDEWAY_METRICS_BEARER_TOKEN (or METRICS_BEARER_TOKEN).
    #[serde(default, skip_serializing)]
    pub bearer_token: Option<String>,
}

impl std::fmt::Debug for MetricsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsConfig")
            .field("enabled", &self.enabled)
            .field("path", &self.path)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            path: default_path(),
            bearer_token: None,
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

        config.bearer_token = get_env_with_prefix("METRICS_BEARER_TOKEN");

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

    /// Require this bearer token for the built-in scrape endpoint.
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.config.bearer_token = Some(token.into());
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
    fn test_token_is_not_exposed_in_debug_or_serialization() {
        let config = MetricsConfig::builder()
            .bearer_token("scrape-secret")
            .build();
        assert!(!format!("{config:?}").contains("scrape-secret"));
        assert!(
            !serde_json::to_string(&config)
                .unwrap()
                .contains("scrape-secret")
        );
        let old_config: MetricsConfig = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert!(old_config.bearer_token.is_none());
    }

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
