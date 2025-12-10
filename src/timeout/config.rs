use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::utils::get_env_with_prefix;

/// Timeout configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    /// Whether timeout is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Request timeout duration in seconds
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            timeout_seconds: default_timeout_seconds(),
        }
    }
}

impl TimeoutConfig {
    /// Create a new TimeoutConfig builder
    pub fn builder() -> TimeoutConfigBuilder {
        TimeoutConfigBuilder::new()
    }

    /// Get the timeout duration
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    /// Load timeout configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("TIMEOUT_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(seconds) = get_env_with_prefix("TIMEOUT_SECONDS") {
            if let Ok(s) = seconds.parse() {
                config.timeout_seconds = s;
            }
        }

        config
    }
}

/// Builder for TimeoutConfig
#[must_use = "builder does nothing until you call build()"]
pub struct TimeoutConfigBuilder {
    config: TimeoutConfig,
}

impl TimeoutConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: TimeoutConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn timeout_seconds(mut self, seconds: u64) -> Self {
        self.config.timeout_seconds = seconds;
        self
    }

    pub fn timeout(mut self, duration: Duration) -> Self {
        self.config.timeout_seconds = duration.as_secs();
        self
    }

    pub fn build(self) -> TimeoutConfig {
        self.config
    }
}

impl Default for TimeoutConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_timeout_seconds() -> u64 {
    30 // 30 seconds default timeout
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TimeoutConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.duration(), Duration::from_secs(30));
    }

    #[test]
    fn test_builder() {
        let config = TimeoutConfig::builder()
            .timeout_seconds(60)
            .build();

        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.duration(), Duration::from_secs(60));
    }

    #[test]
    fn test_duration() {
        let config = TimeoutConfig::builder()
            .timeout(Duration::from_secs(45))
            .build();

        assert_eq!(config.timeout_seconds, 45);
    }
}

