use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// Rate limiting configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum number of requests allowed per window
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,

    /// Time window in seconds for rate limiting
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,

    /// Rate limiting strategy: "global" or "per_ip"
    #[serde(default = "default_strategy")]
    pub strategy: String,

    /// Trust X-Forwarded-For header for client IP detection
    ///
    /// **SECURITY WARNING**: Only enable this if your application is behind
    /// a trusted reverse proxy (nginx, cloudflare, AWS ALB, etc.).
    ///
    /// When `false` (default): Only uses the direct connection IP, ignoring
    /// proxy headers. This is safe but won't work correctly behind a proxy.
    ///
    /// When `true`: Trusts X-Forwarded-For and X-Real-IP headers. Only enable
    /// if your proxy is properly configured to overwrite (not append to) these
    /// headers, otherwise attackers can spoof their IP to bypass rate limiting.
    ///
    /// Default: `false`
    #[serde(default)]
    pub trust_proxy: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_requests: default_max_requests(),
            window_seconds: default_window_seconds(),
            strategy: default_strategy(),
            trust_proxy: false,
        }
    }
}

impl RateLimitConfig {
    /// Create a new RateLimitConfig builder
    pub fn builder() -> RateLimitConfigBuilder {
        RateLimitConfigBuilder::new()
    }

    /// Create a permissive rate limit configuration for development
    /// Allows 1000 requests per minute
    pub fn permissive() -> Self {
        Self {
            enabled: true,
            max_requests: 1000,
            window_seconds: 60,
            strategy: "global".to_string(),
            trust_proxy: false,
        }
    }

    /// Create a restrictive rate limit configuration for production
    /// Default: 100 requests per minute per IP
    pub fn restrictive() -> Self {
        Self {
            enabled: true,
            max_requests: 100,
            window_seconds: 60,
            strategy: "per_ip".to_string(),
            trust_proxy: false,
        }
    }

    /// Load rate limit configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("RATE_LIMIT_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(max_requests) = get_env_with_prefix("RATE_LIMIT_MAX_REQUESTS") {
            if let Ok(val) = max_requests.parse() {
                config.max_requests = val;
            }
        }

        if let Some(window) = get_env_with_prefix("RATE_LIMIT_WINDOW_SECONDS") {
            if let Ok(val) = window.parse() {
                config.window_seconds = val;
            }
        }

        if let Some(strategy) = get_env_with_prefix("RATE_LIMIT_STRATEGY") {
            config.strategy = strategy;
        }

        if let Some(trust_proxy) = get_env_with_prefix("RATE_LIMIT_TRUST_PROXY") {
            config.trust_proxy = trust_proxy.parse().unwrap_or(false);
        }

        config
    }
}

/// Builder for RateLimitConfig
#[must_use = "builder does nothing until you call build()"]
pub struct RateLimitConfigBuilder {
    config: RateLimitConfig,
}

impl RateLimitConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: RateLimitConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn max_requests(mut self, max: u32) -> Self {
        self.config.max_requests = max;
        self
    }

    pub fn window_seconds(mut self, seconds: u64) -> Self {
        self.config.window_seconds = seconds;
        self
    }

    pub fn strategy(mut self, strategy: impl Into<String>) -> Self {
        self.config.strategy = strategy.into();
        self
    }

    pub fn per_ip(mut self) -> Self {
        self.config.strategy = "per_ip".to_string();
        self
    }

    pub fn global(mut self) -> Self {
        self.config.strategy = "global".to_string();
        self
    }

    /// Trust proxy headers (X-Forwarded-For, X-Real-IP) for client IP detection.
    ///
    /// **SECURITY WARNING**: Only enable this if behind a trusted reverse proxy.
    /// See [`RateLimitConfig::trust_proxy`] for details.
    pub fn trust_proxy(mut self, trust: bool) -> Self {
        self.config.trust_proxy = trust;
        self
    }

    pub fn build(self) -> RateLimitConfig {
        self.config
    }
}

impl Default for RateLimitConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    false
}

fn default_max_requests() -> u32 {
    100
}

fn default_window_seconds() -> u64 {
    60
}

fn default_strategy() -> String {
    "per_ip".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window_seconds, 60);
        assert_eq!(config.strategy, "per_ip");
        // Security: trust_proxy defaults to false
        assert!(!config.trust_proxy);
    }

    #[test]
    fn test_permissive_config() {
        let config = RateLimitConfig::permissive();
        assert!(config.enabled);
        assert_eq!(config.max_requests, 1000);
        assert_eq!(config.strategy, "global");
        assert!(!config.trust_proxy);
    }

    #[test]
    fn test_restrictive_config() {
        let config = RateLimitConfig::restrictive();
        assert!(config.enabled);
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.strategy, "per_ip");
        assert!(!config.trust_proxy);
    }

    #[test]
    fn test_builder() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .max_requests(200)
            .window_seconds(120)
            .per_ip()
            .build();

        assert!(config.enabled);
        assert_eq!(config.max_requests, 200);
        assert_eq!(config.window_seconds, 120);
        assert_eq!(config.strategy, "per_ip");
        assert!(!config.trust_proxy);
    }

    #[test]
    fn test_builder_trust_proxy() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip()
            .trust_proxy(true)
            .build();

        assert!(config.trust_proxy);
    }

    #[test]
    fn test_trust_proxy_defaults_false_for_security() {
        // This is a critical security test: trust_proxy MUST default to false
        // to prevent IP spoofing attacks via X-Forwarded-For header manipulation
        let config = RateLimitConfig::default();
        assert!(
            !config.trust_proxy,
            "SECURITY: trust_proxy must default to false to prevent IP spoofing"
        );

        let config = RateLimitConfig::builder().build();
        assert!(
            !config.trust_proxy,
            "SECURITY: trust_proxy must default to false in builder"
        );
    }
}
