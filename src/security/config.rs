use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// X-Frame-Options header value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum XFrameOptions {
    /// DENY - Don't allow framing at all
    Deny,
    /// SAMEORIGIN - Allow framing from same origin
    SameOrigin,
}

impl Default for XFrameOptions {
    fn default() -> Self {
        Self::Deny
    }
}

/// Referrer-Policy header value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferrerPolicy {
    /// No referrer information is sent
    NoReferrer,
    /// Only send referrer for same-origin requests
    SameOrigin,
    /// Send full referrer for same-origin, only origin for cross-origin
    StrictOriginWhenCrossOrigin,
    /// Send origin only
    StrictOrigin,
    /// Send full referrer (not recommended)
    UnsafeUrl,
}

impl Default for ReferrerPolicy {
    fn default() -> Self {
        Self::StrictOriginWhenCrossOrigin
    }
}

/// Security headers configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Whether security headers are enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Strict-Transport-Security (HSTS) max age in seconds
    /// Set to 0 to disable HSTS
    #[serde(default = "default_hsts_max_age")]
    pub hsts_max_age: u64,

    /// Include HSTS preload directive
    #[serde(default)]
    pub hsts_preload: bool,

    /// Include HSTS includeSubDomains directive
    #[serde(default)]
    pub hsts_include_subdomains: bool,

    /// X-Content-Type-Options header
    /// Set to false to disable nosniff header
    #[serde(default = "default_nosniff")]
    pub nosniff: bool,

    /// X-Frame-Options header value
    #[serde(default)]
    pub x_frame_options: Option<XFrameOptions>,

    /// X-XSS-Protection header (deprecated but some APIs still use)
    /// Set to Some(false) to explicitly disable, None to omit
    #[serde(default)]
    pub xss_protection: Option<bool>,

    /// Content-Security-Policy header value
    /// Set to None to disable CSP
    #[serde(default)]
    pub content_security_policy: Option<String>,

    /// Referrer-Policy header value
    #[serde(default)]
    pub referrer_policy: Option<ReferrerPolicy>,

    /// Permissions-Policy header value
    /// Example: "geolocation=(), microphone=()"
    #[serde(default)]
    pub permissions_policy: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            hsts_max_age: default_hsts_max_age(),
            hsts_preload: false,
            hsts_include_subdomains: true,
            nosniff: default_nosniff(),
            x_frame_options: Some(XFrameOptions::default()),
            xss_protection: Some(false), // Disable deprecated XSS protection
            content_security_policy: None,
            referrer_policy: Some(ReferrerPolicy::default()),
            permissions_policy: None,
        }
    }
}

impl SecurityConfig {
    /// Create a new SecurityConfig builder
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::new()
    }

    /// Load security configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("SECURITY_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(max_age) = get_env_with_prefix("SECURITY_HSTS_MAX_AGE") {
            if let Ok(age) = max_age.parse() {
                config.hsts_max_age = age;
            }
        }

        if let Some(preload) = get_env_with_prefix("SECURITY_HSTS_PRELOAD") {
            config.hsts_preload = preload.parse().unwrap_or(false);
        }

        if let Some(include_subdomains) = get_env_with_prefix("SECURITY_HSTS_INCLUDE_SUBDOMAINS") {
            config.hsts_include_subdomains = include_subdomains.parse().unwrap_or(true);
        }

        if let Some(nosniff) = get_env_with_prefix("SECURITY_NOSNIFF") {
            config.nosniff = nosniff.parse().unwrap_or(true);
        }

        if let Some(frame_options) = get_env_with_prefix("SECURITY_X_FRAME_OPTIONS") {
            config.x_frame_options = match frame_options.to_uppercase().as_str() {
                "DENY" => Some(XFrameOptions::Deny),
                "SAMEORIGIN" => Some(XFrameOptions::SameOrigin),
                "DISABLE" | "OFF" => None,
                _ => Some(XFrameOptions::default()),
            };
        }

        if let Some(csp) = get_env_with_prefix("SECURITY_CSP") {
            config.content_security_policy = Some(csp);
        }

        if let Some(referrer) = get_env_with_prefix("SECURITY_REFERRER_POLICY") {
            config.referrer_policy = match referrer.to_lowercase().as_str() {
                "no-referrer" => Some(ReferrerPolicy::NoReferrer),
                "same-origin" => Some(ReferrerPolicy::SameOrigin),
                "strict-origin-when-cross-origin" => Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
                "strict-origin" => Some(ReferrerPolicy::StrictOrigin),
                "unsafe-url" => Some(ReferrerPolicy::UnsafeUrl),
                "disable" | "off" => None,
                _ => Some(ReferrerPolicy::default()),
            };
        }

        if let Some(permissions) = get_env_with_prefix("SECURITY_PERMISSIONS_POLICY") {
            config.permissions_policy = Some(permissions);
        }

        config
    }
}

/// Builder for SecurityConfig
#[must_use = "builder does nothing until you call build()"]
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl SecurityConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: SecurityConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn hsts_max_age(mut self, seconds: u64) -> Self {
        self.config.hsts_max_age = seconds;
        self
    }

    pub fn hsts_preload(mut self, preload: bool) -> Self {
        self.config.hsts_preload = preload;
        self
    }

    pub fn hsts_include_subdomains(mut self, include: bool) -> Self {
        self.config.hsts_include_subdomains = include;
        self
    }

    pub fn nosniff(mut self, enabled: bool) -> Self {
        self.config.nosniff = enabled;
        self
    }

    pub fn x_frame_options(mut self, options: Option<XFrameOptions>) -> Self {
        self.config.x_frame_options = options;
        self
    }

    pub fn deny_framing(mut self) -> Self {
        self.config.x_frame_options = Some(XFrameOptions::Deny);
        self
    }

    pub fn same_origin_framing(mut self) -> Self {
        self.config.x_frame_options = Some(XFrameOptions::SameOrigin);
        self
    }

    pub fn allow_framing(mut self) -> Self {
        self.config.x_frame_options = None;
        self
    }

    pub fn xss_protection(mut self, enabled: Option<bool>) -> Self {
        self.config.xss_protection = enabled;
        self
    }

    pub fn content_security_policy(mut self, csp: Option<String>) -> Self {
        self.config.content_security_policy = csp;
        self
    }

    pub fn referrer_policy(mut self, policy: Option<ReferrerPolicy>) -> Self {
        self.config.referrer_policy = policy;
        self
    }

    pub fn permissions_policy(mut self, policy: Option<String>) -> Self {
        self.config.permissions_policy = policy;
        self
    }

    pub fn build(self) -> SecurityConfig {
        self.config
    }
}

impl Default for SecurityConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_hsts_max_age() -> u64 {
    31536000 // 1 year
}

fn default_nosniff() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert!(config.enabled);
        assert_eq!(config.hsts_max_age, 31536000);
        assert!(config.nosniff);
        assert_eq!(config.x_frame_options, Some(XFrameOptions::Deny));
    }

    #[test]
    fn test_builder() {
        let config = SecurityConfig::builder()
            .hsts_max_age(63072000) // 2 years
            .deny_framing()
            .nosniff(true)
            .build();

        assert_eq!(config.hsts_max_age, 63072000);
        assert_eq!(config.x_frame_options, Some(XFrameOptions::Deny));
        assert!(config.nosniff);
    }

    #[test]
    fn test_framing_options() {
        let config = SecurityConfig::builder()
            .same_origin_framing()
            .build();
        assert_eq!(config.x_frame_options, Some(XFrameOptions::SameOrigin));

        let config = SecurityConfig::builder()
            .allow_framing()
            .build();
        assert_eq!(config.x_frame_options, None);
    }
}

