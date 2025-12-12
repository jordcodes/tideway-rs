use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// CORS configuration for Tideway applications
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsConfig {
    /// Whether CORS is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Allowed origins (e.g., ["http://localhost:3000", "https://example.com"])
    /// Use ["*"] to allow all origins (not recommended for production)
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods (e.g., ["GET", "POST", "PUT", "DELETE"])
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed headers (e.g., ["content-type", "authorization"])
    /// Use ["*"] to allow all headers
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: Vec<String>,

    /// Exposed headers that browsers can access
    #[serde(default)]
    pub exposed_headers: Vec<String>,

    /// Whether to allow credentials (cookies, authorization headers)
    #[serde(default)]
    pub allow_credentials: bool,

    /// Maximum age for preflight request caching (in seconds)
    #[serde(default = "default_max_age")]
    pub max_age_seconds: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            // Default: empty origins - CORS disabled by default for security
            // Users must explicitly enable and configure allowed origins
            allowed_origins: Vec::new(),
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
            exposed_headers: Vec::new(),
            // Default: no credentials allowed for security
            allow_credentials: false,
            max_age_seconds: default_max_age(),
        }
    }
}

impl CorsConfig {
    /// Create a new CorsConfig builder
    pub fn builder() -> CorsConfigBuilder {
        CorsConfigBuilder::new()
    }

    /// Create a permissive CORS configuration for development
    /// WARNING: Do not use in production!
    pub fn permissive() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec!["*".to_string()],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_seconds: 3600,
        }
    }

    /// Create a restrictive CORS configuration for production
    pub fn restrictive(allowed_origins: Vec<String>) -> Self {
        Self {
            enabled: true,
            allowed_origins,
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["content-type".to_string(), "authorization".to_string()],
            exposed_headers: vec![],
            allow_credentials: true,
            max_age_seconds: 3600,
        }
    }

    /// Load CORS configuration from environment variables
    /// Checks TIDEWAY_ prefixed vars first, falls back to unprefixed for compatibility
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("CORS_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(true);
        }

        if let Some(origins) = get_env_with_prefix("CORS_ALLOWED_ORIGINS") {
            config.allowed_origins = origins.split(',').map(|s| s.trim().to_string()).collect();
        }

        if let Some(methods) = get_env_with_prefix("CORS_ALLOWED_METHODS") {
            config.allowed_methods = methods.split(',').map(|s| s.trim().to_string()).collect();
        }

        if let Some(headers) = get_env_with_prefix("CORS_ALLOWED_HEADERS") {
            config.allowed_headers = headers.split(',').map(|s| s.trim().to_string()).collect();
        }

        if let Some(exposed) = get_env_with_prefix("CORS_EXPOSED_HEADERS") {
            config.exposed_headers = exposed.split(',').map(|s| s.trim().to_string()).collect();
        }

        if let Some(credentials) = get_env_with_prefix("CORS_ALLOW_CREDENTIALS") {
            config.allow_credentials = credentials.parse().unwrap_or(false);
        }

        if let Some(max_age) = get_env_with_prefix("CORS_MAX_AGE") {
            if let Ok(val) = max_age.parse() {
                config.max_age_seconds = val;
            }
        }

        config
    }
}

/// Builder for CorsConfig
#[must_use = "builder does nothing until you call build()"]
pub struct CorsConfigBuilder {
    config: CorsConfig,
}

impl CorsConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: CorsConfig::default(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        self.config.allowed_origins.push(origin.into());
        self
    }

    pub fn allow_origins(mut self, origins: Vec<String>) -> Self {
        self.config.allowed_origins = origins;
        self
    }

    pub fn allow_any_origin(mut self) -> Self {
        self.config.allowed_origins = vec!["*".to_string()];
        self
    }

    pub fn allow_method(mut self, method: impl Into<String>) -> Self {
        self.config.allowed_methods.push(method.into());
        self
    }

    pub fn allow_methods(mut self, methods: Vec<String>) -> Self {
        self.config.allowed_methods = methods;
        self
    }

    pub fn allow_header(mut self, header: impl Into<String>) -> Self {
        self.config.allowed_headers.push(header.into());
        self
    }

    pub fn allow_headers(mut self, headers: Vec<String>) -> Self {
        self.config.allowed_headers = headers;
        self
    }

    pub fn allow_any_header(mut self) -> Self {
        self.config.allowed_headers = vec!["*".to_string()];
        self
    }

    pub fn expose_header(mut self, header: impl Into<String>) -> Self {
        self.config.exposed_headers.push(header.into());
        self
    }

    pub fn expose_headers(mut self, headers: Vec<String>) -> Self {
        self.config.exposed_headers = headers;
        self
    }

    pub fn allow_credentials(mut self, allow: bool) -> Self {
        self.config.allow_credentials = allow;
        self
    }

    pub fn max_age(mut self, seconds: u64) -> Self {
        self.config.max_age_seconds = seconds;
        self
    }

    pub fn build(self) -> CorsConfig {
        self.config
    }
}

impl Default for CorsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_enabled() -> bool {
    // SECURITY: CORS is disabled by default.
    // Users must explicitly enable CORS and configure allowed origins.
    // This prevents accidental exposure of APIs to cross-origin requests.
    false
}

fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "PATCH".to_string(),
        "DELETE".to_string(),
    ]
}

fn default_allowed_headers() -> Vec<String> {
    vec![
        "content-type".to_string(),
        "authorization".to_string(),
        "x-request-id".to_string(),
    ]
}

fn default_max_age() -> u64 {
    3600 // 1 hour
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CorsConfig::default();
        // SECURITY: CORS disabled by default
        assert!(!config.enabled);
        assert_eq!(config.allowed_origins.len(), 0);
        assert_eq!(config.allowed_methods.len(), 5);
        assert!(!config.allow_credentials);
    }

    #[test]
    fn test_cors_disabled_by_default_for_security() {
        // This is a critical security test: CORS must be disabled by default
        // to prevent accidental cross-origin API exposure
        let config = CorsConfig::default();
        assert!(
            !config.enabled,
            "SECURITY: CORS must be disabled by default"
        );

        let config = CorsConfig::builder().build();
        assert!(
            !config.enabled,
            "SECURITY: CORS must be disabled by default in builder"
        );
    }

    #[test]
    fn test_permissive_config() {
        let config = CorsConfig::permissive();
        assert!(config.enabled);
        assert_eq!(config.allowed_origins, vec!["*"]);
        assert_eq!(config.allowed_headers, vec!["*"]);
        assert!(!config.allow_credentials);
    }

    #[test]
    fn test_restrictive_config() {
        let origins = vec!["https://example.com".to_string()];
        let config = CorsConfig::restrictive(origins.clone());
        assert!(config.enabled);
        assert_eq!(config.allowed_origins, origins);
        assert!(config.allow_credentials);
        assert_eq!(config.allowed_methods.len(), 2);
    }

    #[test]
    fn test_builder() {
        let config = CorsConfig::builder()
            .allow_origin("https://example.com")
            .allow_method("GET")
            .allow_header("content-type")
            .allow_credentials(true)
            .max_age(7200)
            .build();

        assert_eq!(config.allowed_origins, vec!["https://example.com"]);
        assert!(config.allow_credentials);
        assert_eq!(config.max_age_seconds, 7200);
    }

    #[test]
    fn test_builder_any_origin() {
        let config = CorsConfig::builder().allow_any_origin().build();
        assert_eq!(config.allowed_origins, vec!["*"]);
    }

    #[test]
    fn test_builder_explicit_enable() {
        let config = CorsConfig::builder()
            .enabled(true)
            .allow_origin("https://example.com")
            .build();

        assert!(config.enabled);
        assert_eq!(config.allowed_origins, vec!["https://example.com"]);
    }
}
