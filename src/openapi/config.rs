use crate::utils::{get_env_with_prefix, parse_env_bool};

/// Read a route path override, ignoring values that axum cannot mount (must start with `/`).
fn env_route_path(key: &str) -> Option<String> {
    let value = get_env_with_prefix(key)?;
    let value = value.trim();

    if value.starts_with('/') {
        return Some(value.to_string());
    }

    tracing::warn!(
        key,
        value,
        "Ignoring OpenAPI path that does not start with '/'"
    );
    None
}

/// OpenAPI configuration for controlling documentation generation and serving
#[derive(Debug, Clone)]
pub struct OpenApiConfig {
    /// Enable OpenAPI feature
    pub enabled: bool,

    /// Serve Swagger UI (typically disable in production)
    pub swagger_ui: bool,

    /// Serve OpenAPI JSON spec endpoint
    pub serve_spec: bool,

    /// Path to serve Swagger UI
    pub swagger_ui_path: String,

    /// Path to serve OpenAPI spec
    pub spec_path: String,

    /// Visibility filter for endpoints
    pub visibility: OpenApiVisibility,
}

/// Controls which endpoints are included in the OpenAPI spec
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenApiVisibility {
    /// Include all documented endpoints
    All,
    /// Only include endpoints tagged as "public" (exclude internal)
    PublicOnly,
    /// Only include internal endpoints
    InternalOnly,
}

impl Default for OpenApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            swagger_ui: false,
            serve_spec: false,
            swagger_ui_path: "/swagger-ui".to_string(),
            spec_path: "/api-docs/openapi.json".to_string(),
            visibility: OpenApiVisibility::All,
        }
    }
}

impl OpenApiConfig {
    /// Create config from environment variables
    /// Checks TIDEWAY_ prefixed vars first, falls back to unprefixed for compatibility
    pub fn from_env() -> Self {
        Self::default().with_env()
    }

    /// Apply environment overrides, preserving settings for absent or invalid variables.
    pub(crate) fn with_env(mut self) -> Self {
        if let Some(enabled) = get_env_with_prefix("OPENAPI_ENABLED") {
            self.enabled = parse_env_bool("OPENAPI_ENABLED", &enabled, self.enabled);
        }

        if let Some(swagger_ui) = get_env_with_prefix("OPENAPI_SWAGGER_UI") {
            self.swagger_ui = parse_env_bool("OPENAPI_SWAGGER_UI", &swagger_ui, self.swagger_ui);
        }

        if let Some(serve_spec) = get_env_with_prefix("OPENAPI_SERVE_SPEC") {
            self.serve_spec = parse_env_bool("OPENAPI_SERVE_SPEC", &serve_spec, self.serve_spec);
        }

        if let Some(path) = env_route_path("OPENAPI_SWAGGER_UI_PATH") {
            self.swagger_ui_path = path;
        }

        if let Some(path) = env_route_path("OPENAPI_SPEC_PATH") {
            self.spec_path = path;
        }

        if let Some(visibility) = get_env_with_prefix("OPENAPI_VISIBILITY").and_then(|v| {
            match v.to_lowercase().as_str() {
                "public" | "public-only" => Some(OpenApiVisibility::PublicOnly),
                "internal" | "internal-only" => Some(OpenApiVisibility::InternalOnly),
                "all" => Some(OpenApiVisibility::All),
                _ => None,
            }
        }) {
            self.visibility = visibility;
        }

        self
    }

    /// Builder: Enable OpenAPI
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Builder: Enable Swagger UI
    pub fn with_swagger_ui(mut self) -> Self {
        self.swagger_ui = true;
        self
    }

    /// Builder: Enable spec endpoint
    pub fn with_spec(mut self) -> Self {
        self.serve_spec = true;
        self
    }

    /// Builder: Set visibility filter
    pub fn visibility(mut self, visibility: OpenApiVisibility) -> Self {
        self.visibility = visibility;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::env::lock_env;

    const KEYS: [&str; 6] = [
        "OPENAPI_ENABLED",
        "OPENAPI_SWAGGER_UI",
        "OPENAPI_SERVE_SPEC",
        "OPENAPI_SWAGGER_UI_PATH",
        "OPENAPI_SPEC_PATH",
        "OPENAPI_VISIBILITY",
    ];

    fn clear_openapi_env() {
        for key in KEYS {
            unsafe {
                std::env::remove_var(key);
                std::env::remove_var(format!("TIDEWAY_{key}"));
            }
        }
    }

    #[test]
    fn test_from_env_reads_prefixed_and_unprefixed_vars() {
        let _env = lock_env();
        clear_openapi_env();
        unsafe {
            std::env::set_var("TIDEWAY_OPENAPI_ENABLED", "yes");
            std::env::set_var("OPENAPI_SWAGGER_UI", "1");
            std::env::set_var("OPENAPI_SERVE_SPEC", "on");
            std::env::set_var("TIDEWAY_OPENAPI_SWAGGER_UI_PATH", "/docs");
            std::env::set_var("OPENAPI_SPEC_PATH", "/docs/openapi.json");
            std::env::set_var("OPENAPI_VISIBILITY", "public");
        }

        let config = OpenApiConfig::from_env();
        clear_openapi_env();

        assert!(config.enabled);
        assert!(config.swagger_ui);
        assert!(config.serve_spec);
        assert_eq!(config.swagger_ui_path, "/docs");
        assert_eq!(config.spec_path, "/docs/openapi.json");
        assert_eq!(config.visibility, OpenApiVisibility::PublicOnly);
    }

    #[test]
    fn test_from_env_prefers_prefixed_var() {
        let _env = lock_env();
        clear_openapi_env();
        unsafe {
            std::env::set_var("TIDEWAY_OPENAPI_ENABLED", "false");
            std::env::set_var("OPENAPI_ENABLED", "true");
        }

        let config = OpenApiConfig::default().enable().with_env();
        clear_openapi_env();

        assert!(!config.enabled);
    }

    #[test]
    fn test_from_env_invalid_values_keep_current_settings() {
        let _env = lock_env();
        clear_openapi_env();
        unsafe {
            std::env::set_var("OPENAPI_ENABLED", "maybe");
            std::env::set_var("OPENAPI_SWAGGER_UI_PATH", "docs");
            std::env::set_var("OPENAPI_SPEC_PATH", "");
        }

        let config = OpenApiConfig::default().enable().with_env();
        clear_openapi_env();

        assert!(config.enabled);
        assert_eq!(config.swagger_ui_path, "/swagger-ui");
        assert_eq!(config.spec_path, "/api-docs/openapi.json");
    }
}
