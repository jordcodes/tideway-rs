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
    pub fn from_env() -> Self {
        let enabled = std::env::var("OPENAPI_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        let swagger_ui = std::env::var("OPENAPI_SWAGGER_UI")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        let serve_spec = std::env::var("OPENAPI_SERVE_SPEC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        let visibility = std::env::var("OPENAPI_VISIBILITY")
            .ok()
            .and_then(|v| match v.to_lowercase().as_str() {
                "public" | "public-only" => Some(OpenApiVisibility::PublicOnly),
                "internal" | "internal-only" => Some(OpenApiVisibility::InternalOnly),
                "all" => Some(OpenApiVisibility::All),
                _ => None,
            })
            .unwrap_or(OpenApiVisibility::All);

        Self {
            enabled,
            swagger_ui,
            serve_spec,
            visibility,
            ..Default::default()
        }
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
