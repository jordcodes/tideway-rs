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
        Self::default().with_env()
    }

    /// Apply environment overrides, preserving settings for absent or invalid variables.
    pub(crate) fn with_env(mut self) -> Self {
        let parse_bool = |name| std::env::var(name).ok().and_then(|v| v.parse().ok());

        if let Some(enabled) = parse_bool("OPENAPI_ENABLED") {
            self.enabled = enabled;
        }

        if let Some(swagger_ui) = parse_bool("OPENAPI_SWAGGER_UI") {
            self.swagger_ui = swagger_ui;
        }

        if let Some(serve_spec) = parse_bool("OPENAPI_SERVE_SPEC") {
            self.serve_spec = serve_spec;
        }

        if let Some(visibility) =
            std::env::var("OPENAPI_VISIBILITY")
                .ok()
                .and_then(|v| match v.to_lowercase().as_str() {
                    "public" | "public-only" => Some(OpenApiVisibility::PublicOnly),
                    "internal" | "internal-only" => Some(OpenApiVisibility::InternalOnly),
                    "all" => Some(OpenApiVisibility::All),
                    _ => None,
                })
        {
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
