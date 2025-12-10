//! OpenAPI/Swagger documentation support.
//!
//! Provides automatic API documentation generation using utoipa
//! and Swagger UI for interactive API exploration.

pub mod config;

pub use config::{OpenApiConfig, OpenApiVisibility};

#[cfg(feature = "openapi")]
use axum::{Json, Router, routing::get};
#[cfg(feature = "openapi")]
use utoipa_swagger_ui::SwaggerUi;

/// Create a router with Swagger UI and OpenAPI spec endpoints
#[cfg(feature = "openapi")]
pub fn create_openapi_router(openapi: utoipa::openapi::OpenApi, config: &OpenApiConfig) -> Router {
    let mut router = Router::new();

    // Add dedicated JSON spec endpoint if enabled
    if config.serve_spec {
        let openapi_clone = openapi.clone();
        let spec_path = config.spec_path.clone();

        router = router.route(
            &spec_path,
            get(move || async move { Json(openapi_clone.clone()) }),
        );

        tracing::info!(path = spec_path, "OpenAPI spec endpoint enabled");
    }

    // Add Swagger UI if enabled
    if config.swagger_ui {
        let swagger_ui =
            SwaggerUi::new(config.swagger_ui_path.clone()).url(config.spec_path.clone(), openapi);

        router = router.merge(swagger_ui);

        tracing::info!(path = config.swagger_ui_path, "Swagger UI enabled");
    }

    router
}

/// Helper macro to reduce boilerplate for common response patterns
#[cfg(feature = "openapi")]
#[macro_export]
macro_rules! openapi_path {
    (
        $method:ident,
        path = $path:expr,
        tag = $tag:expr,
        summary = $summary:expr,
        request_body = $request:ty,
        response = $response:ty
    ) => {
        #[utoipa::path(
            $method,
            path = $path,
            tag = $tag,
            summary = $summary,
            request_body = $request,
            responses(
                (status = 200, description = "Success", body = $response),
                (status = 401, description = "Unauthorized"),
                (status = 500, description = "Internal server error")
            ),
            security(("bearer_auth" = []))
        )]
    };
}
