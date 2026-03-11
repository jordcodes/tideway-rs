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

/// Merge multiple OpenAPI specs into one.
///
/// This is useful when you define smaller `#[derive(OpenApi)]` docs per module.
#[cfg(feature = "openapi")]
pub fn merge_openapi(mut docs: Vec<utoipa::openapi::OpenApi>) -> utoipa::openapi::OpenApi {
    let mut iter = docs.drain(..);
    let Some(mut openapi) = iter.next() else {
        let info = utoipa::openapi::Info::new("tideway", "0.0.0");
        return utoipa::openapi::OpenApi::new(info, utoipa::openapi::Paths::new());
    };

    for doc in iter {
        openapi.merge(doc);
    }

    openapi
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    mod merge_docs {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(paths())]
        pub struct DocOne;

        #[derive(OpenApi)]
        #[openapi(paths())]
        pub struct DocTwo;
    }

    #[derive(utoipa::ToSchema)]
    struct DummySchema;

    crate::openapi_components!(ComponentsDoc, schemas(DummySchema));

    #[derive(OpenApi)]
    #[openapi(paths())]
    struct ADoc;

    #[derive(OpenApi)]
    #[openapi(paths())]
    struct BDoc;

    #[test]
    fn test_openapi_merge_macro() {
        let openapi = crate::openapi_merge!(ADoc, BDoc);
        let title = openapi.info.title;
        assert!(!title.is_empty());
    }

    #[test]
    fn test_openapi_merge_macro_single_doc() {
        let openapi = crate::openapi_merge!(ADoc);
        let title = openapi.info.title;
        assert!(!title.is_empty());
    }

    #[test]
    fn test_merge_openapi_empty() {
        let openapi = merge_openapi(Vec::new());
        assert_eq!(openapi.info.title, "tideway");
    }

    #[test]
    fn test_openapi_doc_macro() {
        crate::openapi_doc!(DocOne, paths());
        crate::openapi_doc!(pub(crate) DocTwo, paths());

        let openapi = crate::openapi_merge!(DocOne, DocTwo);
        assert!(!openapi.info.title.is_empty());
    }

    #[test]
    fn test_openapi_components_macro() {
        let openapi = ComponentsDoc::openapi();
        assert!(!openapi.info.title.is_empty());
    }

    #[test]
    fn test_openapi_merge_module_macro() {
        let openapi = crate::openapi_merge_module!(merge_docs, DocOne, DocTwo);
        assert!(!openapi.info.title.is_empty());
    }
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

/// Define a lightweight `OpenApi` doc struct with less boilerplate.
///
/// # Example
/// ```ignore
/// tideway::openapi_doc!(pub(crate) UsersDoc, paths(crate::routes::users::list_users));
/// ```
#[cfg(feature = "openapi")]
#[macro_export]
macro_rules! openapi_doc {
    ($vis:vis $name:ident, $($openapi:tt)+) => {
        #[derive(utoipa::OpenApi)]
        #[openapi($($openapi)+)]
        $vis struct $name;
    };
    ($name:ident, $($openapi:tt)+) => {
        #[derive(utoipa::OpenApi)]
        #[openapi($($openapi)+)]
        struct $name;
    };
}

/// Define an OpenAPI components-only doc struct.
///
/// # Example
/// ```ignore
/// tideway::openapi_components!(pub(crate) ComponentsDoc, schemas(Foo, Bar));
/// ```
#[cfg(feature = "openapi")]
#[macro_export]
macro_rules! openapi_components {
    ($vis:vis $name:ident, schemas($($schema:ty),+ $(,)?), modifiers($($modifier:tt)+)) => {
        #[derive(utoipa::OpenApi)]
        #[openapi(components(schemas($($schema),+)), modifiers($($modifier)+))]
        $vis struct $name;
    };
    ($vis:vis $name:ident, schemas($($schema:ty),+ $(,)?)) => {
        #[derive(utoipa::OpenApi)]
        #[openapi(components(schemas($($schema),+)))]
        $vis struct $name;
    };
    ($name:ident, schemas($($schema:ty),+ $(,)?), modifiers($($modifier:tt)+)) => {
        #[derive(utoipa::OpenApi)]
        #[openapi(components(schemas($($schema),+)), modifiers($($modifier)+))]
        struct $name;
    };
    ($name:ident, schemas($($schema:ty),+ $(,)?)) => {
        #[derive(utoipa::OpenApi)]
        #[openapi(components(schemas($($schema),+)))]
        struct $name;
    };
}

/// Merge multiple `OpenApi` derives into a single spec.
///
/// # Example
/// ```ignore
/// let openapi = tideway::openapi_merge!(AuthDoc, BillingDoc, AdminDoc);
/// ```
#[cfg(feature = "openapi")]
#[macro_export]
macro_rules! openapi_merge {
    ($first:ty $(, $rest:ty)* $(,)?) => {{
        $crate::openapi::merge_openapi(vec![
            <$first as utoipa::OpenApi>::openapi()
            $(, <$rest as utoipa::OpenApi>::openapi())*
        ])
    }};
}

/// Merge multiple docs from the same module without repeating the module path.
///
/// # Example
/// ```ignore
/// let openapi = tideway::openapi_merge_module!(openapi_docs, UsersDoc, BillingDoc);
/// ```
#[cfg(feature = "openapi")]
#[macro_export]
macro_rules! openapi_merge_module {
    ($module:ident, $first:ident $(, $rest:ident)* $(,)?) => {
        $crate::openapi_merge!(
            $module::$first
            $(, $module::$rest)*
        )
    };
}
