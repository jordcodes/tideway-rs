//! Dev mode must never expose internal error details in production.
//!
//! Lives in its own test binary because it mutates process environment
//! variables that other dev-mode tests depend on.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::{Router, routing::get};
use tideway::{App, AppContext, ConfigBuilder, DevConfigBuilder, RouteModule, TidewayError};
use tower::ServiceExt;

struct ErrorModule;

impl RouteModule for ErrorModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/boom", get(boom))
    }
}

async fn boom() -> tideway::Result<&'static str> {
    Err(TidewayError::internal("connection pool exhausted"))
}

async fn error_body() -> serde_json::Value {
    let config = ConfigBuilder::new()
        .with_dev_config(
            DevConfigBuilder::new()
                .enabled(true)
                .with_stack_traces(true)
                .build(),
        )
        .build()
        .expect("build config");

    let app = App::with_config(config)
        .register_module(ErrorModule)
        .into_router_with_middleware();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/boom")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body"),
    )
    .expect("parse json body")
}

#[tokio::test]
async fn test_dev_mode_is_ignored_in_production_environment() {
    for (key, value) in [
        ("TIDEWAY_ENV", "production"),
        ("APP_ENV", "prod"),
        ("ENVIRONMENT", "Production"),
    ] {
        unsafe {
            std::env::set_var(key, value);
        }

        let body = error_body().await;
        let dev_config = DevConfigBuilder::new().enabled(true).build();
        let dev_mode = dev_config.is_dev_mode();

        unsafe {
            std::env::remove_var(key);
        }

        assert!(!dev_mode, "{key}={value} should disable dev mode");
        assert_eq!(
            body["error"],
            serde_json::json!("Internal server error"),
            "{key}={value} leaked internal error details: {body}"
        );
        assert!(
            body.get("stack_trace").is_none(),
            "{key}={value} leaked a stack trace: {body}"
        );
    }

    // Sanity check: outside production, dev mode still exposes details.
    let body = error_body().await;
    assert_eq!(
        body["error"],
        serde_json::json!("Internal server error: connection pool exhausted")
    );
}
