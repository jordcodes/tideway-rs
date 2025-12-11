//! Tests for App and AppBuilder functionality

use axum::{routing::get, Json, Router};
use serde_json::json;
use tideway::{App, AppContext, RouteModule};
use tideway::testing::get as test_get;

// A module with a prefix
struct PrefixedModule;

impl RouteModule for PrefixedModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/hello", get(|| async { Json(json!({"message": "hello from prefixed"})) }))
            .route("/world", get(|| async { Json(json!({"message": "world"})) }))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api/v1")
    }
}

// A module without a prefix
struct UnprefixedModule;

impl RouteModule for UnprefixedModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/status", get(|| async { Json(json!({"status": "ok"})) }))
    }

    fn prefix(&self) -> Option<&str> {
        None
    }
}

// A module with a different prefix
struct AdminModule;

impl RouteModule for AdminModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/users", get(|| async { Json(json!({"users": []})) }))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/admin")
    }
}

#[tokio::test]
async fn test_app_builder_respects_module_prefix() {
    let app = App::builder()
        .register_module(PrefixedModule)
        .build()
        .into_test_router();

    // Should be accessible at /api/v1/hello
    test_get(app.clone(), "/api/v1/hello")
        .execute()
        .await
        .assert_ok();

    // Should NOT be accessible at /hello (without prefix)
    test_get(app, "/hello")
        .execute()
        .await
        .assert_not_found();
}

#[tokio::test]
async fn test_app_builder_unprefixed_module() {
    let app = App::builder()
        .register_module(UnprefixedModule)
        .build()
        .into_test_router();

    // Should be accessible at root /status
    test_get(app, "/status")
        .execute()
        .await
        .assert_ok();
}

#[tokio::test]
async fn test_app_builder_multiple_modules_with_different_prefixes() {
    let app = App::builder()
        .register_module(PrefixedModule)
        .register_module(AdminModule)
        .register_module(UnprefixedModule)
        .build()
        .into_test_router();

    // PrefixedModule routes at /api/v1/*
    test_get(app.clone(), "/api/v1/hello")
        .execute()
        .await
        .assert_ok();

    test_get(app.clone(), "/api/v1/world")
        .execute()
        .await
        .assert_ok();

    // AdminModule routes at /admin/*
    test_get(app.clone(), "/admin/users")
        .execute()
        .await
        .assert_ok();

    // UnprefixedModule routes at root
    test_get(app.clone(), "/status")
        .execute()
        .await
        .assert_ok();

    // Cross-check: routes should NOT exist at wrong prefixes
    test_get(app.clone(), "/hello")
        .execute()
        .await
        .assert_not_found();

    test_get(app.clone(), "/api/v1/users")
        .execute()
        .await
        .assert_not_found();

    test_get(app, "/admin/hello")
        .execute()
        .await
        .assert_not_found();
}

#[tokio::test]
async fn test_app_register_module_matches_builder_behavior() {
    // Test that App::register_module and AppBuilder::register_module behave the same

    let app_via_builder = App::builder()
        .register_module(PrefixedModule)
        .build()
        .into_test_router();

    let app_via_direct = App::new()
        .register_module(PrefixedModule)
        .into_test_router();

    // Both should have routes at /api/v1/hello
    test_get(app_via_builder.clone(), "/api/v1/hello")
        .execute()
        .await
        .assert_ok();

    test_get(app_via_direct.clone(), "/api/v1/hello")
        .execute()
        .await
        .assert_ok();

    // Both should NOT have routes at /hello
    test_get(app_via_builder, "/hello")
        .execute()
        .await
        .assert_not_found();

    test_get(app_via_direct, "/hello")
        .execute()
        .await
        .assert_not_found();
}
