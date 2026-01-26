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

// A module for optional registration tests
struct OptionalModule;

impl RouteModule for OptionalModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/optional", get(|| async { Json(json!({"ok": true})) }))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

#[tokio::test]
async fn test_app_builder_respects_module_prefix() {
    let app = App::builder()
        .register_module(PrefixedModule)
        .build()
        .into_router();

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
        .into_router();

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
        .into_router();

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
        .into_router();

    let app_via_direct = App::new()
        .register_module(PrefixedModule)
        .into_router();

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

#[tokio::test]
async fn test_register_optional_module_skips_none() {
    let app = App::new()
        .register_optional_module(None::<OptionalModule>)
        .into_router();

    test_get(app, "/api/optional")
        .execute()
        .await
        .assert_not_found();
}

#[tokio::test]
async fn test_register_optional_module_registers_some() {
    let app = App::new()
        .register_optional_module(Some(OptionalModule))
        .into_router();

    test_get(app, "/api/optional")
        .execute()
        .await
        .assert_ok();
}

#[tokio::test]
async fn test_register_modules_macro() {
    let app = tideway::register_modules!(
        App::new(),
        OptionalModule,
        AdminModule,
    )
    .into_router();

    test_get(app.clone(), "/api/optional")
        .execute()
        .await
        .assert_ok();

    test_get(app, "/admin/users")
        .execute()
        .await
        .assert_ok();
}

#[tokio::test]
async fn test_health_route_available_on_default_app() {
    let app = App::new().into_router();

    test_get(app, "/health")
        .execute()
        .await
        .assert_ok();
}

#[tokio::test]
async fn test_health_route_available_on_builder() {
    let app = App::builder()
        .build()
        .into_router();

    test_get(app, "/health")
        .execute()
        .await
        .assert_ok();
}
