use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::Response;
use axum::{Router, routing::get};
use std::sync::{Arc, Mutex};
use tideway::App;
use tideway::testing::TestHost;

#[tokio::test]
async fn test_host_builder_can_configure_app_before_build() {
    let host = TestHost::builder(App::new())
        .configure_app(|app| {
            app.merge_router(Router::new().route("/builder-route", get(|| async { "configured" })))
        })
        .build();

    host.scenario(|scenario| {
        scenario.get("/builder-route");
        scenario.content_should_contain("configured");
    })
    .await;
}

#[tokio::test]
async fn test_host_builder_preserves_without_middleware_choice() {
    let layer = axum::middleware::from_fn(
        |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
            let mut response = next.run(req).await;
            response
                .headers_mut()
                .insert("x-builder", "1".parse().unwrap());
            response
        },
    );

    let host = TestHost::builder(App::new().with_global_layer(layer))
        .without_middleware()
        .build();

    let outcome = host
        .scenario(|scenario| {
            scenario.get("/health");
        })
        .await;

    assert!(outcome.header("x-builder").is_none());
}

#[tokio::test]
async fn test_host_builder_applies_hooks() {
    async fn echo(headers: HeaderMap) -> Response<Body> {
        let value = headers
            .get("x-hook")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing");

        Response::builder()
            .status(axum::http::StatusCode::OK)
            .header("x-hook", value)
            .body(Body::empty())
            .unwrap()
    }

    let seen_status = Arc::new(Mutex::new(None));
    let host =
        TestHost::builder(App::new().merge_router(Router::new().route("/hooked", get(echo))))
            .before_each(|request| {
                request
                    .headers_mut()
                    .insert("x-hook", "builder".parse().unwrap());
            })
            .after_each({
                let seen_status = Arc::clone(&seen_status);
                move |outcome| {
                    *seen_status.lock().unwrap() = Some(outcome.status());
                }
            })
            .build();

    host.scenario(|scenario| {
        scenario.get("/hooked");
        scenario.header_should_be("x-hook", "builder");
    })
    .await;

    assert_eq!(*seen_status.lock().unwrap(), Some(StatusCode::OK));
}

#[cfg(feature = "auth")]
mod auth_context_override {
    use super::*;
    use async_trait::async_trait;
    use axum::Json;
    use serde::Deserialize;
    use serde_json::json;
    use std::sync::Arc;
    use tideway::auth::{AuthProvider, AuthUser};
    use tideway::{AppContext, RouteModule, TidewayError};

    #[derive(Clone, Default)]
    struct TestProvider;

    #[derive(Clone, Deserialize)]
    struct TestClaims {
        sub: String,
    }

    #[derive(Clone)]
    struct TestUser {
        id: String,
    }

    #[async_trait]
    impl AuthProvider for TestProvider {
        type Claims = TestClaims;
        type User = TestUser;

        async fn verify_token(&self, token: &str) -> tideway::Result<Self::Claims> {
            if token == "override-token" {
                Ok(TestClaims {
                    sub: "override-user".to_string(),
                })
            } else {
                Err(TidewayError::unauthorized("Invalid token"))
            }
        }

        async fn load_user(&self, claims: &Self::Claims) -> tideway::Result<Self::User> {
            Ok(TestUser {
                id: claims.sub.clone(),
            })
        }
    }

    struct ProtectedModule;

    impl RouteModule for ProtectedModule {
        fn routes(&self) -> Router<AppContext> {
            Router::new().route("/me", get(me))
        }

        fn prefix(&self) -> Option<&str> {
            Some("/api")
        }
    }

    async fn me(AuthUser(user): AuthUser<TestProvider>) -> Json<serde_json::Value> {
        Json(json!({ "id": user.id }))
    }

    #[tokio::test]
    async fn test_host_builder_can_override_context_dependencies() {
        let host = TestHost::builder(App::new().register_module(ProtectedModule))
            .configure_context(|context| context.with_auth_provider(Arc::new(TestProvider)))
            .build();

        host.scenario(|scenario| {
            scenario.get("/api/me");
            scenario.with_auth("override-token");
            scenario.json_path_should_be("id", json!("override-user"));
        })
        .await;
    }
}
