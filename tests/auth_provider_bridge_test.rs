#![cfg(feature = "auth")]

use async_trait::async_trait;
use axum::{Router, routing::get};
use serde::Deserialize;
use std::sync::Arc;
use tideway::auth::{AuthProvider, AuthUser};
use tideway::testing::get as test_get;
use tideway::{App, AppContext, MessageResponse, RouteModule, TidewayError};

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
        if token == "ok-token" {
            Ok(TestClaims {
                sub: "user-1".to_string(),
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

async fn me(AuthUser(user): AuthUser<TestProvider>) -> MessageResponse {
    MessageResponse::success(format!("hello {}", user.id))
}

#[tokio::test]
async fn test_auth_provider_from_context_is_available_to_extractors() {
    let context = AppContext::builder()
        .with_auth_provider(Arc::new(TestProvider))
        .build();

    let app = App::new()
        .with_context(context)
        .register_module(ProtectedModule)
        .into_router_with_middleware();

    test_get(app, "/api/me")
        .header("Authorization", "Bearer ok-token")
        .execute()
        .await
        .assert_ok();
}
