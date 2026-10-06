#![cfg(all(feature = "auth", feature = "test-auth-bypass"))]

use async_trait::async_trait;
use axum::middleware::from_fn;
use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tideway::auth::{AdminUser, AuthProvider, AuthUser, Claims, RequireAdmin, RequireAuth};
use tideway::testing::TestHost;
use tideway::{App, AppContext, RouteModule, TidewayError};

#[derive(Clone, Default)]
struct TestProvider;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    role: String,
}

#[derive(Clone, Debug)]
struct TestUser {
    id: String,
    role: String,
}

impl AdminUser for TestUser {
    fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[async_trait]
impl AuthProvider for TestProvider {
    type Claims = TestClaims;
    type User = TestUser;

    async fn verify_token(&self, token: &str) -> tideway::Result<Self::Claims> {
        if token == "real-token" {
            Ok(TestClaims {
                sub: "real-user".to_string(),
                role: "member".to_string(),
            })
        } else {
            Err(TidewayError::unauthorized("Invalid token"))
        }
    }

    async fn load_user(&self, claims: &Self::Claims) -> tideway::Result<Self::User> {
        Ok(TestUser {
            id: claims.sub.clone(),
            role: claims.role.clone(),
        })
    }

    async fn test_claims(&self, user_id: &str) -> tideway::Result<Self::Claims> {
        Ok(TestClaims {
            sub: user_id.to_string(),
            role: "member".to_string(),
        })
    }
}

struct TestAuthModule;

impl RouteModule for TestAuthModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/me", get(me))
            .route("/claims", get(claims))
            .route("/admin", get(admin))
            .route(
                "/guarded",
                get(guarded).layer(from_fn(RequireAuth::<TestProvider>::middleware)),
            )
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

async fn me(AuthUser(user): AuthUser<TestProvider>) -> Json<serde_json::Value> {
    Json(json!({ "id": user.id, "role": user.role }))
}

async fn claims(Claims(claims): Claims<TestProvider>) -> Json<serde_json::Value> {
    Json(json!({ "sub": claims.sub, "role": claims.role }))
}

async fn admin(RequireAdmin(user): RequireAdmin<TestProvider>) -> Json<serde_json::Value> {
    Json(json!({ "id": user.id, "role": user.role }))
}

async fn guarded(AuthUser(user): AuthUser<TestProvider>) -> Json<serde_json::Value> {
    Json(json!({ "id": user.id }))
}

fn host() -> TestHost {
    let context = AppContext::builder()
        .with_auth_provider(Arc::new(TestProvider))
        .build();

    let app = App::new()
        .with_context(context)
        .register_module(TestAuthModule);
    TestHost::new(app)
}

#[tokio::test]
async fn test_host_can_bypass_auth_with_test_user() {
    host()
        .scenario(|scenario| {
            scenario.get("/api/me");
            scenario.with_test_user("test-user-42");
            scenario.json_path_should_be("id", json!("test-user-42"));
            scenario.json_path_should_be("role", json!("member"));
        })
        .await;
}

#[tokio::test]
async fn test_host_can_override_claims_per_scenario() {
    host()
        .scenario(|scenario| {
            scenario.get("/api/claims");
            scenario.with_test_claims(&TestClaims {
                sub: "claims-user".to_string(),
                role: "admin".to_string(),
            });
            scenario.json_path_should_be("sub", json!("claims-user"));
            scenario.json_path_should_be("role", json!("admin"));
        })
        .await;
}

#[tokio::test]
async fn test_require_auth_middleware_honors_test_bypass() {
    host()
        .scenario(|scenario| {
            scenario.get("/api/guarded");
            scenario.with_test_user("guarded-user");
            scenario.json_path_should_be("id", json!("guarded-user"));
        })
        .await;
}

#[tokio::test]
async fn test_require_admin_honors_test_claims() {
    host()
        .scenario(|scenario| {
            scenario.get("/api/admin");
            scenario.with_test_claims(&TestClaims {
                sub: "admin-user".to_string(),
                role: "admin".to_string(),
            });
            scenario.json_path_should_be("id", json!("admin-user"));
            scenario.json_path_should_be("role", json!("admin"));
        })
        .await;
}

#[tokio::test]
async fn test_non_admin_claims_are_rejected() {
    let outcome = host()
        .scenario(|scenario| {
            scenario.get("/api/admin");
            scenario.with_test_user("member-user");
            scenario.status_code_should_be(403);
        })
        .await;

    assert_eq!(outcome.status(), axum::http::StatusCode::FORBIDDEN);
}
