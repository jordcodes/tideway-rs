#![cfg(all(feature = "auth", feature = "test-auth-bypass"))]

//! End-to-end checks that protected routes accept organization API keys
//! alongside JWT-authenticated users.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use tideway::Result;
use tideway::auth::{
    ApiKeyAuth, ApiKeyConfig, ApiKeyExtension, ApiKeyManager, AuthProvider, InMemoryApiKeyStore,
    NewApiKey, Principal,
};
use tower::ServiceExt;

#[derive(Clone)]
struct JwtProvider;

#[derive(Deserialize)]
struct JwtClaims {
    sub: String,
}

#[derive(Clone)]
struct User {
    id: String,
}

#[async_trait::async_trait]
impl AuthProvider for JwtProvider {
    type Claims = JwtClaims;
    type User = User;

    async fn verify_token(&self, token: &str) -> Result<JwtClaims> {
        token
            .strip_prefix("jwt-")
            .map(|sub| JwtClaims { sub: sub.into() })
            .ok_or_else(|| tideway::TidewayError::unauthorized("bad jwt"))
    }

    async fn load_user(&self, claims: &JwtClaims) -> Result<User> {
        Ok(User {
            id: claims.sub.clone(),
        })
    }
}

async fn whoami(principal: Principal<JwtProvider>) -> Result<String> {
    Ok(match principal {
        Principal::User(user) => format!("user:{}", user.id),
        Principal::ApiKey(key) => {
            key.require_scope("projects:read")?;
            format!("org:{}", key.organization_id)
        }
    })
}

async fn machine_only(ApiKeyAuth(key): ApiKeyAuth) -> String {
    key.organization_id
}

fn app(manager: ApiKeyManager<InMemoryApiKeyStore>) -> Router {
    Router::new()
        .route("/whoami", get(whoami))
        .route("/machine", get(machine_only))
        .layer(Extension(ApiKeyExtension::new(manager)))
        .layer(Extension(JwtProvider))
}

async fn call(app: &Router, path: &str, header: Option<(&str, &str)>) -> (StatusCode, String) {
    let mut req = Request::builder().uri(path);
    if let Some((name, value)) = header {
        req = req.header(name, value);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn protected_routes_accept_api_keys_alongside_jwt() {
    let manager = ApiKeyManager::new(InMemoryApiKeyStore::new(), ApiKeyConfig::default());
    let created = manager
        .create(
            NewApiKey::new("org-42", "CI")
                .scopes(["projects:*"])
                .created_by("user-1"),
        )
        .await
        .unwrap();
    let key = created.plaintext.as_str();
    let bearer = format!("Bearer {key}");
    let app = app(manager.clone());

    // JWT users still work.
    assert_eq!(
        call(&app, "/whoami", Some(("authorization", "Bearer jwt-alice"))).await,
        (StatusCode::OK, "user:alice".into())
    );

    // API keys work via bearer and X-API-Key, and are bound to their organization.
    assert_eq!(
        call(&app, "/whoami", Some(("authorization", &bearer))).await,
        (StatusCode::OK, "org:org-42".into())
    );
    assert_eq!(
        call(&app, "/whoami", Some(("x-api-key", key))).await,
        (StatusCode::OK, "org:org-42".into())
    );
    assert_eq!(
        call(&app, "/machine", Some(("x-api-key", key))).await,
        (StatusCode::OK, "org-42".into())
    );

    // Usage is recorded.
    let stored = manager
        .get("org-42", &created.api_key.id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.last_used_at.is_some());

    // Unauthenticated, malformed, and JWT-on-API-key-only requests are rejected.
    assert_eq!(
        call(&app, "/whoami", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "/whoami", Some(("x-api-key", "tw_garbage")))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "/machine",
            Some(("authorization", "Bearer jwt-alice"))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );

    // Revoked keys stop working immediately.
    assert!(manager.revoke("org-42", &created.api_key.id).await.unwrap());
    assert_eq!(
        call(&app, "/whoami", Some(("authorization", &bearer)))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn api_key_without_required_scope_is_forbidden() {
    let manager = ApiKeyManager::new(InMemoryApiKeyStore::new(), ApiKeyConfig::default());
    let created = manager
        .create(NewApiKey::new("org-42", "billing bot").scopes(["billing:read"]))
        .await
        .unwrap();
    let app = app(manager);

    assert_eq!(
        call(&app, "/whoami", Some(("x-api-key", &created.plaintext)))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}
