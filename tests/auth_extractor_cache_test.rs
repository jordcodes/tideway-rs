#![cfg(feature = "auth")]

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::Request;
use serde::Deserialize;
use tideway::auth::{AdminUser, AuthProvider, AuthUser, OptionalAuth, RequireAdmin};
use tideway::Result;

#[derive(Clone, Default)]
struct TestProvider;

#[derive(Clone, Deserialize)]
struct TestClaims;

#[derive(Clone)]
struct TestUser {
    admin: bool,
}

impl AdminUser for TestUser {
    fn is_admin(&self) -> bool {
        self.admin
    }
}

#[async_trait::async_trait]
impl AuthProvider for TestProvider {
    type Claims = TestClaims;
    type User = TestUser;

    async fn verify_token(&self, _token: &str) -> Result<TestClaims> {
        panic!("verify_token should not be called when user is cached");
    }

    async fn load_user(&self, _claims: &TestClaims) -> Result<TestUser> {
        panic!("load_user should not be called when user is cached");
    }
}

#[tokio::test]
async fn auth_user_reuses_cached_user() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: false });

    let AuthUser(user) =
        AuthUser::<TestProvider>::from_request_parts(&mut parts, &()).await.unwrap();
    assert!(!user.admin);
}

#[tokio::test]
async fn optional_auth_reuses_cached_user() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: true });

    let OptionalAuth(user) =
        OptionalAuth::<TestProvider>::from_request_parts(&mut parts, &()).await.unwrap();
    assert!(user.is_some());
    assert!(user.unwrap().admin);
}

#[tokio::test]
async fn require_admin_reuses_cached_user() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: true });

    let RequireAdmin(user) =
        RequireAdmin::<TestProvider>::from_request_parts(&mut parts, &()).await.unwrap();
    assert!(user.admin);
}

#[tokio::test]
async fn require_admin_rejects_cached_non_admin() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: false });

    let result = RequireAdmin::<TestProvider>::from_request_parts(&mut parts, &()).await;
    assert!(result.is_err());
}
