#![cfg(feature = "auth")]

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::Request;
use serde::Deserialize;
use std::sync::Arc;
use tideway::Result;
use tideway::auth::{AdminUser, AuthProvider, AuthUser, ClaimsRef, OptionalAuth, RequireAdmin};

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

#[derive(Clone, Default)]
struct ClaimsProvider;

#[async_trait::async_trait]
impl AuthProvider for ClaimsProvider {
    type Claims = TestClaims;
    type User = TestUser;

    async fn verify_token(&self, _token: &str) -> Result<TestClaims> {
        Ok(TestClaims)
    }

    async fn load_user(&self, _claims: &TestClaims) -> Result<TestUser> {
        Ok(TestUser { admin: false })
    }
}

#[derive(Clone, Default)]
struct RejectingUserProvider;

#[async_trait::async_trait]
impl AuthProvider for RejectingUserProvider {
    type Claims = TestClaims;
    type User = TestUser;

    async fn verify_token(&self, _token: &str) -> Result<TestClaims> {
        Ok(TestClaims)
    }

    async fn load_user(&self, _claims: &TestClaims) -> Result<TestUser> {
        Ok(TestUser { admin: false })
    }

    async fn validate_user(&self, _user: &Self::User) -> Result<()> {
        Err(tideway::TidewayError::unauthorized("Invalid user"))
    }
}

#[tokio::test]
async fn auth_user_reuses_cached_user() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: false });

    let AuthUser(user) = AuthUser::<TestProvider>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert!(!user.admin);
}

#[tokio::test]
async fn optional_auth_reuses_cached_user() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: true });

    let OptionalAuth(user) = OptionalAuth::<TestProvider>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert!(user.is_some());
    assert!(user.unwrap().admin);
}

#[tokio::test]
async fn require_admin_reuses_cached_user() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(TestProvider::default());
    parts.extensions.insert(TestUser { admin: true });

    let RequireAdmin(user) = RequireAdmin::<TestProvider>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
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

#[tokio::test]
async fn claims_ref_reuses_cached_claims() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(ClaimsProvider::default());
    let cached = Arc::new(TestClaims);
    parts.extensions.insert(Arc::clone(&cached));

    let ClaimsRef(claims) = ClaimsRef::<ClaimsProvider>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&claims, &cached));
}

#[tokio::test]
async fn claims_ref_inserts_claims_when_missing() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(ClaimsProvider::default());
    parts
        .headers
        .insert("authorization", "Bearer test-token".parse().unwrap());

    let ClaimsRef(claims) = ClaimsRef::<ClaimsProvider>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    let cached = parts.extensions.get::<Arc<TestClaims>>().cloned().unwrap();
    assert!(Arc::ptr_eq(&claims, &cached));
}

#[tokio::test]
async fn optional_auth_does_not_cache_claims_on_validation_error() {
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let (mut parts, _) = request.into_parts();

    parts.extensions.insert(RejectingUserProvider::default());
    parts
        .headers
        .insert("authorization", "Bearer test-token".parse().unwrap());

    let OptionalAuth(user) =
        OptionalAuth::<RejectingUserProvider>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
    assert!(user.is_none());
    assert!(parts.extensions.get::<Arc<TestClaims>>().is_none());
}
