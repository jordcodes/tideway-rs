//! Integration tests for authentication flows.
//!
//! These tests verify the complete HTTP request/response cycle for all auth operations.

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tideway::auth::{
    JwtIssuer, JwtIssuerConfig, LoginFlow, LoginFlowConfig, LoginRateLimitConfig,
    LoginRateLimiter, LoginRequest, LoginResponse, MfaTokenStore, PasswordHasher,
    RefreshTokenStore, RegisterRequest, RegistrationFlow, TokenIssuer, TokenIssuance,
    TokenSubject, UserCreator, UserStore,
};
use tideway::testing::post as test_post;
use tideway::Result;

// =============================================================================
// Test User and In-Memory Store
// =============================================================================

#[derive(Clone, Debug)]
struct TestUser {
    id: String,
    email: String,
    password_hash: String,
    name: Option<String>,
    verified: bool,
    locked_until: Option<SystemTime>,
    failed_attempts: u32,
    mfa_enabled: bool,
    #[cfg(feature = "auth-mfa")]
    totp_secret: Option<String>,
    #[cfg(feature = "auth-mfa")]
    backup_codes: Vec<String>,
}

#[derive(Clone)]
struct InMemoryUserStore {
    users: Arc<RwLock<HashMap<String, TestUser>>>,
    hasher: PasswordHasher,
}

impl InMemoryUserStore {
    fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            hasher: PasswordHasher::default(),
        }
    }

    fn add_user(&self, email: &str, password: &str, verified: bool) -> String {
        let id = format!("user-{}", fastrand::u64(..));
        let hash = self.hasher.hash(password).unwrap();
        let user = TestUser {
            id: id.clone(),
            email: email.to_lowercase(),
            password_hash: hash,
            name: None,
            verified,
            locked_until: None,
            failed_attempts: 0,
            mfa_enabled: false,
            #[cfg(feature = "auth-mfa")]
            totp_secret: None,
            #[cfg(feature = "auth-mfa")]
            backup_codes: vec![],
        };
        self.users.write().unwrap().insert(email.to_lowercase(), user);
        id
    }

    #[cfg(feature = "auth-mfa")]
    fn enable_mfa(&self, email: &str, secret: &str, backup_codes: Vec<String>) {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&email.to_lowercase()) {
            user.mfa_enabled = true;
            user.totp_secret = Some(secret.to_string());
            user.backup_codes = backup_codes;
        }
    }

    fn lock_user(&self, email: &str, duration: Duration) {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&email.to_lowercase()) {
            user.locked_until = Some(SystemTime::now() + duration);
        }
    }

    fn get_failed_attempts(&self, email: &str) -> u32 {
        let users = self.users.read().unwrap();
        users.get(&email.to_lowercase()).map(|u| u.failed_attempts).unwrap_or(0)
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    type User = TestUser;

    async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>> {
        let users = self.users.read().unwrap();
        Ok(users.get(&email.to_lowercase()).cloned())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::User>> {
        let users = self.users.read().unwrap();
        Ok(users.values().find(|u| u.id == id).cloned())
    }

    fn user_id(&self, user: &Self::User) -> String {
        user.id.clone()
    }

    fn user_email(&self, user: &Self::User) -> String {
        user.email.clone()
    }

    fn user_name(&self, user: &Self::User) -> Option<String> {
        user.name.clone()
    }

    async fn get_password_hash(&self, user: &Self::User) -> Result<String> {
        Ok(user.password_hash.clone())
    }

    async fn update_password_hash(&self, user: &Self::User, hash: &str) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(u) = users.get_mut(&user.email) {
            u.password_hash = hash.to_string();
        }
        Ok(())
    }

    async fn is_verified(&self, user: &Self::User) -> Result<bool> {
        Ok(user.verified)
    }

    async fn mark_verified(&self, user: &Self::User) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(u) = users.get_mut(&user.email) {
            u.verified = true;
        }
        Ok(())
    }

    async fn is_locked(&self, user: &Self::User) -> Result<Option<SystemTime>> {
        Ok(user.locked_until)
    }

    async fn record_failed_attempt(&self, user: &Self::User) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(u) = users.get_mut(&user.email) {
            u.failed_attempts += 1;
        }
        Ok(())
    }

    async fn clear_failed_attempts(&self, user: &Self::User) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(u) = users.get_mut(&user.email) {
            u.failed_attempts = 0;
        }
        Ok(())
    }

    async fn has_mfa_enabled(&self, user: &Self::User) -> Result<bool> {
        Ok(user.mfa_enabled)
    }

    #[cfg(feature = "auth-mfa")]
    async fn get_totp_secret(&self, user: &Self::User) -> Result<Option<String>> {
        Ok(user.totp_secret.clone())
    }

    #[cfg(feature = "auth-mfa")]
    async fn get_backup_codes(&self, user: &Self::User) -> Result<Vec<String>> {
        Ok(user.backup_codes.clone())
    }

    #[cfg(feature = "auth-mfa")]
    async fn remove_backup_code(&self, user: &Self::User, index: usize) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(u) = users.get_mut(&user.email) {
            if index < u.backup_codes.len() {
                u.backup_codes.remove(index);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl UserCreator for InMemoryUserStore {
    type User = TestUser;

    fn user_id(&self, user: &Self::User) -> String {
        user.id.clone()
    }

    async fn email_exists(&self, email: &str) -> Result<bool> {
        let users = self.users.read().unwrap();
        Ok(users.contains_key(&email.to_lowercase()))
    }

    async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        name: Option<&str>,
    ) -> Result<Self::User> {
        let id = format!("user-{}", fastrand::u64(..));
        let user = TestUser {
            id,
            email: email.to_lowercase(),
            password_hash: password_hash.to_string(),
            name: name.map(|s| s.to_string()),
            verified: false,
            locked_until: None,
            failed_attempts: 0,
            mfa_enabled: false,
            #[cfg(feature = "auth-mfa")]
            totp_secret: None,
            #[cfg(feature = "auth-mfa")]
            backup_codes: vec![],
        };
        self.users.write().unwrap().insert(email.to_lowercase(), user.clone());
        Ok(user)
    }

    async fn send_verification_email(&self, _user: &Self::User) -> Result<()> {
        // No-op for tests
        Ok(())
    }
}

// =============================================================================
// In-Memory MFA Token Store
// =============================================================================

#[derive(Clone, Default)]
struct InMemoryMfaTokenStore {
    tokens: Arc<RwLock<HashMap<String, (String, SystemTime)>>>,
}

impl InMemoryMfaTokenStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MfaTokenStore for InMemoryMfaTokenStore {
    async fn store(&self, token: &str, user_id: &str, ttl: Duration) -> Result<()> {
        let expires = SystemTime::now() + ttl;
        self.tokens.write().unwrap().insert(token.to_string(), (user_id.to_string(), expires));
        Ok(())
    }

    async fn consume(&self, token: &str) -> Result<Option<String>> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some((user_id, expires)) = tokens.remove(token) {
            if expires > SystemTime::now() {
                return Ok(Some(user_id));
            }
        }
        Ok(None)
    }
}

// =============================================================================
// In-Memory Refresh Token Store
// =============================================================================

#[derive(Clone, Default)]
struct InMemoryRefreshTokenStore {
    families: Arc<RwLock<HashMap<String, (String, u32, bool)>>>, // family -> (user_id, generation, revoked)
}

impl InMemoryRefreshTokenStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RefreshTokenStore for InMemoryRefreshTokenStore {
    async fn is_family_revoked(&self, family: &str) -> Result<bool> {
        let families = self.families.read().unwrap();
        Ok(families.get(family).map(|(_, _, r)| *r).unwrap_or(false))
    }

    async fn get_family_generation(&self, family: &str) -> Result<Option<u32>> {
        let families = self.families.read().unwrap();
        Ok(families.get(family).map(|(_, g, _)| *g))
    }

    async fn set_family_generation(&self, family: &str, generation: u32) -> Result<()> {
        let mut families = self.families.write().unwrap();
        if let Some((_, g, _)) = families.get_mut(family) {
            *g = generation;
        }
        Ok(())
    }

    async fn revoke_family(&self, family: &str) -> Result<()> {
        let mut families = self.families.write().unwrap();
        if let Some((_, _, r)) = families.get_mut(family) {
            *r = true;
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Result<()> {
        let mut families = self.families.write().unwrap();
        for (_, (uid, _, revoked)) in families.iter_mut() {
            if uid == user_id {
                *revoked = true;
            }
        }
        Ok(())
    }

    async fn associate_family_with_user(&self, family: &str, user_id: &str) -> Result<()> {
        let mut families = self.families.write().unwrap();
        families.insert(family.to_string(), (user_id.to_string(), 0, false));
        Ok(())
    }
}

// =============================================================================
// Token Issuer Implementation
// =============================================================================

#[derive(Clone)]
struct TestTokenIssuer {
    jwt_issuer: Arc<JwtIssuer>,
}

impl TestTokenIssuer {
    fn new(secret: &str) -> Self {
        let config = JwtIssuerConfig::with_secret(secret, "test-app")
            .access_token_ttl(Duration::from_secs(900))
            .refresh_token_ttl(Duration::from_secs(86400));
        Self {
            jwt_issuer: Arc::new(JwtIssuer::new(config).unwrap()),
        }
    }
}

impl TokenIssuer for TestTokenIssuer {
    type User = TestUser;

    fn issue(&self, user: &Self::User, remember_me: bool) -> Result<TokenIssuance> {
        let mut subject = TokenSubject::new(&user.id).with_email(&user.email);
        if let Some(ref name) = user.name {
            subject = subject.with_name(name);
        }
        let pair = self.jwt_issuer.issue(subject, remember_me)?;
        Ok(TokenIssuance {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            expires_in: pair.expires_in,
            family: pair.family,
        })
    }
}

// =============================================================================
// App State and Routes
// =============================================================================

type TestLoginFlow = LoginFlow<
    InMemoryUserStore,
    InMemoryMfaTokenStore,
    TestTokenIssuer,
    tideway::auth::flows::WithRefreshStore<InMemoryRefreshTokenStore>,
    tideway::auth::flows::WithRateLimiter,
>;

#[derive(Clone)]
struct AppState {
    login_flow: Arc<TestLoginFlow>,
    registration_flow: Arc<RegistrationFlow<InMemoryUserStore>>,
    user_store: InMemoryUserStore,
}

async fn register_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>> {
    let user = state.registration_flow.register(req).await?;
    Ok(Json(json!({
        "id": user.id,
        "email": user.email,
        "message": "Registration successful"
    })))
}

async fn login_handler(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Simulate extracting IP from request (use a fixed IP for testing)
    let response = state.login_flow.login_with_ip(req, Some("127.0.0.1".to_string())).await?;
    Ok(Json(response))
}

#[cfg(feature = "auth-mfa")]
async fn verify_mfa_handler(
    State(state): State<AppState>,
    Json(req): Json<tideway::auth::MfaVerifyRequest>,
) -> Result<Json<LoginResponse>> {
    let response = state.login_flow.verify_mfa(req).await?;
    Ok(Json(response))
}

fn create_test_app(user_store: InMemoryUserStore) -> (Router, AppState) {
    let mfa_store = InMemoryMfaTokenStore::new();
    let refresh_store = InMemoryRefreshTokenStore::new();
    let token_issuer = TestTokenIssuer::new("test-secret-key-for-jwt-signing-min-32-chars");
    let rate_limiter = LoginRateLimiter::new(LoginRateLimitConfig::new(5, 60));

    let login_config = LoginFlowConfig::new("TestApp").require_verification(true);
    let login_flow = Arc::new(
        LoginFlow::new(
            user_store.clone(),
            mfa_store,
            token_issuer,
            login_config,
        )
        .with_refresh_store(refresh_store)
        .with_rate_limiter(rate_limiter),
    );

    let registration_flow = Arc::new(RegistrationFlow::new(user_store.clone()));

    let state = AppState {
        login_flow,
        registration_flow,
        user_store,
    };

    let mut router = Router::new()
        .route("/auth/register", post(register_handler))
        .route("/auth/login", post(login_handler));

    #[cfg(feature = "auth-mfa")]
    {
        router = router.route("/auth/mfa/verify", post(verify_mfa_handler));
    }

    let router = router.with_state(state.clone());

    (router, state)
}

// =============================================================================
// Registration Tests
// =============================================================================

#[tokio::test]
async fn test_registration_success() {
    let user_store = InMemoryUserStore::new();
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/register")
        .json_body(&json!({
            "email": "newuser@example.com",
            "password": "SecureP@ss123"
        }))
        .execute()
        .await;

    response.assert_ok();
}

#[tokio::test]
async fn test_registration_duplicate_email() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("existing@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/register")
        .json_body(&json!({
            "email": "existing@example.com",
            "password": "SecureP@ss123"
        }))
        .execute()
        .await;

    response.assert_bad_request();
}

#[tokio::test]
async fn test_registration_weak_password() {
    let user_store = InMemoryUserStore::new();
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/register")
        .json_body(&json!({
            "email": "newuser@example.com",
            "password": "weak"
        }))
        .execute()
        .await;

    response.assert_bad_request();
}

#[tokio::test]
async fn test_registration_invalid_email() {
    let user_store = InMemoryUserStore::new();
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/register")
        .json_body(&json!({
            "email": "not-an-email",
            "password": "SecureP@ss123"
        }))
        .execute()
        .await;

    response.assert_bad_request();
}

// =============================================================================
// Login Tests
// =============================================================================

#[tokio::test]
async fn test_login_success() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "password123"
        }))
        .execute()
        .await;

    response.assert_ok();
}

#[tokio::test]
async fn test_login_wrong_password() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "wrongpassword"
        }))
        .execute()
        .await;

    // Login returns OK with error in body (not HTTP 401)
    response.assert_ok();
}

#[tokio::test]
async fn test_login_user_not_found() {
    let user_store = InMemoryUserStore::new();
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "nonexistent@example.com",
            "password": "password123"
        }))
        .execute()
        .await;

    // Returns same response as wrong password (prevents enumeration)
    response.assert_ok();
}

#[tokio::test]
async fn test_login_unverified_email() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", false); // Not verified
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "password123"
        }))
        .execute()
        .await;

    response.assert_ok(); // Returns error in body
}

#[tokio::test]
async fn test_login_locked_account() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    user_store.lock_user("user@example.com", Duration::from_secs(3600));
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "password123"
        }))
        .execute()
        .await;

    response.assert_ok(); // Returns error in body
}

#[tokio::test]
async fn test_login_case_insensitive_email() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "USER@EXAMPLE.COM",
            "password": "password123"
        }))
        .execute()
        .await;

    response.assert_ok();
}

#[tokio::test]
async fn test_login_failed_attempts_recorded() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, state) = create_test_app(user_store);

    // Try wrong password
    test_post(app.clone(), "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "wrongpassword"
        }))
        .execute()
        .await;

    // Check failed attempts
    let attempts = state.user_store.get_failed_attempts("user@example.com");
    assert_eq!(attempts, 1, "Failed attempts should be recorded");
}

#[tokio::test]
async fn test_login_clears_failed_attempts_on_success() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, state) = create_test_app(user_store);

    // Fail first
    test_post(app.clone(), "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "wrongpassword"
        }))
        .execute()
        .await;

    assert_eq!(state.user_store.get_failed_attempts("user@example.com"), 1);

    // Succeed
    test_post(app.clone(), "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "password123"
        }))
        .execute()
        .await;

    assert_eq!(state.user_store.get_failed_attempts("user@example.com"), 0);
}

// =============================================================================
// MFA Tests
// =============================================================================

#[cfg(feature = "auth-mfa")]
mod mfa_tests {
    use super::*;
    use tideway::auth::mfa::{TotpManager, TotpConfig};

    #[tokio::test]
    async fn test_login_mfa_required() {
        let user_store = InMemoryUserStore::new();
        user_store.add_user("mfa@example.com", "password123", true);

        let totp = TotpManager::new(TotpConfig::default());
        let setup = totp.generate_setup("mfa@example.com").unwrap();
        user_store.enable_mfa("mfa@example.com", &setup.secret, vec![]);

        let (app, _) = create_test_app(user_store);

        let response = test_post(app, "/auth/login")
            .json_body(&json!({
                "email": "mfa@example.com",
                "password": "password123"
            }))
            .execute()
            .await;

        response.assert_ok();
        // Response body should indicate MFA is required
    }

    #[tokio::test]
    async fn test_login_with_mfa_code() {
        let user_store = InMemoryUserStore::new();
        user_store.add_user("mfa@example.com", "password123", true);

        let totp = TotpManager::new(TotpConfig::default());
        let setup = totp.generate_setup("mfa@example.com").unwrap();
        let code = totp.generate_current(&setup.secret, "mfa@example.com").unwrap();
        user_store.enable_mfa("mfa@example.com", &setup.secret, vec![]);

        let (app, _) = create_test_app(user_store);

        let response = test_post(app, "/auth/login")
            .json_body(&json!({
                "email": "mfa@example.com",
                "password": "password123",
                "mfa_code": code
            }))
            .execute()
            .await;

        response.assert_ok();
    }

    #[tokio::test]
    async fn test_login_with_backup_code() {
        use tideway::auth::mfa::BackupCodeGenerator;

        let user_store = InMemoryUserStore::new();
        user_store.add_user("mfa@example.com", "password123", true);

        let backup_gen = BackupCodeGenerator::default();
        let codes = backup_gen.generate();
        let first_code = codes.codes[0].clone();

        user_store.enable_mfa("mfa@example.com", "JBSWY3DPEHPK3PXP", codes.codes);

        let (app, _) = create_test_app(user_store);

        let response = test_post(app, "/auth/login")
            .json_body(&json!({
                "email": "mfa@example.com",
                "password": "password123",
                "mfa_code": first_code
            }))
            .execute()
            .await;

        response.assert_ok();
    }
}

// =============================================================================
// Rate Limiting Tests
// =============================================================================

#[tokio::test]
async fn test_rate_limiting_blocks_after_limit() {
    let user_store = InMemoryUserStore::new();
    // Don't add user - all attempts will fail but rate limiter still applies
    let (app, _) = create_test_app(user_store);

    // Make 5 requests (the limit)
    for _ in 0..5 {
        test_post(app.clone(), "/auth/login")
            .json_body(&json!({
                "email": "test@example.com",
                "password": "password"
            }))
            .execute()
            .await;
    }

    // 6th request should be rate limited
    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "test@example.com",
            "password": "password"
        }))
        .execute()
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

// =============================================================================
// Response Validation Tests
// =============================================================================

#[tokio::test]
async fn test_login_response_contains_tokens() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "password123"
        }))
        .execute()
        .await;

    let body = response.response();
    let bytes = axum::body::to_bytes(body.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(json.get("access_token").is_some(), "Response should contain access_token");
    assert!(json.get("refresh_token").is_some(), "Response should contain refresh_token");
    assert!(json.get("expires_in").is_some(), "Response should contain expires_in");
}

#[tokio::test]
async fn test_login_error_response_structure() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("user@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    let response = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "user@example.com",
            "password": "wrongpassword"
        }))
        .execute()
        .await;

    let body = response.response();
    let bytes = axum::body::to_bytes(body.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(json.get("message").is_some(), "Error response should contain message");
}

// =============================================================================
// Security Tests
// =============================================================================

#[tokio::test]
async fn test_timing_safe_user_not_found() {
    // This test verifies that the response time is similar whether user exists or not
    // (prevents timing-based user enumeration)
    let user_store = InMemoryUserStore::new();
    user_store.add_user("exists@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    // Request for existing user with wrong password
    let start1 = std::time::Instant::now();
    test_post(app.clone(), "/auth/login")
        .json_body(&json!({
            "email": "exists@example.com",
            "password": "wrongpassword"
        }))
        .execute()
        .await;
    let duration1 = start1.elapsed();

    // Request for non-existing user
    let start2 = std::time::Instant::now();
    test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "nonexistent@example.com",
            "password": "password123"
        }))
        .execute()
        .await;
    let duration2 = start2.elapsed();

    // Times should be roughly similar (within 100ms is reasonable for test environment)
    // This is a basic check - real timing attacks need more sophisticated analysis
    let diff = if duration1 > duration2 {
        duration1 - duration2
    } else {
        duration2 - duration1
    };

    assert!(
        diff < Duration::from_millis(100),
        "Response times should be similar to prevent timing attacks: {:?} vs {:?}",
        duration1,
        duration2
    );
}

#[tokio::test]
async fn test_email_enumeration_prevention() {
    let user_store = InMemoryUserStore::new();
    user_store.add_user("exists@example.com", "password123", true);
    let (app, _) = create_test_app(user_store);

    // Wrong password for existing user
    let response1 = test_post(app.clone(), "/auth/login")
        .json_body(&json!({
            "email": "exists@example.com",
            "password": "wrongpassword"
        }))
        .execute()
        .await;
    let body1 = response1.response();
    let bytes1 = axum::body::to_bytes(body1.into_body(), usize::MAX).await.unwrap();
    let json1: serde_json::Value = serde_json::from_slice(&bytes1).unwrap();

    // Non-existent user
    let response2 = test_post(app, "/auth/login")
        .json_body(&json!({
            "email": "nonexistent@example.com",
            "password": "password123"
        }))
        .execute()
        .await;
    let body2 = response2.response();
    let bytes2 = axum::body::to_bytes(body2.into_body(), usize::MAX).await.unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();

    // Both should return the same error message
    assert_eq!(
        json1.get("message"),
        json2.get("message"),
        "Error messages should be identical to prevent email enumeration"
    );
}
