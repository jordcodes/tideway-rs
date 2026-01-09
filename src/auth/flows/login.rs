//! Login flow with MFA support.
//!
//! This module emits tracing events for security monitoring. Events include:
//! - `auth.login.failed` - Failed login attempts (user not found, wrong password)
//! - `auth.login.locked` - Login blocked due to account lockout
//! - `auth.login.unverified` - Login blocked due to unverified email
//! - `auth.login.success` - Successful login
//! - `auth.login.mfa_required` - MFA challenge issued
//! - `auth.login.rate_limited` - Login blocked due to IP rate limiting
//! - `auth.mfa.failed` - Failed MFA verification
//! - `auth.mfa.backup_used` - Backup code consumed
//! - `auth.password.rehashed` - Password hash upgraded

use crate::auth::password::{PasswordConfig, PasswordHasher};
use crate::auth::storage::token::{MfaTokenStore, RefreshTokenStore};
use crate::auth::storage::UserStore;
use crate::error::{Result, TidewayError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::time::{Duration, SystemTime};

use super::rate_limit::{LoginRateLimiter, OptionalRateLimiter, WithRateLimiter};
use super::types::{LoginRequest, LoginResponse, MfaVerifyRequest};

#[cfg(feature = "auth-mfa")]
use crate::auth::mfa::{BackupCodeGenerator, TotpConfig, TotpManager};

/// Configuration for the login flow.
#[derive(Clone)]
pub struct LoginFlowConfig {
    /// App name for TOTP.
    pub app_name: String,
    /// How long MFA tokens are valid.
    pub mfa_token_ttl: Duration,
    /// Whether to require email verification before login.
    pub require_verification: bool,
    /// Password hasher config.
    pub password_config: PasswordConfig,
    #[cfg(feature = "auth-mfa")]
    /// TOTP config.
    pub totp_config: TotpConfig,
}

impl Default for LoginFlowConfig {
    fn default() -> Self {
        Self {
            app_name: "App".to_string(),
            mfa_token_ttl: Duration::from_secs(300), // 5 minutes
            require_verification: true,
            password_config: PasswordConfig::default(),
            #[cfg(feature = "auth-mfa")]
            totp_config: TotpConfig::default(),
        }
    }
}

impl LoginFlowConfig {
    /// Create a new login flow config with the given app name.
    pub fn new(app_name: impl Into<String>) -> Self {
        let app_name = app_name.into();
        Self {
            #[cfg(feature = "auth-mfa")]
            totp_config: TotpConfig::new(&app_name),
            app_name,
            ..Default::default()
        }
    }

    /// Set whether email verification is required.
    pub fn require_verification(mut self, required: bool) -> Self {
        self.require_verification = required;
        self
    }

    /// Set the MFA token TTL.
    pub fn mfa_token_ttl(mut self, ttl: Duration) -> Self {
        self.mfa_token_ttl = ttl;
        self
    }
}

/// Result of token issuance.
#[derive(Debug, Clone)]
pub struct TokenIssuance {
    /// Access token (short-lived)
    pub access_token: String,
    /// Refresh token (long-lived)
    pub refresh_token: String,
    /// Access token expiry in seconds
    pub expires_in: u64,
    /// Token family ID (for refresh token rotation tracking)
    pub family: String,
}

/// Trait for issuing tokens after successful authentication.
pub trait TokenIssuer: Send + Sync {
    /// The user type.
    type User;

    /// Issue tokens for a user.
    fn issue(&self, user: &Self::User, remember_me: bool) -> Result<TokenIssuance>;
}

/// Handles the login flow including MFA.
pub struct LoginFlow<U, M, T, R = (), L = ()>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
    R: OptionalRefreshTokenStore,
    L: OptionalRateLimiter,
{
    user_store: U,
    mfa_store: M,
    token_issuer: T,
    refresh_store: R,
    rate_limiter: L,
    password_hasher: PasswordHasher,
    #[cfg(feature = "auth-mfa")]
    totp_manager: TotpManager,
    config: LoginFlowConfig,
}

/// Helper trait to make RefreshTokenStore optional.
pub trait OptionalRefreshTokenStore: Send + Sync {
    /// Store the token family association (no-op if not configured).
    fn associate_family_with_user(
        &self,
        family: &str,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// No-op implementation for when no refresh token store is configured.
impl OptionalRefreshTokenStore for () {
    async fn associate_family_with_user(&self, _family: &str, _user_id: &str) -> Result<()> {
        Ok(())
    }
}

/// Wrapper to use a real RefreshTokenStore.
pub struct WithRefreshStore<S: RefreshTokenStore>(pub S);

impl<S: RefreshTokenStore> OptionalRefreshTokenStore for WithRefreshStore<S> {
    async fn associate_family_with_user(&self, family: &str, user_id: &str) -> Result<()> {
        self.0.associate_family_with_user(family, user_id).await
    }
}

impl<U, M, T> LoginFlow<U, M, T, (), ()>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
{
    /// Create a new login flow without refresh token store or rate limiter.
    /// Token families will not be stored (refresh token rotation tracking disabled).
    pub fn new(user_store: U, mfa_store: M, token_issuer: T, config: LoginFlowConfig) -> Self {
        Self {
            user_store,
            password_hasher: PasswordHasher::new(config.password_config.clone()),
            #[cfg(feature = "auth-mfa")]
            totp_manager: TotpManager::new(config.totp_config.clone()),
            mfa_store,
            token_issuer,
            refresh_store: (),
            rate_limiter: (),
            config,
        }
    }
}

impl<U, M, T, L> LoginFlow<U, M, T, (), L>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
    L: OptionalRateLimiter,
{
    /// Add a refresh token store for token family tracking.
    /// This enables refresh token rotation and revocation.
    pub fn with_refresh_store<R: RefreshTokenStore>(
        self,
        refresh_store: R,
    ) -> LoginFlow<U, M, T, WithRefreshStore<R>, L> {
        LoginFlow {
            user_store: self.user_store,
            mfa_store: self.mfa_store,
            token_issuer: self.token_issuer,
            refresh_store: WithRefreshStore(refresh_store),
            rate_limiter: self.rate_limiter,
            password_hasher: self.password_hasher,
            #[cfg(feature = "auth-mfa")]
            totp_manager: self.totp_manager,
            config: self.config,
        }
    }
}

impl<U, M, T, R> LoginFlow<U, M, T, R, ()>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
    R: OptionalRefreshTokenStore,
{
    /// Add an IP-based rate limiter for brute force protection.
    ///
    /// The rate limiter is checked before any authentication logic runs,
    /// preventing brute force attacks at the IP level.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tideway::auth::flows::{LoginFlow, LoginRateLimiter, LoginRateLimitConfig};
    ///
    /// let rate_limiter = LoginRateLimiter::new(LoginRateLimitConfig::default());
    ///
    /// let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config)
    ///     .with_rate_limiter(rate_limiter);
    /// ```
    pub fn with_rate_limiter(
        self,
        rate_limiter: LoginRateLimiter,
    ) -> LoginFlow<U, M, T, R, WithRateLimiter> {
        LoginFlow {
            user_store: self.user_store,
            mfa_store: self.mfa_store,
            token_issuer: self.token_issuer,
            refresh_store: self.refresh_store,
            rate_limiter: WithRateLimiter(rate_limiter),
            password_hasher: self.password_hasher,
            #[cfg(feature = "auth-mfa")]
            totp_manager: self.totp_manager,
            config: self.config,
        }
    }
}

impl<U, M, T, R, L> LoginFlow<U, M, T, R, L>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
    R: OptionalRefreshTokenStore,
    L: OptionalRateLimiter,
{
    /// Primary login endpoint - handles email/password and optional MFA.
    ///
    /// This method does not perform IP-based rate limiting. Use [`login_with_ip`]
    /// if you have configured a rate limiter.
    #[cfg(feature = "auth")]
    pub async fn login(&self, req: LoginRequest) -> Result<LoginResponse> {
        self.login_with_ip(req, None).await
    }

    /// Primary login endpoint with IP-based rate limiting.
    ///
    /// Pass the client's IP address to enable rate limiting protection
    /// against brute force attacks.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use axum::extract::ConnectInfo;
    /// use std::net::SocketAddr;
    ///
    /// async fn login_handler(
    ///     ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ///     State(flow): State<LoginFlow<...>>,
    ///     Json(req): Json<LoginRequest>,
    /// ) -> Result<Json<LoginResponse>> {
    ///     let response = flow.login_with_ip(req, Some(addr.ip().to_string())).await?;
    ///     Ok(Json(response))
    /// }
    /// ```
    #[cfg(feature = "auth")]
    pub async fn login_with_ip(
        &self,
        req: LoginRequest,
        client_ip: Option<String>,
    ) -> Result<LoginResponse> {
        // Check rate limit first (before any auth logic)
        self.rate_limiter.check_rate_limit(client_ip.as_deref())?;
        // Normalize email
        let email = req.email.trim().to_lowercase();

        // Find user
        let user = match self.user_store.find_by_email(&email).await? {
            Some(u) => u,
            None => {
                // Timing-safe: hash anyway to prevent enumeration
                let _ = self.password_hasher.hash("dummy");
                tracing::warn!(
                    target: "auth.login.failed",
                    email = %email,
                    reason = "user_not_found",
                    "Login failed: user not found"
                );
                return Ok(LoginResponse::error("Invalid credentials"));
            }
        };

        let user_id = self.user_store.user_id(&user);

        // Check if locked
        if let Some(until) = self.user_store.is_locked(&user).await? {
            if until > SystemTime::now() {
                tracing::warn!(
                    target: "auth.login.locked",
                    user_id = %user_id,
                    email = %email,
                    locked_until = ?until,
                    "Login blocked: account locked"
                );
                return Ok(LoginResponse::error(
                    "Account temporarily locked. Try again later.",
                ));
            }
        }

        // Check if verified (if required)
        if self.config.require_verification && !self.user_store.is_verified(&user).await? {
            tracing::info!(
                target: "auth.login.unverified",
                user_id = %user_id,
                email = %email,
                "Login blocked: email not verified"
            );
            return Ok(LoginResponse::error(
                "Please verify your email before logging in.",
            ));
        }

        // Verify password
        let hash = self.user_store.get_password_hash(&user).await?;
        if !self.password_hasher.verify(&req.password, &hash)? {
            self.user_store.record_failed_attempt(&user).await?;
            tracing::warn!(
                target: "auth.login.failed",
                user_id = %user_id,
                email = %email,
                reason = "invalid_password",
                "Login failed: invalid password"
            );
            return Ok(LoginResponse::error("Invalid credentials"));
        }

        // Rehash if needed (transparent upgrade)
        if self.password_hasher.needs_rehash(&hash)? {
            let new_hash = self.password_hasher.hash(&req.password)?;
            self.user_store.update_password_hash(&user, &new_hash).await?;
            tracing::info!(
                target: "auth.password.rehashed",
                user_id = %user_id,
                "Password hash upgraded to current algorithm"
            );
        }

        // Check MFA
        let mfa_enabled = self.user_store.has_mfa_enabled(&user).await?;

        if mfa_enabled {
            #[cfg(feature = "auth-mfa")]
            {
                // If MFA code provided, verify it
                if let Some(code) = req.mfa_code {
                    return self
                        .verify_mfa_code(&user, &code, req.remember_me)
                        .await;
                }

                // Otherwise, return MFA challenge
                let backup_remaining = self.user_store.get_backup_codes(&user).await?.len();
                let mfa_token = self.generate_mfa_token(&user).await?;

                tracing::info!(
                    target: "auth.login.mfa_required",
                    user_id = %user_id,
                    email = %email,
                    backup_codes_remaining = backup_remaining,
                    "MFA challenge issued"
                );

                return Ok(LoginResponse::mfa_required(mfa_token, Some(backup_remaining)));
            }

            #[cfg(not(feature = "auth-mfa"))]
            {
                return Ok(LoginResponse::error("MFA enabled but not supported"));
            }
        }

        // No MFA, issue tokens
        self.complete_login(&user, req.remember_me).await
    }

    /// Primary login endpoint stub when auth feature is disabled.
    #[cfg(not(feature = "auth"))]
    pub async fn login(&self, _req: LoginRequest) -> Result<LoginResponse> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }

    /// Second step: verify MFA code with MFA token.
    pub async fn verify_mfa(&self, req: MfaVerifyRequest) -> Result<LoginResponse> {
        // Consume MFA token (one-time use)
        let user_id = self
            .mfa_store
            .consume(&req.mfa_token)
            .await?
            .ok_or_else(|| TidewayError::Unauthorized("Invalid or expired MFA token".into()))?;

        // Load user
        let user = self
            .user_store
            .find_by_id(&user_id)
            .await?
            .ok_or_else(|| TidewayError::Unauthorized("User not found".into()))?;

        #[cfg(feature = "auth-mfa")]
        {
            self.verify_mfa_code(&user, &req.code, false).await
        }

        #[cfg(not(feature = "auth-mfa"))]
        {
            let _ = user;
            Ok(LoginResponse::error("MFA not supported"))
        }
    }

    #[cfg(feature = "auth-mfa")]
    async fn verify_mfa_code(
        &self,
        user: &U::User,
        code: &str,
        remember_me: bool,
    ) -> Result<LoginResponse> {
        let code = code.trim();
        let user_id = self.user_store.user_id(user);
        let email = self.user_store.user_email(user);

        // Try TOTP first (6 digits)
        if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
            if let Some(secret) = self.user_store.get_totp_secret(user).await? {
                if self.totp_manager.verify(&secret, code, &email)? {
                    tracing::info!(
                        target: "auth.mfa.success",
                        user_id = %user_id,
                        method = "totp",
                        "MFA verification successful"
                    );
                    return self.complete_login(user, remember_me).await;
                }
            }
        }

        // Try backup code (typically 8+ chars alphanumeric)
        let backup_codes = self.user_store.get_backup_codes(user).await?;
        if let Some(index) = BackupCodeGenerator::verify(code, &backup_codes) {
            self.user_store.remove_backup_code(user, index).await?;
            let remaining = backup_codes.len() - 1;
            tracing::info!(
                target: "auth.mfa.backup_used",
                user_id = %user_id,
                backup_codes_remaining = remaining,
                "Backup code consumed"
            );
            if remaining <= 2 {
                tracing::warn!(
                    target: "auth.mfa.backup_low",
                    user_id = %user_id,
                    backup_codes_remaining = remaining,
                    "Low backup codes remaining"
                );
            }
            return self.complete_login(user, remember_me).await;
        }

        // Invalid code - use MFA-specific rate limiting
        self.user_store.record_failed_mfa_attempt(user).await?;
        tracing::warn!(
            target: "auth.mfa.failed",
            user_id = %user_id,
            "MFA verification failed: invalid code"
        );
        Ok(LoginResponse::error("Invalid MFA code"))
    }

    async fn complete_login(&self, user: &U::User, remember_me: bool) -> Result<LoginResponse> {
        // Clear failed attempts
        self.user_store.clear_failed_attempts(user).await?;

        // Issue tokens
        let issuance = self.token_issuer.issue(user, remember_me)?;

        // Store token family for refresh token rotation tracking
        let user_id = self.user_store.user_id(user);
        let email = self.user_store.user_email(user);
        self.refresh_store
            .associate_family_with_user(&issuance.family, &user_id)
            .await?;

        tracing::info!(
            target: "auth.login.success",
            user_id = %user_id,
            email = %email,
            remember_me = remember_me,
            token_family = %issuance.family,
            "Login successful"
        );

        Ok(LoginResponse::success(
            issuance.access_token,
            issuance.refresh_token,
            issuance.expires_in,
        ))
    }

    async fn generate_mfa_token(&self, user: &U::User) -> Result<String> {
        let token = generate_secure_token();
        let user_id = self.user_store.user_id(user);

        self.mfa_store
            .store(&token, &user_id, self.config.mfa_token_ttl)
            .await?;

        Ok(token)
    }
}

/// Generate a secure random token.
fn generate_secure_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use crate::auth::password::PasswordHasher;
    use crate::auth::storage::token::test::{InMemoryMfaTokenStore, InMemoryRefreshTokenStore};
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[derive(Clone)]
    struct TestUser {
        id: String,
        email: String,
        password_hash: String,
        verified: bool,
        locked_until: Option<SystemTime>,
        failed_attempts: u32,
        mfa_enabled: bool,
        #[cfg(feature = "auth-mfa")]
        totp_secret: Option<String>,
        #[cfg(feature = "auth-mfa")]
        backup_codes: Vec<String>,
    }

    struct TestUserStore {
        users: RwLock<HashMap<String, TestUser>>,
    }

    impl TestUserStore {
        fn new() -> Self {
            Self {
                users: RwLock::new(HashMap::new()),
            }
        }

        fn add_user(&self, user: TestUser) {
            let mut users = self.users.write().unwrap();
            users.insert(user.email.clone(), user);
        }
    }

    #[async_trait]
    impl UserStore for TestUserStore {
        type User = TestUser;

        async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>> {
            let users = self.users.read().unwrap();
            Ok(users.get(email).cloned())
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

    struct TestTokenIssuer;

    impl TokenIssuer for TestTokenIssuer {
        type User = TestUser;

        fn issue(&self, user: &Self::User, _remember_me: bool) -> Result<TokenIssuance> {
            Ok(TokenIssuance {
                access_token: format!("access-{}", user.id),
                refresh_token: format!("refresh-{}", user.id),
                expires_in: 3600,
                family: format!("family-{}", user.id),
            })
        }
    }

    fn create_test_user(email: &str, password: &str, verified: bool) -> TestUser {
        let hasher = PasswordHasher::default();
        let hash = hasher.hash(password).unwrap();
        TestUser {
            id: format!("user-{}", email.split('@').next().unwrap()),
            email: email.to_string(),
            password_hash: hash,
            verified,
            locked_until: None,
            failed_attempts: 0,
            mfa_enabled: false,
            #[cfg(feature = "auth-mfa")]
            totp_secret: None,
            #[cfg(feature = "auth-mfa")]
            backup_codes: vec![],
        }
    }

    fn is_success(response: &LoginResponse) -> bool {
        matches!(response, LoginResponse::Success { .. })
    }

    fn is_error(response: &LoginResponse) -> bool {
        matches!(response, LoginResponse::Error { .. })
    }

    fn is_mfa_required(response: &LoginResponse) -> bool {
        matches!(response, LoginResponse::MfaRequired { .. })
    }

    fn get_error_message(response: &LoginResponse) -> Option<String> {
        match response {
            LoginResponse::Error { message } => Some(message.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "auth-mfa")]
    fn get_mfa_token(response: &LoginResponse) -> Option<String> {
        match response {
            LoginResponse::MfaRequired { mfa_token, .. } => Some(mfa_token.clone()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn test_successful_login() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", true));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp").require_verification(true);

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[tokio::test]
    async fn test_login_wrong_password() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", true));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp").require_verification(true);

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "wrongpassword".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_error(&response));
        assert!(get_error_message(&response).unwrap().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        let user_store = TestUserStore::new();
        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "nonexistent@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_error(&response));
        assert!(get_error_message(&response).unwrap().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn test_login_unverified_email() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", false));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp").require_verification(true);

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_error(&response));
        assert!(get_error_message(&response).unwrap().contains("verify your email"));
    }

    #[tokio::test]
    async fn test_login_verification_not_required() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", false));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp").require_verification(false);

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[tokio::test]
    async fn test_login_locked_account() {
        let user_store = TestUserStore::new();
        let mut user = create_test_user("test@example.com", "password123", true);
        user.locked_until = Some(SystemTime::now() + Duration::from_secs(3600));
        user_store.add_user(user);

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_error(&response));
        assert!(get_error_message(&response).unwrap().contains("locked"));
    }

    #[tokio::test]
    async fn test_login_email_case_insensitive() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", true));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp").require_verification(true);

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "TEST@EXAMPLE.COM".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[tokio::test]
    async fn test_login_with_refresh_store() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", true));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let refresh_store = InMemoryRefreshTokenStore::new();
        let config = LoginFlowConfig::new("TestApp").require_verification(true);

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config)
            .with_refresh_store(refresh_store);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[cfg(feature = "auth-mfa")]
    #[tokio::test]
    async fn test_login_mfa_required() {
        use crate::auth::mfa::{TotpManager, TotpConfig};

        let user_store = TestUserStore::new();
        let totp = TotpManager::new(TotpConfig::default());
        let setup = totp.generate_setup("test@example.com").unwrap();

        let mut user = create_test_user("test@example.com", "password123", true);
        user.mfa_enabled = true;
        user.totp_secret = Some(setup.secret.clone());
        user_store.add_user(user);

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_mfa_required(&response));
        assert!(get_mfa_token(&response).is_some());
    }

    #[cfg(feature = "auth-mfa")]
    #[tokio::test]
    async fn test_login_with_mfa_code() {
        use crate::auth::mfa::{TotpManager, TotpConfig};

        let user_store = TestUserStore::new();
        let totp = TotpManager::new(TotpConfig::default());
        let setup = totp.generate_setup("test@example.com").unwrap();
        let code = totp.generate_current(&setup.secret, "test@example.com").unwrap();

        let mut user = create_test_user("test@example.com", "password123", true);
        user.mfa_enabled = true;
        user.totp_secret = Some(setup.secret.clone());
        user_store.add_user(user);

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: Some(code),
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[cfg(feature = "auth-mfa")]
    #[tokio::test]
    async fn test_login_with_backup_code() {
        use crate::auth::mfa::BackupCodeGenerator;

        let user_store = TestUserStore::new();
        let backup_gen = BackupCodeGenerator::default();
        let codes = backup_gen.generate();

        let mut user = create_test_user("test@example.com", "password123", true);
        user.mfa_enabled = true;
        user.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
        user.backup_codes = codes.codes.clone();
        user_store.add_user(user);

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: Some(codes.codes[0].clone()),
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[cfg(feature = "auth-mfa")]
    #[tokio::test]
    async fn test_verify_mfa_with_token() {
        use crate::auth::mfa::{TotpManager, TotpConfig};

        let user_store = TestUserStore::new();
        let totp = TotpManager::new(TotpConfig::default());
        let setup = totp.generate_setup("test@example.com").unwrap();

        let mut user = create_test_user("test@example.com", "password123", true);
        user.mfa_enabled = true;
        user.totp_secret = Some(setup.secret.clone());
        user_store.add_user(user);

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        // First login to get MFA token
        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        let mfa_token = get_mfa_token(&response).unwrap();
        let code = totp.generate_current(&setup.secret, "test@example.com").unwrap();

        // Verify MFA with the token
        let response = flow
            .verify_mfa(MfaVerifyRequest {
                mfa_token,
                code,
            })
            .await
            .unwrap();

        assert!(is_success(&response));
    }

    #[cfg(feature = "auth-mfa")]
    #[tokio::test]
    async fn test_verify_mfa_invalid_token() {
        let user_store = TestUserStore::new();
        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        let result = flow
            .verify_mfa(MfaVerifyRequest {
                mfa_token: "invalid-token".to_string(),
                code: "123456".to_string(),
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_failed_attempts_recorded() {
        let user_store = TestUserStore::new();
        user_store.add_user(create_test_user("test@example.com", "password123", true));

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        // Try wrong password
        let _ = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "wrongpassword".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        // Check that failed attempts was incremented
        let users = flow.user_store.users.read().unwrap();
        let user = users.get("test@example.com").unwrap();
        assert_eq!(user.failed_attempts, 1);
    }

    #[tokio::test]
    async fn test_failed_attempts_cleared_on_success() {
        let user_store = TestUserStore::new();
        let mut user = create_test_user("test@example.com", "password123", true);
        user.failed_attempts = 3;
        user_store.add_user(user);

        let mfa_store = InMemoryMfaTokenStore::new();
        let token_issuer = TestTokenIssuer;
        let config = LoginFlowConfig::new("TestApp");

        let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config);

        // Successful login
        let response = flow
            .login(LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
                remember_me: false,
                mfa_code: None,
            })
            .await
            .unwrap();

        assert!(is_success(&response));

        // Check that failed attempts was cleared
        let users = flow.user_store.users.read().unwrap();
        let user = users.get("test@example.com").unwrap();
        assert_eq!(user.failed_attempts, 0);
    }
}
