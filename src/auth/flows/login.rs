//! Login flow with MFA support.

use crate::auth::password::{PasswordConfig, PasswordHasher};
use crate::auth::storage::token::MfaTokenStore;
use crate::auth::storage::UserStore;
use crate::error::{Result, TidewayError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::time::{Duration, SystemTime};

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

/// Trait for issuing tokens after successful authentication.
pub trait TokenIssuer: Send + Sync {
    /// The user type.
    type User;

    /// Issue tokens for a user.
    ///
    /// Returns (access_token, refresh_token, expires_in).
    fn issue(
        &self,
        user: &Self::User,
        remember_me: bool,
    ) -> Result<(String, String, u64)>;
}

/// Handles the login flow including MFA.
pub struct LoginFlow<U, M, T>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
{
    user_store: U,
    mfa_store: M,
    token_issuer: T,
    password_hasher: PasswordHasher,
    #[cfg(feature = "auth-mfa")]
    totp_manager: TotpManager,
    config: LoginFlowConfig,
}

impl<U, M, T> LoginFlow<U, M, T>
where
    U: UserStore,
    M: MfaTokenStore,
    T: TokenIssuer<User = U::User>,
{
    /// Create a new login flow.
    pub fn new(user_store: U, mfa_store: M, token_issuer: T, config: LoginFlowConfig) -> Self {
        Self {
            user_store,
            password_hasher: PasswordHasher::new(config.password_config.clone()),
            #[cfg(feature = "auth-mfa")]
            totp_manager: TotpManager::new(config.totp_config.clone()),
            mfa_store,
            token_issuer,
            config,
        }
    }

    /// Primary login endpoint - handles email/password and optional MFA.
    #[cfg(feature = "auth")]
    pub async fn login(&self, req: LoginRequest) -> Result<LoginResponse> {
        // Normalize email
        let email = req.email.trim().to_lowercase();

        // Find user
        let user = match self.user_store.find_by_email(&email).await? {
            Some(u) => u,
            None => {
                // Timing-safe: hash anyway to prevent enumeration
                let _ = self.password_hasher.hash("dummy");
                return Ok(LoginResponse::error("Invalid credentials"));
            }
        };

        // Check if locked
        if let Some(until) = self.user_store.is_locked(&user).await? {
            if until > SystemTime::now() {
                return Ok(LoginResponse::error(
                    "Account temporarily locked. Try again later.",
                ));
            }
        }

        // Check if verified (if required)
        if self.config.require_verification && !self.user_store.is_verified(&user).await? {
            return Ok(LoginResponse::error(
                "Please verify your email before logging in.",
            ));
        }

        // Verify password
        let hash = self.user_store.get_password_hash(&user).await?;
        if !self.password_hasher.verify(&req.password, &hash)? {
            self.user_store.record_failed_attempt(&user).await?;
            return Ok(LoginResponse::error("Invalid credentials"));
        }

        // Rehash if needed (transparent upgrade)
        if self.password_hasher.needs_rehash(&hash)? {
            let new_hash = self.password_hasher.hash(&req.password)?;
            self.user_store.update_password_hash(&user, &new_hash).await?;
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
        let email = self.user_store.user_email(user);

        // Try TOTP first (6 digits)
        if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
            if let Some(secret) = self.user_store.get_totp_secret(user).await? {
                if self.totp_manager.verify(&secret, code, &email)? {
                    return self.complete_login(user, remember_me).await;
                }
            }
        }

        // Try backup code (typically 8+ chars alphanumeric)
        let backup_codes = self.user_store.get_backup_codes(user).await?;
        if let Some(index) = BackupCodeGenerator::verify(code, &backup_codes) {
            self.user_store.remove_backup_code(user, index).await?;
            return self.complete_login(user, remember_me).await;
        }

        // Invalid code - use MFA-specific rate limiting
        self.user_store.record_failed_mfa_attempt(user).await?;
        Ok(LoginResponse::error("Invalid MFA code"))
    }

    async fn complete_login(&self, user: &U::User, remember_me: bool) -> Result<LoginResponse> {
        // Clear failed attempts
        self.user_store.clear_failed_attempts(user).await?;

        // Issue tokens
        let (access_token, refresh_token, expires_in) =
            self.token_issuer.issue(user, remember_me)?;

        Ok(LoginResponse::success(access_token, refresh_token, expires_in))
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
