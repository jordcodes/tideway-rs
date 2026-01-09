//! Password reset flow.

use crate::auth::password::{PasswordHasher, PasswordPolicy};
use crate::auth::storage::PasswordResetStore;
use crate::error::{Result, TidewayError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

use super::types::{PasswordResetComplete, PasswordResetRequest};

/// Handles password reset flow.
pub struct PasswordResetFlow<S: PasswordResetStore> {
    store: S,
    password_hasher: PasswordHasher,
    password_policy: PasswordPolicy,
    token_ttl: Duration,
}

impl<S: PasswordResetStore> PasswordResetFlow<S> {
    /// Create a new password reset flow.
    pub fn new(store: S) -> Self {
        Self {
            store,
            password_hasher: PasswordHasher::default(),
            password_policy: PasswordPolicy::modern(),
            token_ttl: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Set the token TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = ttl;
        self
    }

    /// Set a custom password policy.
    pub fn with_policy(mut self, policy: PasswordPolicy) -> Self {
        self.password_policy = policy;
        self
    }

    /// Request a password reset.
    ///
    /// Always returns success to prevent email enumeration.
    pub async fn request_reset(&self, req: PasswordResetRequest) -> Result<()> {
        let email = req.email.trim().to_lowercase();

        // Find user (don't reveal if exists)
        let user = match self.store.find_by_email(&email).await? {
            Some(u) => u,
            None => {
                // Log but don't reveal
                tracing::info!("Password reset requested for unknown email");
                return Ok(());
            }
        };

        // Generate token
        let token = generate_reset_token();
        let token_hash = hash_token(&token);
        let expires = SystemTime::now() + self.token_ttl;

        // Store token hash
        self.store
            .store_reset_token(&self.store.user_id(&user), &token_hash, expires)
            .await?;

        // Send email with the raw token (not the hash)
        self.store
            .send_reset_email(&user, &token, self.token_ttl)
            .await?;

        Ok(())
    }

    /// Complete a password reset.
    #[cfg(feature = "auth")]
    pub async fn complete_reset(&self, req: PasswordResetComplete) -> Result<()> {
        // Validate new password
        self.password_policy.check(&req.new_password)?;

        // Hash the provided token to look up
        let token_hash = hash_token(&req.token);

        // Consume token
        let user_id = self
            .store
            .consume_reset_token(&token_hash)
            .await?
            .ok_or_else(|| TidewayError::BadRequest("Invalid or expired reset token".into()))?;

        // Hash new password
        let password_hash = self.password_hasher.hash(&req.new_password)?;

        // Update password
        self.store.update_password(&user_id, &password_hash).await?;

        // Invalidate existing sessions
        self.store.invalidate_sessions(&user_id).await?;

        Ok(())
    }

    #[cfg(not(feature = "auth"))]
    pub async fn complete_reset(&self, _req: PasswordResetComplete) -> Result<()> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }
}

/// Generate a secure reset token.
fn generate_reset_token() -> String {
    let bytes: [u8; 32] = std::array::from_fn(|_| fastrand::u8(..));
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token for storage.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}
