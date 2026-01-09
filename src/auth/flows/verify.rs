//! Email verification flow.

use crate::auth::storage::VerificationStore;
use crate::error::{Result, TidewayError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

use super::types::{EmailVerifyRequest, ResendVerificationRequest};

/// Handles email verification flow.
pub struct EmailVerificationFlow<S: VerificationStore> {
    store: S,
    token_ttl: Duration,
}

impl<S: VerificationStore> EmailVerificationFlow<S> {
    /// Create a new email verification flow.
    pub fn new(store: S) -> Self {
        Self {
            store,
            token_ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
        }
    }

    /// Set the token TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = ttl;
        self
    }

    /// Send a verification email to a user.
    pub async fn send_verification(&self, user_id: &str, email: &str) -> Result<()> {
        // Generate token
        let token = generate_verification_token();
        let token_hash = hash_token(&token);
        let expires = SystemTime::now() + self.token_ttl;

        // Store token hash
        self.store
            .store_verification_token(user_id, &token_hash, expires)
            .await?;

        // Send email with the raw token
        self.store
            .send_verification_email(user_id, email, &token, self.token_ttl)
            .await?;

        Ok(())
    }

    /// Verify an email using a token.
    pub async fn verify(&self, req: EmailVerifyRequest) -> Result<()> {
        // Hash the provided token to look up
        let token_hash = hash_token(&req.token);

        // Consume token
        let user_id = self
            .store
            .consume_verification_token(&token_hash)
            .await?
            .ok_or_else(|| {
                TidewayError::BadRequest("Invalid or expired verification token".into())
            })?;

        // Mark user as verified
        self.store.mark_user_verified(&user_id).await?;

        Ok(())
    }

    /// Resend a verification email.
    ///
    /// Note: The caller should verify the user exists and is not already verified.
    pub async fn resend(&self, req: ResendVerificationRequest, user_id: &str) -> Result<()> {
        self.send_verification(user_id, &req.email).await
    }
}

/// Generate a secure verification token.
fn generate_verification_token() -> String {
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
