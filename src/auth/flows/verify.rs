//! Email verification flow.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.email.verification_sent` - Verification email sent
//! - `auth.email.verified` - Email verified successfully
//! - `auth.email.verification_failed` - Verification failed (invalid token)

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

        tracing::info!(
            target: "auth.email.verification_sent",
            user_id = %user_id,
            email = %email,
            expires_in_secs = self.token_ttl.as_secs(),
            "Verification email sent"
        );

        Ok(())
    }

    /// Verify an email using a token.
    pub async fn verify(&self, req: EmailVerifyRequest) -> Result<()> {
        // Hash the provided token to look up
        let token_hash = hash_token(&req.token);

        // Consume token
        let user_id = match self.store.consume_verification_token(&token_hash).await? {
            Some(id) => id,
            None => {
                tracing::warn!(
                    target: "auth.email.verification_failed",
                    reason = "invalid_token",
                    "Email verification failed: invalid or expired token"
                );
                return Err(TidewayError::BadRequest(
                    "Invalid or expired verification token".into(),
                ));
            }
        };

        // Mark user as verified
        self.store.mark_user_verified(&user_id).await?;

        tracing::info!(
            target: "auth.email.verified",
            user_id = %user_id,
            "Email verified successfully"
        );

        Ok(())
    }

    /// Resend a verification email.
    ///
    /// Note: The caller should verify the user exists and is not already verified.
    pub async fn resend(&self, req: ResendVerificationRequest, user_id: &str) -> Result<()> {
        tracing::info!(
            target: "auth.email.verification_resent",
            user_id = %user_id,
            email = %req.email,
            "Verification email resend requested"
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::RwLock;

    struct TestVerificationStore {
        tokens: RwLock<HashMap<String, (String, SystemTime)>>,
        verified_users: RwLock<Vec<String>>,
        emails_sent: RwLock<Vec<(String, String, String)>>, // (user_id, email, token)
    }

    impl TestVerificationStore {
        fn new() -> Self {
            Self {
                tokens: RwLock::new(HashMap::new()),
                verified_users: RwLock::new(vec![]),
                emails_sent: RwLock::new(vec![]),
            }
        }

        fn get_sent_emails(&self) -> Vec<(String, String, String)> {
            self.emails_sent.read().unwrap().clone()
        }

        fn get_verified_users(&self) -> Vec<String> {
            self.verified_users.read().unwrap().clone()
        }

        fn is_user_verified(&self, user_id: &str) -> bool {
            self.verified_users.read().unwrap().contains(&user_id.to_string())
        }
    }

    #[async_trait]
    impl VerificationStore for TestVerificationStore {
        async fn store_verification_token(
            &self,
            user_id: &str,
            token_hash: &str,
            expires: SystemTime,
        ) -> Result<()> {
            let mut tokens = self.tokens.write().unwrap();
            tokens.insert(token_hash.to_string(), (user_id.to_string(), expires));
            Ok(())
        }

        async fn consume_verification_token(&self, token_hash: &str) -> Result<Option<String>> {
            let mut tokens = self.tokens.write().unwrap();
            if let Some((user_id, expires)) = tokens.remove(token_hash) {
                if SystemTime::now() < expires {
                    return Ok(Some(user_id));
                }
            }
            Ok(None)
        }

        async fn mark_user_verified(&self, user_id: &str) -> Result<()> {
            let mut verified = self.verified_users.write().unwrap();
            verified.push(user_id.to_string());
            Ok(())
        }

        async fn send_verification_email(
            &self,
            user_id: &str,
            email: &str,
            token: &str,
            _expires_in: Duration,
        ) -> Result<()> {
            let mut emails = self.emails_sent.write().unwrap();
            emails.push((user_id.to_string(), email.to_string(), token.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_send_verification() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        let result = flow
            .send_verification("user-123", "test@example.com")
            .await;

        assert!(result.is_ok());

        // Verify email was sent
        let emails = flow.store.get_sent_emails();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].0, "user-123");
        assert_eq!(emails[0].1, "test@example.com");
        assert!(!emails[0].2.is_empty()); // Token should not be empty
    }

    #[tokio::test]
    async fn test_verify_valid_token() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        // Send verification
        flow.send_verification("user-123", "test@example.com")
            .await
            .unwrap();

        // Get the token from the sent email
        let emails = flow.store.get_sent_emails();
        let token = &emails[0].2;

        // Verify
        let result = flow.verify(EmailVerifyRequest { token: token.clone() }).await;

        assert!(result.is_ok());

        // Check user is marked verified
        assert!(flow.store.is_user_verified("user-123"));
    }

    #[tokio::test]
    async fn test_verify_invalid_token() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        let result = flow
            .verify(EmailVerifyRequest {
                token: "invalid-token".to_string(),
            })
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid or expired"));
    }

    #[tokio::test]
    async fn test_verify_token_consumed() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        // Send verification
        flow.send_verification("user-123", "test@example.com")
            .await
            .unwrap();

        // Get the token from the sent email
        let emails = flow.store.get_sent_emails();
        let token = &emails[0].2;

        // Verify first time
        flow.verify(EmailVerifyRequest { token: token.clone() })
            .await
            .unwrap();

        // Try to verify again
        let result = flow.verify(EmailVerifyRequest { token: token.clone() }).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resend_verification() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        // Send initial verification
        flow.send_verification("user-123", "test@example.com")
            .await
            .unwrap();

        // Resend
        flow.resend(
            ResendVerificationRequest {
                email: "test@example.com".to_string(),
            },
            "user-123",
        )
        .await
        .unwrap();

        // Should have two emails sent
        let emails = flow.store.get_sent_emails();
        assert_eq!(emails.len(), 2);
    }

    #[tokio::test]
    async fn test_custom_ttl() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store).with_ttl(Duration::from_secs(60));

        let result = flow
            .send_verification("user-123", "test@example.com")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_uniqueness() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        // Send two verification emails
        flow.send_verification("user-1", "user1@example.com")
            .await
            .unwrap();
        flow.send_verification("user-2", "user2@example.com")
            .await
            .unwrap();

        // Get the tokens
        let emails = flow.store.get_sent_emails();
        let token1 = &emails[0].2;
        let token2 = &emails[1].2;

        // Tokens should be different
        assert_ne!(token1, token2);
    }

    #[tokio::test]
    async fn test_verify_correct_user() {
        let store = TestVerificationStore::new();
        let flow = EmailVerificationFlow::new(store);

        // Send verification emails for two users
        flow.send_verification("user-1", "user1@example.com")
            .await
            .unwrap();
        flow.send_verification("user-2", "user2@example.com")
            .await
            .unwrap();

        // Get user-1's token
        let emails = flow.store.get_sent_emails();
        let token1 = &emails[0].2;

        // Verify with user-1's token
        flow.verify(EmailVerifyRequest { token: token1.clone() })
            .await
            .unwrap();

        // Only user-1 should be verified
        let verified = flow.store.get_verified_users();
        assert!(verified.contains(&"user-1".to_string()));
        assert!(!verified.contains(&"user-2".to_string()));
    }
}
