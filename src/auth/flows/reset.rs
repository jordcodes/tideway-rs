//! Password reset flow.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.password.reset_requested` - Password reset requested (email sent)
//! - `auth.password.reset_completed` - Password successfully reset
//! - `auth.password.reset_failed` - Password reset failed (invalid token, weak password)

use crate::auth::password::{PasswordHasher, PasswordPolicy};
use crate::auth::storage::PasswordResetStore;
use crate::error::{Result, TidewayError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

    /// Set a custom password hasher (primarily useful for controlled migrations and tests).
    pub fn with_hasher(mut self, hasher: PasswordHasher) -> Self {
        self.password_hasher = hasher;
        self
    }

    /// Request a password reset.
    ///
    /// Always uses the same response value for known and unknown accounts.
    ///
    /// Callers should keep this work off the HTTP response path (for example, enqueue it) so
    /// account lookup and provider latency cannot become an enumeration side channel.
    pub async fn request_reset(&self, req: PasswordResetRequest) -> Result<()> {
        let email = req.email.trim().to_lowercase();

        // Find user (don't reveal if exists)
        let user = match self.store.find_by_email(&email).await? {
            Some(u) => u,
            None => {
                // Log but don't reveal to caller
                tracing::info!(
                    target: "auth.password.reset_requested",
                    email = %email,
                    user_found = false,
                    "Password reset requested for unknown email"
                );
                return Ok(());
            }
        };

        let user_id = self.store.user_id(&user);

        // Generate token
        let token = generate_reset_token();
        let token_hash = hash_token(&token);
        let expires = SystemTime::now() + self.token_ttl;

        // Store token hash
        self.store
            .store_reset_token(&user_id, &token_hash, expires)
            .await?;

        // Send email with the raw token (not the hash)
        if let Err(error) = self
            .store
            .send_reset_email(&user, &token, self.token_ttl)
            .await
        {
            if let Err(cleanup_error) = self.store.discard_reset_token(&token_hash).await {
                tracing::error!(%cleanup_error, "Failed to discard undelivered password reset token");
            }
            return Err(error);
        }

        tracing::info!(
            target: "auth.password.reset_requested",
            user_id = %user_id,
            email = %email,
            user_found = true,
            expires_in_secs = self.token_ttl.as_secs(),
            "Password reset email sent"
        );

        Ok(())
    }

    /// Complete a password reset.
    #[cfg(feature = "auth")]
    pub async fn complete_reset(&self, req: PasswordResetComplete) -> Result<()> {
        // Validate new password
        if let Err(e) = self.password_policy.check(&req.new_password) {
            tracing::info!(
                target: "auth.password.reset_failed",
                reason = "weak_password",
                "Password reset failed: password policy violation"
            );
            return Err(e);
        }

        // Hash the provided token to look up
        let token_hash = hash_token(&req.token);

        // Avoid expensive Argon2 work for invalid tokens without holding a transaction open
        // during hashing. The atomic completion operation revalidates after hashing.
        if !self.store.is_reset_token_valid(&token_hash).await? {
            tracing::warn!(
                target: "auth.password.reset_failed",
                reason = "invalid_token",
                "Password reset failed: invalid or expired token"
            );
            return Err(TidewayError::coded_bad_request(
                "password_reset.invalid_or_expired_token",
                "Invalid or expired reset token",
            ));
        }

        // Hash before the token is claimed so hashing failure remains retryable.
        let password_hash = self.password_hasher.hash_async(&req.new_password).await?;

        // The store owns the atomic security-state transition and revalidates the token.
        let user_id = match self
            .store
            .complete_password_reset(&token_hash, &password_hash)
            .await?
        {
            Some(id) => id,
            None => {
                tracing::warn!(
                    target: "auth.password.reset_failed",
                    reason = "invalid_token",
                    "Password reset failed: invalid or expired token"
                );
                return Err(TidewayError::coded_bad_request(
                    "password_reset.invalid_or_expired_token",
                    "Invalid or expired reset token",
                ));
            }
        };

        tracing::info!(
            target: "auth.password.reset_completed",
            user_id = %user_id,
            "Password reset completed successfully"
        );

        Ok(())
    }

    #[cfg(not(feature = "auth"))]
    pub async fn complete_reset(&self, _req: PasswordResetComplete) -> Result<()> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }
}

/// Generate a secure reset token.
fn generate_reset_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
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

    #[derive(Clone)]
    struct TestUser {
        id: String,
        email: String,
        password_hash: String,
        failed_attempts: u32,
        failed_mfa_attempts: u32,
        locked_until: Option<SystemTime>,
    }

    struct TestResetStore {
        users: RwLock<HashMap<String, TestUser>>,
        tokens: RwLock<HashMap<String, (String, SystemTime)>>,
        emails_sent: RwLock<Vec<(String, String)>>,
        sessions_invalidated: RwLock<Vec<String>>,
        fail_email: RwLock<bool>,
        fail_completion: RwLock<bool>,
    }

    impl TestResetStore {
        fn new() -> Self {
            Self {
                users: RwLock::new(HashMap::new()),
                tokens: RwLock::new(HashMap::new()),
                emails_sent: RwLock::new(vec![]),
                sessions_invalidated: RwLock::new(vec![]),
                fail_email: RwLock::new(false),
                fail_completion: RwLock::new(false),
            }
        }

        fn add_user(&self, user: TestUser) {
            let mut users = self.users.write().unwrap();
            users.insert(user.email.clone(), user);
        }

        fn get_sent_emails(&self) -> Vec<(String, String)> {
            self.emails_sent.read().unwrap().clone()
        }

        fn get_invalidated_sessions(&self) -> Vec<String> {
            self.sessions_invalidated.read().unwrap().clone()
        }

        fn get_user_password(&self, email: &str) -> Option<String> {
            let users = self.users.read().unwrap();
            users.get(email).map(|u| u.password_hash.clone())
        }

        fn get_lockout_state(&self, email: &str) -> Option<(u32, u32, Option<SystemTime>)> {
            self.users.read().unwrap().get(email).map(|user| {
                (
                    user.failed_attempts,
                    user.failed_mfa_attempts,
                    user.locked_until,
                )
            })
        }

        fn set_email_failure(&self, fail: bool) {
            *self.fail_email.write().unwrap() = fail;
        }

        fn set_completion_failure(&self, fail: bool) {
            *self.fail_completion.write().unwrap() = fail;
        }
    }

    #[async_trait]
    impl PasswordResetStore for TestResetStore {
        type User = TestUser;

        async fn find_by_email(&self, email: &str) -> Result<Option<Self::User>> {
            let users = self.users.read().unwrap();
            Ok(users.get(email).cloned())
        }

        fn user_id(&self, user: &Self::User) -> String {
            user.id.clone()
        }

        async fn store_reset_token(
            &self,
            user_id: &str,
            token_hash: &str,
            expires: SystemTime,
        ) -> Result<()> {
            let mut tokens = self.tokens.write().unwrap();
            tokens.insert(token_hash.to_string(), (user_id.to_string(), expires));
            Ok(())
        }

        async fn consume_reset_token(&self, token_hash: &str) -> Result<Option<String>> {
            let mut tokens = self.tokens.write().unwrap();
            if let Some((user_id, expires)) = tokens.remove(token_hash)
                && SystemTime::now() < expires
            {
                return Ok(Some(user_id));
            }
            Ok(None)
        }

        async fn is_reset_token_valid(&self, token_hash: &str) -> Result<bool> {
            Ok(self
                .tokens
                .read()
                .unwrap()
                .get(token_hash)
                .is_some_and(|(_, expires)| SystemTime::now() < *expires))
        }

        async fn discard_reset_token(&self, token_hash: &str) -> Result<()> {
            self.tokens.write().unwrap().remove(token_hash);
            Ok(())
        }

        async fn update_password(&self, user_id: &str, hash: &str) -> Result<()> {
            let mut users = self.users.write().unwrap();
            for user in users.values_mut() {
                if user.id == user_id {
                    user.password_hash = hash.to_string();
                    break;
                }
            }
            Ok(())
        }

        async fn invalidate_sessions(&self, user_id: &str) -> Result<()> {
            let mut sessions = self.sessions_invalidated.write().unwrap();
            sessions.push(user_id.to_string());
            Ok(())
        }

        async fn complete_password_reset(
            &self,
            token_hash: &str,
            password_hash: &str,
        ) -> Result<Option<String>> {
            if *self.fail_completion.read().unwrap() {
                return Err(TidewayError::Internal("injected completion failure".into()));
            }
            let token = self.tokens.read().unwrap().get(token_hash).cloned();
            let Some((user_id, expires)) = token else {
                return Ok(None);
            };
            if SystemTime::now() >= expires {
                return Ok(None);
            }

            let mut users = self.users.write().unwrap();
            let Some(user) = users.values_mut().find(|user| user.id == user_id) else {
                return Err(TidewayError::NotFound("User not found".into()));
            };
            user.password_hash = password_hash.to_string();
            user.failed_attempts = 0;
            user.failed_mfa_attempts = 0;
            user.locked_until = None;
            self.tokens
                .write()
                .unwrap()
                .retain(|_, (token_user_id, _)| token_user_id != &user_id);
            self.sessions_invalidated
                .write()
                .unwrap()
                .push(user_id.clone());
            Ok(Some(user_id))
        }

        async fn send_reset_email(
            &self,
            user: &Self::User,
            token: &str,
            _expires_in: Duration,
        ) -> Result<()> {
            if *self.fail_email.read().unwrap() {
                return Err(TidewayError::Internal("injected email failure".into()));
            }
            let mut emails = self.emails_sent.write().unwrap();
            emails.push((user.email.clone(), token.to_string()));
            Ok(())
        }
    }

    fn create_test_user(email: &str) -> TestUser {
        TestUser {
            id: format!("user-{}", email.split('@').next().unwrap()),
            email: email.to_string(),
            password_hash: "old-hash".to_string(),
            failed_attempts: 5,
            failed_mfa_attempts: 5,
            locked_until: Some(SystemTime::now() + Duration::from_secs(900)),
        }
    }

    #[tokio::test]
    async fn test_request_reset_existing_user() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store);

        let result = flow
            .request_reset(PasswordResetRequest {
                email: "test@example.com".to_string(),
            })
            .await;

        assert!(result.is_ok());

        // Verify email was sent
        let emails = flow.store.get_sent_emails();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].0, "test@example.com");
        assert!(!emails[0].1.is_empty()); // Token should not be empty
    }

    #[tokio::test]
    async fn test_request_reset_unknown_user() {
        let store = TestResetStore::new();
        let flow = PasswordResetFlow::new(store);

        // Should not error even for unknown users (prevent enumeration)
        let result = flow
            .request_reset(PasswordResetRequest {
                email: "unknown@example.com".to_string(),
            })
            .await;

        assert!(result.is_ok());

        // No email should be sent
        let emails = flow.store.get_sent_emails();
        assert!(emails.is_empty());
    }

    #[tokio::test]
    async fn test_request_reset_case_insensitive() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store);

        let result = flow
            .request_reset(PasswordResetRequest {
                email: "TEST@EXAMPLE.COM".to_string(),
            })
            .await;

        assert!(result.is_ok());

        // Should still find the user and send email
        let emails = flow.store.get_sent_emails();
        assert_eq!(emails.len(), 1);
    }

    #[tokio::test]
    async fn test_complete_reset_valid_token() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store);

        // Request reset
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".to_string(),
        })
        .await
        .unwrap();

        // Get the token from the sent email
        let emails = flow.store.get_sent_emails();
        let token = &emails[0].1;

        // Complete reset
        let result = flow
            .complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "NewSecurePassword123!".to_string(),
            })
            .await;

        assert!(result.is_ok());

        // Verify password was updated
        let new_hash = flow.store.get_user_password("test@example.com").unwrap();
        assert_ne!(new_hash, "old-hash");

        // Verify sessions were invalidated
        let invalidated = flow.store.get_invalidated_sessions();
        assert!(invalidated.contains(&"user-test".to_string()));

        // A reset is an account-recovery event and clears both login and MFA lockout state.
        let lockout = flow.store.get_lockout_state("test@example.com").unwrap();
        assert_eq!(lockout, (0, 0, None));
    }

    #[tokio::test]
    async fn test_complete_reset_invalid_token() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store);

        let result = flow
            .complete_reset(PasswordResetComplete {
                token: "invalid-token".to_string(),
                new_password: "NewSecurePassword123!".to_string(),
            })
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid or expired"));
    }

    #[tokio::test]
    async fn test_complete_reset_weak_password() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store);

        // Request reset
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".to_string(),
        })
        .await
        .unwrap();

        // Get the token from the sent email
        let emails = flow.store.get_sent_emails();
        let token = &emails[0].1;

        // Try to complete with weak password
        let result = flow
            .complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "weak".to_string(),
            })
            .await;

        assert!(result.is_err());

        // Verify password was NOT updated
        let hash = flow.store.get_user_password("test@example.com").unwrap();
        assert_eq!(hash, "old-hash");
    }

    #[tokio::test]
    async fn test_complete_reset_token_consumed() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store);

        // Request reset
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".to_string(),
        })
        .await
        .unwrap();

        // Get the token from the sent email
        let emails = flow.store.get_sent_emails();
        let token = &emails[0].1;

        // Complete reset first time
        flow.complete_reset(PasswordResetComplete {
            token: token.clone(),
            new_password: "NewSecurePassword123!".to_string(),
        })
        .await
        .unwrap();

        // Try to use the same token again
        let result = flow
            .complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "AnotherPassword456!".to_string(),
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_custom_ttl() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        let flow = PasswordResetFlow::new(store).with_ttl(Duration::from_secs(60));

        let result = flow
            .request_reset(PasswordResetRequest {
                email: "test@example.com".to_string(),
            })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_custom_policy() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));

        // Use a strict policy
        let policy = PasswordPolicy::strict();
        let flow = PasswordResetFlow::new(store).with_policy(policy);

        // Request reset
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".to_string(),
        })
        .await
        .unwrap();

        // Get the token from the sent email
        let emails = flow.store.get_sent_emails();
        let token = &emails[0].1;

        // Try to complete with password that doesn't meet strict policy
        let result = flow
            .complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "SimplePassword123".to_string(), // Missing special char
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn completion_failure_does_not_consume_token() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));
        let flow = PasswordResetFlow::new(store);
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".into(),
        })
        .await
        .unwrap();
        let token = flow.store.get_sent_emails()[0].1.clone();

        flow.store.set_completion_failure(true);
        assert!(
            flow.complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "NewSecurePassword123!".into(),
            })
            .await
            .is_err()
        );
        flow.store.set_completion_failure(false);
        assert!(
            flow.complete_reset(PasswordResetComplete {
                token,
                new_password: "NewSecurePassword123!".into(),
            })
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn hashing_failure_does_not_consume_token() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));
        let invalid_hasher = PasswordHasher::new(crate::auth::PasswordConfig::new(0, 0, 0));
        let flow = PasswordResetFlow::new(store).with_hasher(invalid_hasher);
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".into(),
        })
        .await
        .unwrap();
        let token = flow.store.get_sent_emails()[0].1.clone();
        assert!(
            flow.complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "NewSecurePassword123!".into(),
            })
            .await
            .is_err()
        );

        let flow = flow.with_hasher(PasswordHasher::default());
        assert!(
            flow.complete_reset(PasswordResetComplete {
                token,
                new_password: "NewSecurePassword123!".into(),
            })
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn email_failure_preserves_an_existing_token() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));
        let flow = PasswordResetFlow::new(store);
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".into(),
        })
        .await
        .unwrap();
        let original_token = flow.store.get_sent_emails()[0].1.clone();

        flow.store.set_email_failure(true);
        assert!(
            flow.request_reset(PasswordResetRequest {
                email: "test@example.com".into(),
            })
            .await
            .is_err()
        );
        flow.store.set_email_failure(false);
        assert!(
            flow.complete_reset(PasswordResetComplete {
                token: original_token,
                new_password: "NewSecurePassword123!".into(),
            })
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn successful_reset_invalidates_other_outstanding_tokens() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));
        let flow = PasswordResetFlow::new(store);
        for _ in 0..2 {
            flow.request_reset(PasswordResetRequest {
                email: "test@example.com".into(),
            })
            .await
            .unwrap();
        }
        let emails = flow.store.get_sent_emails();
        flow.complete_reset(PasswordResetComplete {
            token: emails[0].1.clone(),
            new_password: "NewSecurePassword123!".into(),
        })
        .await
        .unwrap();
        let error = flow
            .complete_reset(PasswordResetComplete {
                token: emails[1].1.clone(),
                new_password: "AnotherSecurePassword456!".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(
            error.error_code(),
            Some("password_reset.invalid_or_expired_token")
        );
    }

    #[tokio::test]
    async fn concurrent_completion_has_one_winner() {
        let store = TestResetStore::new();
        store.add_user(create_test_user("test@example.com"));
        let flow = PasswordResetFlow::new(store);
        flow.request_reset(PasswordResetRequest {
            email: "test@example.com".into(),
        })
        .await
        .unwrap();
        let token = flow.store.get_sent_emails()[0].1.clone();
        let (first, second) = tokio::join!(
            flow.complete_reset(PasswordResetComplete {
                token: token.clone(),
                new_password: "FirstSecurePassword123!".into(),
            }),
            flow.complete_reset(PasswordResetComplete {
                token,
                new_password: "SecondSecurePassword456!".into(),
            })
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    }

    #[tokio::test]
    async fn password_policy_errors_have_stable_codes() {
        let error = PasswordPolicy::modern().check("short").unwrap_err();
        assert_eq!(error.error_code(), Some("password_policy.too_short"));

        let too_long = "x".repeat(129);
        let error = PasswordPolicy::modern().check(&too_long).unwrap_err();
        assert_eq!(error.error_code(), Some("password_policy.too_long"));
    }
}
