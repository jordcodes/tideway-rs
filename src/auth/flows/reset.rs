//! Password reset flow.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.password.reset_requested` - Password reset requested (email sent)
//! - `auth.password.reset_completed` - Password successfully reset
//! - `auth.password.reset_failed` - Password reset failed (invalid token, weak password)

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
        self.store
            .send_reset_email(&user, &token, self.token_ttl)
            .await?;

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

        // Consume token
        let user_id = match self.store.consume_reset_token(&token_hash).await? {
            Some(id) => id,
            None => {
                tracing::warn!(
                    target: "auth.password.reset_failed",
                    reason = "invalid_token",
                    "Password reset failed: invalid or expired token"
                );
                return Err(TidewayError::BadRequest("Invalid or expired reset token".into()));
            }
        };

        // Hash new password
        let password_hash = self.password_hasher.hash(&req.new_password)?;

        // Update password
        self.store.update_password(&user_id, &password_hash).await?;

        // Invalidate existing sessions
        self.store.invalidate_sessions(&user_id).await?;

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

    #[derive(Clone)]
    struct TestUser {
        id: String,
        email: String,
        password_hash: String,
    }

    struct TestResetStore {
        users: RwLock<HashMap<String, TestUser>>,
        tokens: RwLock<HashMap<String, (String, SystemTime)>>,
        emails_sent: RwLock<Vec<(String, String)>>,
        sessions_invalidated: RwLock<Vec<String>>,
    }

    impl TestResetStore {
        fn new() -> Self {
            Self {
                users: RwLock::new(HashMap::new()),
                tokens: RwLock::new(HashMap::new()),
                emails_sent: RwLock::new(vec![]),
                sessions_invalidated: RwLock::new(vec![]),
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
            if let Some((user_id, expires)) = tokens.remove(token_hash) {
                if SystemTime::now() < expires {
                    return Ok(Some(user_id));
                }
            }
            Ok(None)
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

        async fn send_reset_email(
            &self,
            user: &Self::User,
            token: &str,
            _expires_in: Duration,
        ) -> Result<()> {
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
}
