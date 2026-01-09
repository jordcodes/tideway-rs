//! Password change flow for authenticated users.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.password.change_failed` - Password change failed (wrong current password, weak new password)
//! - `auth.password.changed` - Password changed successfully

use crate::auth::password::{PasswordHasher, PasswordPolicy};
use crate::error::{Result, TidewayError};
use async_trait::async_trait;

use super::types::PasswordChangeRequest;

/// Trait for password change storage operations.
///
/// Implement this trait to connect the password change flow to your database.
#[async_trait]
pub trait PasswordChangeStore: Send + Sync {
    /// Get the user's current password hash by user ID.
    async fn get_password_hash(&self, user_id: &str) -> Result<Option<String>>;

    /// Update the user's password hash.
    async fn update_password(&self, user_id: &str, hash: &str) -> Result<()>;

    /// Invalidate all sessions except the current one.
    ///
    /// Called after successful password change to log out other devices.
    /// The `except_session_id` is the current session to keep active.
    async fn invalidate_other_sessions(
        &self,
        user_id: &str,
        except_session_id: Option<&str>,
    ) -> Result<usize>;
}

/// Configuration for password change flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordChangeConfig {
    /// Whether to invalidate other sessions after password change.
    pub invalidate_sessions: bool,
}

impl Default for PasswordChangeConfig {
    fn default() -> Self {
        Self {
            invalidate_sessions: true,
        }
    }
}

impl PasswordChangeConfig {
    /// Create a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to invalidate other sessions after password change.
    #[must_use]
    pub fn invalidate_sessions(mut self, invalidate: bool) -> Self {
        self.invalidate_sessions = invalidate;
        self
    }
}

/// Handles password change for authenticated users.
///
/// Unlike password reset (which uses email tokens), password change requires
/// the user to verify their current password before setting a new one.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::flows::{PasswordChangeFlow, PasswordChangeRequest};
///
/// let flow = PasswordChangeFlow::new(store);
///
/// // User must be authenticated - we have their user_id from JWT
/// flow.change_password(
///     "user-123",
///     PasswordChangeRequest {
///         current_password: "old-password".to_string(),
///         new_password: "new-secure-password".to_string(),
///     },
///     Some("current-session-id"), // Keep this session active
/// ).await?;
/// ```
pub struct PasswordChangeFlow<S: PasswordChangeStore> {
    store: S,
    password_hasher: PasswordHasher,
    password_policy: PasswordPolicy,
    config: PasswordChangeConfig,
}

impl<S: PasswordChangeStore> PasswordChangeFlow<S> {
    /// Create a new password change flow.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            store,
            password_hasher: PasswordHasher::default(),
            password_policy: PasswordPolicy::modern(),
            config: PasswordChangeConfig::default(),
        }
    }

    /// Set a custom password policy.
    #[must_use]
    pub fn with_policy(mut self, policy: PasswordPolicy) -> Self {
        self.password_policy = policy;
        self
    }

    /// Set a custom configuration.
    #[must_use]
    pub fn with_config(mut self, config: PasswordChangeConfig) -> Self {
        self.config = config;
        self
    }

    /// Disable session invalidation after password change.
    #[must_use]
    pub fn without_session_invalidation(mut self) -> Self {
        self.config.invalidate_sessions = false;
        self
    }

    /// Change a user's password.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The authenticated user's ID (from JWT claims)
    /// * `req` - The password change request with current and new passwords
    /// * `current_session_id` - Optional session ID to keep active (revokes all others)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The current password is incorrect
    /// - The new password doesn't meet the policy
    /// - The user doesn't exist
    #[cfg(feature = "auth")]
    pub async fn change_password(
        &self,
        user_id: &str,
        req: PasswordChangeRequest,
        current_session_id: Option<&str>,
    ) -> Result<()> {
        // Get current password hash
        let current_hash = match self.store.get_password_hash(user_id).await? {
            Some(hash) => hash,
            None => {
                tracing::warn!(
                    target: "auth.password.change_failed",
                    user_id = %user_id,
                    reason = "user_not_found",
                    "Password change failed: user not found"
                );
                return Err(TidewayError::Unauthorized("Invalid credentials".into()));
            }
        };

        // Verify current password
        if !self.password_hasher.verify(&req.current_password, &current_hash)? {
            tracing::warn!(
                target: "auth.password.change_failed",
                user_id = %user_id,
                reason = "wrong_password",
                "Password change failed: current password incorrect"
            );
            return Err(TidewayError::Unauthorized(
                "Current password is incorrect".into(),
            ));
        }

        // Validate new password against policy
        if let Err(e) = self.password_policy.check(&req.new_password) {
            tracing::info!(
                target: "auth.password.change_failed",
                user_id = %user_id,
                reason = "weak_password",
                "Password change failed: new password doesn't meet policy"
            );
            return Err(e);
        }

        // Prevent setting same password
        if self.password_hasher.verify(&req.new_password, &current_hash)? {
            tracing::info!(
                target: "auth.password.change_failed",
                user_id = %user_id,
                reason = "same_password",
                "Password change failed: new password same as current"
            );
            return Err(TidewayError::BadRequest(
                "New password must be different from current password".into(),
            ));
        }

        // Hash new password
        let new_hash = self.password_hasher.hash(&req.new_password)?;

        // Update password
        self.store.update_password(user_id, &new_hash).await?;

        // Invalidate other sessions
        let sessions_revoked = if self.config.invalidate_sessions {
            self.store
                .invalidate_other_sessions(user_id, current_session_id)
                .await?
        } else {
            0
        };

        tracing::info!(
            target: "auth.password.changed",
            user_id = %user_id,
            sessions_revoked = sessions_revoked,
            "Password changed successfully"
        );

        Ok(())
    }

    #[cfg(not(feature = "auth"))]
    pub async fn change_password(
        &self,
        _user_id: &str,
        _req: PasswordChangeRequest,
        _current_session_id: Option<&str>,
    ) -> Result<()> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    struct TestStore {
        passwords: RwLock<HashMap<String, String>>,
        invalidated_sessions: RwLock<Vec<(String, Option<String>)>>,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                passwords: RwLock::new(HashMap::new()),
                invalidated_sessions: RwLock::new(vec![]),
            }
        }

        fn add_user(&self, user_id: &str, password_hash: &str) {
            self.passwords
                .write()
                .unwrap()
                .insert(user_id.to_string(), password_hash.to_string());
        }

        fn get_invalidated(&self) -> Vec<(String, Option<String>)> {
            self.invalidated_sessions.read().unwrap().clone()
        }
    }

    #[async_trait]
    impl PasswordChangeStore for TestStore {
        async fn get_password_hash(&self, user_id: &str) -> Result<Option<String>> {
            Ok(self.passwords.read().unwrap().get(user_id).cloned())
        }

        async fn update_password(&self, user_id: &str, hash: &str) -> Result<()> {
            self.passwords
                .write()
                .unwrap()
                .insert(user_id.to_string(), hash.to_string());
            Ok(())
        }

        async fn invalidate_other_sessions(
            &self,
            user_id: &str,
            except_session_id: Option<&str>,
        ) -> Result<usize> {
            self.invalidated_sessions
                .write()
                .unwrap()
                .push((user_id.to_string(), except_session_id.map(String::from)));
            Ok(3) // Pretend we revoked 3 sessions
        }
    }

    fn create_test_hash(password: &str) -> String {
        let hasher = PasswordHasher::default();
        hasher.hash(password).unwrap()
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let store = TestStore::new();
        let old_hash = create_test_hash("OldPassword123!");
        store.add_user("user-1", &old_hash);

        let flow = PasswordChangeFlow::new(store);

        let result = flow
            .change_password(
                "user-1",
                PasswordChangeRequest {
                    current_password: "OldPassword123!".to_string(),
                    new_password: "NewSecurePassword456!".to_string(),
                },
                Some("session-123"),
            )
            .await;

        assert!(result.is_ok());

        // Verify sessions were invalidated
        let invalidated = flow.store.get_invalidated();
        assert_eq!(invalidated.len(), 1);
        assert_eq!(invalidated[0].0, "user-1");
        assert_eq!(invalidated[0].1, Some("session-123".to_string()));

        // Verify password was updated (can verify new password)
        let new_hash = flow
            .store
            .get_password_hash("user-1")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(new_hash, old_hash);

        let hasher = PasswordHasher::default();
        assert!(hasher.verify("NewSecurePassword456!", &new_hash).unwrap());
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let store = TestStore::new();
        store.add_user("user-1", &create_test_hash("OldPassword123!"));

        let flow = PasswordChangeFlow::new(store);

        let result = flow
            .change_password(
                "user-1",
                PasswordChangeRequest {
                    current_password: "WrongPassword!".to_string(),
                    new_password: "NewSecurePassword456!".to_string(),
                },
                None,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("incorrect"));
    }

    #[tokio::test]
    async fn test_change_password_weak_new_password() {
        let store = TestStore::new();
        store.add_user("user-1", &create_test_hash("OldPassword123!"));

        let flow = PasswordChangeFlow::new(store);

        let result = flow
            .change_password(
                "user-1",
                PasswordChangeRequest {
                    current_password: "OldPassword123!".to_string(),
                    new_password: "weak".to_string(),
                },
                None,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_change_password_same_password() {
        let store = TestStore::new();
        store.add_user("user-1", &create_test_hash("OldPassword123!"));

        let flow = PasswordChangeFlow::new(store);

        let result = flow
            .change_password(
                "user-1",
                PasswordChangeRequest {
                    current_password: "OldPassword123!".to_string(),
                    new_password: "OldPassword123!".to_string(),
                },
                None,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("different"));
    }

    #[tokio::test]
    async fn test_change_password_user_not_found() {
        let store = TestStore::new();
        let flow = PasswordChangeFlow::new(store);

        let result = flow
            .change_password(
                "nonexistent",
                PasswordChangeRequest {
                    current_password: "anything".to_string(),
                    new_password: "NewSecurePassword456!".to_string(),
                },
                None,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_change_password_without_session_invalidation() {
        let store = TestStore::new();
        store.add_user("user-1", &create_test_hash("OldPassword123!"));

        let flow = PasswordChangeFlow::new(store).without_session_invalidation();

        let result = flow
            .change_password(
                "user-1",
                PasswordChangeRequest {
                    current_password: "OldPassword123!".to_string(),
                    new_password: "NewSecurePassword456!".to_string(),
                },
                None,
            )
            .await;

        assert!(result.is_ok());

        // Sessions should NOT be invalidated
        let invalidated = flow.store.get_invalidated();
        assert!(invalidated.is_empty());
    }

    #[tokio::test]
    async fn test_custom_policy() {
        let store = TestStore::new();
        store.add_user("user-1", &create_test_hash("OldPassword123!"));

        // Use strict policy requiring special char
        let flow = PasswordChangeFlow::new(store).with_policy(PasswordPolicy::strict());

        let result = flow
            .change_password(
                "user-1",
                PasswordChangeRequest {
                    current_password: "OldPassword123!".to_string(),
                    new_password: "NewPasswordWithoutSpecial123".to_string(),
                },
                None,
            )
            .await;

        assert!(result.is_err());
    }
}
