//! Account deletion for GDPR compliance.
//!
//! Provides complete account deletion with cascading cleanup of all
//! user-related data (sessions, tokens, trusted devices, etc.).
//!
//! # Features
//!
//! - Cascading deletion of all user data
//! - Optional grace period for recovery
//! - Soft delete vs hard delete modes
//! - Password verification before deletion
//! - Email notifications
//! - Comprehensive audit logging
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::deletion::{AccountDeletionFlow, DeletionConfig, DeletionRequest};
//!
//! let flow = AccountDeletionFlow::new(store, DeletionConfig::default());
//!
//! // Request account deletion (with password verification)
//! flow.request_deletion(DeletionRequest {
//!     user_id: "user-123".to_string(),
//!     password: "current-password".to_string(),
//!     reason: Some("No longer using the service".to_string()),
//! }).await?;
//! ```

use crate::error::{Result, TidewayError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Default grace period (7 days).
const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Maximum length for deletion reason (prevent DoS).
const MAX_REASON_LENGTH: usize = 1000;

/// Configuration for account deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionConfig {
    /// Grace period before permanent deletion (None = immediate).
    pub grace_period: Option<Duration>,
    /// Whether to require password verification.
    pub require_password: bool,
    /// Whether to send confirmation email before deletion.
    pub send_confirmation_email: bool,
    /// Whether to send notification after deletion.
    pub send_deletion_email: bool,
    /// Whether to hard delete or soft delete (anonymize).
    pub hard_delete: bool,
}

impl Default for DeletionConfig {
    fn default() -> Self {
        Self {
            grace_period: Some(DEFAULT_GRACE_PERIOD),
            require_password: true,
            send_confirmation_email: true,
            send_deletion_email: true,
            hard_delete: false, // Soft delete by default (GDPR compliant)
        }
    }
}

impl DeletionConfig {
    /// Create a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a config for immediate hard deletion.
    #[must_use]
    pub fn immediate() -> Self {
        Self {
            grace_period: None,
            require_password: true,
            send_confirmation_email: false,
            send_deletion_email: true,
            hard_delete: true,
        }
    }

    /// Set the grace period before permanent deletion.
    #[must_use]
    pub fn grace_period(mut self, period: Option<Duration>) -> Self {
        self.grace_period = period;
        self
    }

    /// Set whether to require password verification.
    #[must_use]
    pub fn require_password(mut self, require: bool) -> Self {
        self.require_password = require;
        self
    }

    /// Set whether to send confirmation email.
    #[must_use]
    pub fn send_confirmation_email(mut self, send: bool) -> Self {
        self.send_confirmation_email = send;
        self
    }

    /// Set whether to send notification after deletion.
    #[must_use]
    pub fn send_deletion_email(mut self, send: bool) -> Self {
        self.send_deletion_email = send;
        self
    }

    /// Set whether to hard delete (true) or soft delete/anonymize (false).
    #[must_use]
    pub fn hard_delete(mut self, hard: bool) -> Self {
        self.hard_delete = hard;
        self
    }
}

/// Request to delete an account.
#[derive(Debug, Clone, Deserialize)]
pub struct DeletionRequest {
    /// The user's ID.
    pub user_id: String,
    /// The user's current password (for verification).
    pub password: Option<String>,
    /// Optional reason for deletion (for analytics).
    pub reason: Option<String>,
}

/// Result of a deletion request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status")]
pub enum DeletionResult {
    /// Deletion scheduled (grace period active).
    #[serde(rename = "scheduled")]
    Scheduled {
        /// When the account will be permanently deleted.
        scheduled_for: u64, // Unix timestamp
        /// Whether confirmation email was sent.
        confirmation_sent: bool,
    },
    /// Account deleted immediately.
    #[serde(rename = "deleted")]
    Deleted {
        /// Whether notification email was sent.
        notification_sent: bool,
    },
    /// Deletion cancelled (was scheduled).
    #[serde(rename = "cancelled")]
    Cancelled,
}

/// Status of a pending deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDeletion {
    /// User ID.
    pub user_id: String,
    /// When deletion was requested.
    pub requested_at: SystemTime,
    /// When the account will be deleted.
    pub scheduled_for: SystemTime,
    /// Reason provided by user.
    pub reason: Option<String>,
}

/// Statistics from cleanup operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupStats {
    /// Number of sessions revoked.
    pub sessions_revoked: usize,
    /// Number of refresh tokens revoked.
    pub refresh_tokens_revoked: usize,
    /// Number of trusted devices removed.
    pub trusted_devices_removed: usize,
    /// Number of MFA settings cleared.
    pub mfa_cleared: bool,
    /// Number of lockout states cleared.
    pub lockout_cleared: bool,
}

/// Trait for account deletion storage operations.
#[async_trait]
pub trait AccountDeletionStore: Send + Sync {
    /// Get the user's password hash for verification.
    async fn get_password_hash(&self, user_id: &str) -> Result<Option<String>>;

    /// Get the user's email for notifications.
    async fn get_user_email(&self, user_id: &str) -> Result<Option<String>>;

    /// Check if user exists.
    async fn user_exists(&self, user_id: &str) -> Result<bool>;

    /// Schedule account for deletion (grace period).
    async fn schedule_deletion(
        &self,
        user_id: &str,
        scheduled_for: SystemTime,
        reason: Option<&str>,
    ) -> Result<()>;

    /// Cancel a scheduled deletion.
    async fn cancel_deletion(&self, user_id: &str) -> Result<bool>;

    /// Get pending deletion status.
    async fn get_pending_deletion(&self, user_id: &str) -> Result<Option<PendingDeletion>>;

    /// Get all pending deletions that are due.
    async fn get_due_deletions(&self) -> Result<Vec<PendingDeletion>>;

    // Cleanup operations - all have default no-op implementations

    /// Revoke all sessions for the user.
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize> {
        let _ = user_id;
        Ok(0)
    }

    /// Revoke all refresh tokens for the user.
    async fn revoke_all_refresh_tokens(&self, user_id: &str) -> Result<usize> {
        let _ = user_id;
        Ok(0)
    }

    /// Remove all trusted devices for the user.
    async fn remove_all_trusted_devices(&self, user_id: &str) -> Result<usize> {
        let _ = user_id;
        Ok(0)
    }

    /// Clear MFA settings for the user.
    async fn clear_mfa(&self, user_id: &str) -> Result<bool> {
        let _ = user_id;
        Ok(false)
    }

    /// Clear lockout state for the user.
    async fn clear_lockout(&self, user_id: &str) -> Result<bool> {
        let _ = user_id;
        Ok(false)
    }

    /// Soft delete (anonymize) the user account.
    async fn soft_delete_user(&self, user_id: &str) -> Result<()>;

    /// Hard delete the user account.
    async fn hard_delete_user(&self, user_id: &str) -> Result<()>;

    /// Send deletion confirmation email (with cancellation link).
    async fn send_confirmation_email(
        &self,
        user_id: &str,
        email: &str,
        scheduled_for: SystemTime,
    ) -> Result<()> {
        let _ = (user_id, email, scheduled_for);
        Ok(())
    }

    /// Send deletion complete notification.
    async fn send_deletion_notification(&self, email: &str) -> Result<()> {
        let _ = email;
        Ok(())
    }
}

/// Flow for handling account deletion.
pub struct AccountDeletionFlow<S: AccountDeletionStore> {
    store: S,
    config: DeletionConfig,
    #[cfg(feature = "auth")]
    password_hasher: crate::auth::password::PasswordHasher,
}

impl<S: AccountDeletionStore> AccountDeletionFlow<S> {
    /// Create a new account deletion flow.
    #[must_use]
    pub fn new(store: S, config: DeletionConfig) -> Self {
        Self {
            store,
            config,
            #[cfg(feature = "auth")]
            password_hasher: crate::auth::password::PasswordHasher::default(),
        }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults(store: S) -> Self {
        Self::new(store, DeletionConfig::default())
    }

    /// Request account deletion.
    ///
    /// If a grace period is configured, schedules deletion for later.
    /// Otherwise, deletes immediately.
    #[cfg(feature = "auth")]
    pub async fn request_deletion(&self, req: DeletionRequest) -> Result<DeletionResult> {
        // Check user exists
        if !self.store.user_exists(&req.user_id).await? {
            tracing::warn!(
                target: "auth.deletion.user_not_found",
                user_id = %req.user_id,
                "Deletion requested for non-existent user"
            );
            return Err(TidewayError::NotFound("User not found".into()));
        }

        // Verify password if required
        if self.config.require_password {
            let password = req.password.as_ref().ok_or_else(|| {
                TidewayError::BadRequest("Password required for account deletion".into())
            })?;

            let hash = self
                .store
                .get_password_hash(&req.user_id)
                .await?
                .ok_or_else(|| TidewayError::NotFound("User not found".into()))?;

            if !self.password_hasher.verify(password, &hash)? {
                tracing::warn!(
                    target: "auth.deletion.password_invalid",
                    user_id = %req.user_id,
                    "Deletion rejected: invalid password"
                );
                return Err(TidewayError::Unauthorized("Invalid password".into()));
            }
        }

        // Truncate reason to prevent DoS
        let reason = req
            .reason
            .map(|r| truncate_string(&r, MAX_REASON_LENGTH));

        // If grace period, schedule deletion
        if let Some(grace_period) = self.config.grace_period {
            let now = SystemTime::now();
            let scheduled_for = now + grace_period;

            self.store
                .schedule_deletion(&req.user_id, scheduled_for, reason.as_deref())
                .await?;

            let mut confirmation_sent = false;

            // Send confirmation email
            if self.config.send_confirmation_email {
                if let Ok(Some(email)) = self.store.get_user_email(&req.user_id).await {
                    if self
                        .store
                        .send_confirmation_email(&req.user_id, &email, scheduled_for)
                        .await
                        .is_ok()
                    {
                        confirmation_sent = true;
                    }
                }
            }

            let scheduled_timestamp = scheduled_for
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            tracing::info!(
                target: "auth.deletion.scheduled",
                user_id = %req.user_id,
                scheduled_for = scheduled_timestamp,
                grace_period_days = grace_period.as_secs() / 86400,
                reason = reason.as_deref().unwrap_or("none"),
                "Account deletion scheduled"
            );

            return Ok(DeletionResult::Scheduled {
                scheduled_for: scheduled_timestamp,
                confirmation_sent,
            });
        }

        // Immediate deletion
        let result = self.execute_deletion(&req.user_id, reason.as_deref()).await?;

        Ok(DeletionResult::Deleted {
            notification_sent: result.notification_sent,
        })
    }

    #[cfg(not(feature = "auth"))]
    pub async fn request_deletion(&self, _req: DeletionRequest) -> Result<DeletionResult> {
        Err(TidewayError::Internal("auth feature not enabled".into()))
    }

    /// Cancel a scheduled deletion.
    pub async fn cancel_deletion(&self, user_id: &str) -> Result<DeletionResult> {
        let cancelled = self.store.cancel_deletion(user_id).await?;

        if cancelled {
            tracing::info!(
                target: "auth.deletion.cancelled",
                user_id = %user_id,
                "Account deletion cancelled"
            );
            Ok(DeletionResult::Cancelled)
        } else {
            tracing::debug!(
                target: "auth.deletion.cancel_not_found",
                user_id = %user_id,
                "No pending deletion to cancel"
            );
            Err(TidewayError::NotFound(
                "No pending deletion found".into(),
            ))
        }
    }

    /// Check if a user has a pending deletion.
    pub async fn get_pending_deletion(&self, user_id: &str) -> Result<Option<PendingDeletion>> {
        self.store.get_pending_deletion(user_id).await
    }

    /// Process all due deletions (call from scheduled job).
    pub async fn process_due_deletions(&self) -> Result<usize> {
        let due = self.store.get_due_deletions().await?;
        let count = due.len();

        for pending in due {
            if let Err(e) = self
                .execute_deletion(&pending.user_id, pending.reason.as_deref())
                .await
            {
                tracing::error!(
                    target: "auth.deletion.process_failed",
                    user_id = %pending.user_id,
                    error = %e,
                    "Failed to process scheduled deletion"
                );
            }
        }

        if count > 0 {
            tracing::info!(
                target: "auth.deletion.batch_processed",
                count = count,
                "Processed scheduled deletions"
            );
        }

        Ok(count)
    }

    /// Execute the actual deletion (cleanup + delete).
    async fn execute_deletion(
        &self,
        user_id: &str,
        reason: Option<&str>,
    ) -> Result<ExecutionResult> {
        // Get email before deletion for notification
        let email = self.store.get_user_email(user_id).await.ok().flatten();

        // Cleanup all related data
        let stats = self.cleanup_user_data(user_id).await?;

        // Delete user
        if self.config.hard_delete {
            self.store.hard_delete_user(user_id).await?;
        } else {
            self.store.soft_delete_user(user_id).await?;
        }

        let mut notification_sent = false;

        // Send deletion notification
        if self.config.send_deletion_email {
            if let Some(email) = &email {
                if self.store.send_deletion_notification(email).await.is_ok() {
                    notification_sent = true;
                }
            }
        }

        tracing::warn!(
            target: "auth.deletion.completed",
            user_id = %user_id,
            hard_delete = self.config.hard_delete,
            sessions_revoked = stats.sessions_revoked,
            refresh_tokens_revoked = stats.refresh_tokens_revoked,
            trusted_devices_removed = stats.trusted_devices_removed,
            reason = reason.unwrap_or("none"),
            "Account deletion completed"
        );

        Ok(ExecutionResult {
            stats,
            notification_sent,
        })
    }

    /// Cleanup all user-related data.
    async fn cleanup_user_data(&self, user_id: &str) -> Result<CleanupStats> {
        let sessions_revoked = self.store.revoke_all_sessions(user_id).await.unwrap_or(0);
        let refresh_tokens_revoked = self
            .store
            .revoke_all_refresh_tokens(user_id)
            .await
            .unwrap_or(0);
        let trusted_devices_removed = self
            .store
            .remove_all_trusted_devices(user_id)
            .await
            .unwrap_or(0);
        let mfa_cleared = self.store.clear_mfa(user_id).await.unwrap_or(false);
        let lockout_cleared = self.store.clear_lockout(user_id).await.unwrap_or(false);

        Ok(CleanupStats {
            sessions_revoked,
            refresh_tokens_revoked,
            trusted_devices_removed,
            mfa_cleared,
            lockout_cleared,
        })
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &DeletionConfig {
        &self.config
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
}

struct ExecutionResult {
    #[allow(dead_code)] // Used for logging in execute_deletion
    stats: CleanupStats,
    notification_sent: bool,
}

/// Truncate a string to a maximum length.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// In-memory store for testing.
#[cfg(any(test, feature = "test-auth-bypass"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// In-memory account deletion store for testing.
    #[derive(Default)]
    pub struct InMemoryDeletionStore {
        users: RwLock<HashMap<String, UserData>>,
        pending_deletions: RwLock<HashMap<String, PendingDeletion>>,
        emails_sent: RwLock<Vec<(String, String)>>, // (email, type)
    }

    #[derive(Clone)]
    struct UserData {
        email: String,
        password_hash: String,
        sessions: usize,
        refresh_tokens: usize,
        trusted_devices: usize,
        has_mfa: bool,
        has_lockout: bool,
        deleted: bool,
    }

    impl InMemoryDeletionStore {
        /// Create a new in-memory store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a test user.
        pub fn add_user(&self, user_id: &str, email: &str, password_hash: &str) {
            self.users.write().unwrap().insert(
                user_id.to_string(),
                UserData {
                    email: email.to_string(),
                    password_hash: password_hash.to_string(),
                    sessions: 3,
                    refresh_tokens: 2,
                    trusted_devices: 1,
                    has_mfa: true,
                    has_lockout: false,
                    deleted: false,
                },
            );
        }

        /// Check if user was deleted.
        pub fn is_deleted(&self, user_id: &str) -> bool {
            self.users
                .read()
                .unwrap()
                .get(user_id)
                .map(|u| u.deleted)
                .unwrap_or(false)
        }

        /// Check if user was hard deleted (removed from store).
        pub fn is_hard_deleted(&self, user_id: &str) -> bool {
            !self.users.read().unwrap().contains_key(user_id)
        }

        /// Get sent emails.
        pub fn get_emails_sent(&self) -> Vec<(String, String)> {
            self.emails_sent.read().unwrap().clone()
        }
    }

    #[async_trait]
    impl AccountDeletionStore for InMemoryDeletionStore {
        async fn get_password_hash(&self, user_id: &str) -> Result<Option<String>> {
            Ok(self
                .users
                .read()
                .unwrap()
                .get(user_id)
                .map(|u| u.password_hash.clone()))
        }

        async fn get_user_email(&self, user_id: &str) -> Result<Option<String>> {
            Ok(self
                .users
                .read()
                .unwrap()
                .get(user_id)
                .map(|u| u.email.clone()))
        }

        async fn user_exists(&self, user_id: &str) -> Result<bool> {
            let users = self.users.read().unwrap();
            Ok(users.get(user_id).map(|u| !u.deleted).unwrap_or(false))
        }

        async fn schedule_deletion(
            &self,
            user_id: &str,
            scheduled_for: SystemTime,
            reason: Option<&str>,
        ) -> Result<()> {
            self.pending_deletions.write().unwrap().insert(
                user_id.to_string(),
                PendingDeletion {
                    user_id: user_id.to_string(),
                    requested_at: SystemTime::now(),
                    scheduled_for,
                    reason: reason.map(String::from),
                },
            );
            Ok(())
        }

        async fn cancel_deletion(&self, user_id: &str) -> Result<bool> {
            Ok(self
                .pending_deletions
                .write()
                .unwrap()
                .remove(user_id)
                .is_some())
        }

        async fn get_pending_deletion(&self, user_id: &str) -> Result<Option<PendingDeletion>> {
            Ok(self
                .pending_deletions
                .read()
                .unwrap()
                .get(user_id)
                .cloned())
        }

        async fn get_due_deletions(&self) -> Result<Vec<PendingDeletion>> {
            let now = SystemTime::now();
            Ok(self
                .pending_deletions
                .read()
                .unwrap()
                .values()
                .filter(|p| p.scheduled_for <= now)
                .cloned()
                .collect())
        }

        async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize> {
            let mut users = self.users.write().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                let count = user.sessions;
                user.sessions = 0;
                return Ok(count);
            }
            Ok(0)
        }

        async fn revoke_all_refresh_tokens(&self, user_id: &str) -> Result<usize> {
            let mut users = self.users.write().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                let count = user.refresh_tokens;
                user.refresh_tokens = 0;
                return Ok(count);
            }
            Ok(0)
        }

        async fn remove_all_trusted_devices(&self, user_id: &str) -> Result<usize> {
            let mut users = self.users.write().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                let count = user.trusted_devices;
                user.trusted_devices = 0;
                return Ok(count);
            }
            Ok(0)
        }

        async fn clear_mfa(&self, user_id: &str) -> Result<bool> {
            let mut users = self.users.write().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                let had = user.has_mfa;
                user.has_mfa = false;
                return Ok(had);
            }
            Ok(false)
        }

        async fn clear_lockout(&self, user_id: &str) -> Result<bool> {
            let mut users = self.users.write().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                let had = user.has_lockout;
                user.has_lockout = false;
                return Ok(had);
            }
            Ok(false)
        }

        async fn soft_delete_user(&self, user_id: &str) -> Result<()> {
            let mut users = self.users.write().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                user.deleted = true;
                user.email = format!("deleted-{}", user_id);
            }
            // Also remove from pending deletions
            self.pending_deletions.write().unwrap().remove(user_id);
            Ok(())
        }

        async fn hard_delete_user(&self, user_id: &str) -> Result<()> {
            self.users.write().unwrap().remove(user_id);
            self.pending_deletions.write().unwrap().remove(user_id);
            Ok(())
        }

        async fn send_confirmation_email(
            &self,
            _user_id: &str,
            email: &str,
            _scheduled_for: SystemTime,
        ) -> Result<()> {
            self.emails_sent
                .write()
                .unwrap()
                .push((email.to_string(), "confirmation".to_string()));
            Ok(())
        }

        async fn send_deletion_notification(&self, email: &str) -> Result<()> {
            self.emails_sent
                .write()
                .unwrap()
                .push((email.to_string(), "deleted".to_string()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::InMemoryDeletionStore;

    fn create_test_hash(password: &str) -> String {
        #[cfg(feature = "auth")]
        {
            use crate::auth::password::PasswordHasher;
            PasswordHasher::default().hash(password).unwrap()
        }
        #[cfg(not(feature = "auth"))]
        {
            let _ = password;
            "hash".to_string()
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = DeletionConfig::new();
        assert!(config.grace_period.is_some());
        assert!(config.require_password);
        assert!(config.send_confirmation_email);
        assert!(config.send_deletion_email);
        assert!(!config.hard_delete);
    }

    #[test]
    fn test_config_immediate() {
        let config = DeletionConfig::immediate();
        assert!(config.grace_period.is_none());
        assert!(config.require_password);
        assert!(!config.send_confirmation_email);
        assert!(config.send_deletion_email);
        assert!(config.hard_delete);
    }

    #[test]
    fn test_config_builder() {
        let config = DeletionConfig::new()
            .grace_period(None)
            .require_password(false)
            .hard_delete(true);

        assert!(config.grace_period.is_none());
        assert!(!config.require_password);
        assert!(config.hard_delete);
    }

    #[tokio::test]
    async fn test_scheduled_deletion() {
        let store = InMemoryDeletionStore::new();
        store.add_user("user-1", "user@example.com", &create_test_hash("password123"));

        let config = DeletionConfig::new()
            .grace_period(Some(Duration::from_secs(86400)))
            .require_password(false);

        let flow = AccountDeletionFlow::new(store, config);

        let result = flow
            .request_deletion(DeletionRequest {
                user_id: "user-1".to_string(),
                password: None,
                reason: Some("Testing".to_string()),
            })
            .await
            .unwrap();

        match result {
            DeletionResult::Scheduled {
                scheduled_for,
                confirmation_sent,
            } => {
                assert!(scheduled_for > 0);
                assert!(confirmation_sent);
            }
            _ => panic!("Expected Scheduled result"),
        }

        // User should still exist
        assert!(!flow.store.is_deleted("user-1"));

        // Should have pending deletion
        let pending = flow.get_pending_deletion("user-1").await.unwrap();
        assert!(pending.is_some());
    }

    #[tokio::test]
    async fn test_immediate_soft_deletion() {
        let store = InMemoryDeletionStore::new();
        store.add_user("user-1", "user@example.com", &create_test_hash("password123"));

        let config = DeletionConfig::new()
            .grace_period(None)
            .require_password(false)
            .hard_delete(false);

        let flow = AccountDeletionFlow::new(store, config);

        let result = flow
            .request_deletion(DeletionRequest {
                user_id: "user-1".to_string(),
                password: None,
                reason: None,
            })
            .await
            .unwrap();

        match result {
            DeletionResult::Deleted { notification_sent } => {
                assert!(notification_sent);
            }
            _ => panic!("Expected Deleted result"),
        }

        // User should be soft deleted
        assert!(flow.store.is_deleted("user-1"));
        assert!(!flow.store.is_hard_deleted("user-1"));
    }

    #[tokio::test]
    async fn test_immediate_hard_deletion() {
        let store = InMemoryDeletionStore::new();
        store.add_user("user-1", "user@example.com", &create_test_hash("password123"));

        let config = DeletionConfig::immediate().require_password(false);

        let flow = AccountDeletionFlow::new(store, config);

        flow.request_deletion(DeletionRequest {
            user_id: "user-1".to_string(),
            password: None,
            reason: None,
        })
        .await
        .unwrap();

        // User should be hard deleted
        assert!(flow.store.is_hard_deleted("user-1"));
    }

    #[tokio::test]
    async fn test_password_verification() {
        let store = InMemoryDeletionStore::new();
        store.add_user("user-1", "user@example.com", &create_test_hash("correct-password"));

        let config = DeletionConfig::immediate(); // require_password is true

        let flow = AccountDeletionFlow::new(store, config);

        // Wrong password should fail
        let result = flow
            .request_deletion(DeletionRequest {
                user_id: "user-1".to_string(),
                password: Some("wrong-password".to_string()),
                reason: None,
            })
            .await;

        assert!(result.is_err());
        assert!(!flow.store.is_deleted("user-1"));

        // Correct password should work
        let result = flow
            .request_deletion(DeletionRequest {
                user_id: "user-1".to_string(),
                password: Some("correct-password".to_string()),
                reason: None,
            })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cancel_deletion() {
        let store = InMemoryDeletionStore::new();
        store.add_user("user-1", "user@example.com", &create_test_hash("password123"));

        let config = DeletionConfig::new()
            .grace_period(Some(Duration::from_secs(86400)))
            .require_password(false);

        let flow = AccountDeletionFlow::new(store, config);

        // Schedule deletion
        flow.request_deletion(DeletionRequest {
            user_id: "user-1".to_string(),
            password: None,
            reason: None,
        })
        .await
        .unwrap();

        // Cancel it
        let result = flow.cancel_deletion("user-1").await.unwrap();
        assert_eq!(result, DeletionResult::Cancelled);

        // Should have no pending deletion
        let pending = flow.get_pending_deletion("user-1").await.unwrap();
        assert!(pending.is_none());
    }

    #[tokio::test]
    async fn test_nonexistent_user() {
        let store = InMemoryDeletionStore::new();
        let config = DeletionConfig::immediate().require_password(false);
        let flow = AccountDeletionFlow::new(store, config);

        let result = flow
            .request_deletion(DeletionRequest {
                user_id: "nonexistent".to_string(),
                password: None,
                reason: None,
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_emails_sent() {
        let store = InMemoryDeletionStore::new();
        store.add_user("user-1", "user@example.com", &create_test_hash("password123"));

        let config = DeletionConfig::immediate().require_password(false);

        let flow = AccountDeletionFlow::new(store, config);

        flow.request_deletion(DeletionRequest {
            user_id: "user-1".to_string(),
            password: None,
            reason: None,
        })
        .await
        .unwrap();

        let emails = flow.store.get_emails_sent();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].0, "user@example.com");
        assert_eq!(emails[0].1, "deleted");
    }
}
