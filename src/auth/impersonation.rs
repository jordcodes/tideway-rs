//! Admin impersonation for user support.
//!
//! Allows authorized administrators to temporarily act as another user
//! for debugging and support purposes, with full audit logging.
//!
//! # Features
//!
//! - Time-limited impersonation sessions
//! - Full audit trail of all impersonation activity
//! - Configurable restrictions (block destructive actions)
//! - User notification on impersonation
//! - Easy detection via token claims for UI indicators
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::impersonation::{ImpersonationManager, ImpersonationConfig};
//!
//! let manager = ImpersonationManager::new(store, ImpersonationConfig::default());
//!
//! // Admin starts impersonating a user
//! let session = manager.start_impersonation(
//!     "admin-123",      // Admin user ID
//!     "user-456",       // Target user ID
//!     Some("Support ticket #789"),
//! ).await?;
//!
//! // Issue tokens with impersonation claims
//! // The access token will include impersonation info for UI detection
//!
//! // End impersonation
//! manager.end_impersonation(&session.session_id).await?;
//! ```

use crate::error::{Result, TidewayError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Default maximum impersonation duration (1 hour).
const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(60 * 60);

/// Maximum length for impersonation reason (prevent DoS).
const MAX_REASON_LENGTH: usize = 500;

/// Configuration for impersonation behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpersonationConfig {
    /// Maximum duration for an impersonation session.
    pub max_duration: Duration,
    /// Whether to notify the user when impersonation starts.
    pub notify_user: bool,
    /// Whether to notify the user when impersonation ends.
    pub notify_on_end: bool,
    /// Whether admins can impersonate other admins.
    pub allow_admin_impersonation: bool,
    /// Actions blocked during impersonation.
    pub blocked_actions: Vec<BlockedAction>,
    /// Require a reason for impersonation.
    pub require_reason: bool,
}

impl Default for ImpersonationConfig {
    fn default() -> Self {
        Self {
            max_duration: DEFAULT_MAX_DURATION,
            notify_user: false,
            notify_on_end: false,
            allow_admin_impersonation: false,
            blocked_actions: vec![
                BlockedAction::DeleteAccount,
                BlockedAction::ChangePassword,
                BlockedAction::ChangeMfa,
                BlockedAction::ChangeEmail,
            ],
            require_reason: true,
        }
    }
}

impl ImpersonationConfig {
    /// Create a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict config (notify user, all destructive actions blocked).
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_duration: Duration::from_secs(30 * 60), // 30 minutes
            notify_user: true,
            notify_on_end: true,
            allow_admin_impersonation: false,
            blocked_actions: vec![
                BlockedAction::DeleteAccount,
                BlockedAction::ChangePassword,
                BlockedAction::ChangeMfa,
                BlockedAction::ChangeEmail,
                BlockedAction::ModifyBilling,
                BlockedAction::ExportData,
            ],
            require_reason: true,
        }
    }

    /// Create a permissive config (for internal tools).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_duration: Duration::from_secs(4 * 60 * 60), // 4 hours
            notify_user: false,
            notify_on_end: false,
            allow_admin_impersonation: false,
            blocked_actions: vec![BlockedAction::DeleteAccount],
            require_reason: false,
        }
    }

    /// Set the maximum duration for impersonation sessions.
    #[must_use]
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = duration;
        self
    }

    /// Set whether to notify the user when impersonation starts.
    #[must_use]
    pub fn notify_user(mut self, notify: bool) -> Self {
        self.notify_user = notify;
        self
    }

    /// Set whether to notify the user when impersonation ends.
    #[must_use]
    pub fn notify_on_end(mut self, notify: bool) -> Self {
        self.notify_on_end = notify;
        self
    }

    /// Set whether admins can impersonate other admins.
    #[must_use]
    pub fn allow_admin_impersonation(mut self, allow: bool) -> Self {
        self.allow_admin_impersonation = allow;
        self
    }

    /// Set actions blocked during impersonation.
    #[must_use]
    pub fn blocked_actions(mut self, actions: Vec<BlockedAction>) -> Self {
        self.blocked_actions = actions;
        self
    }

    /// Set whether a reason is required for impersonation.
    #[must_use]
    pub fn require_reason(mut self, require: bool) -> Self {
        self.require_reason = require;
        self
    }
}

/// Actions that can be blocked during impersonation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedAction {
    /// Deleting the user's account.
    DeleteAccount,
    /// Changing the user's password.
    ChangePassword,
    /// Modifying MFA settings.
    ChangeMfa,
    /// Changing the user's email.
    ChangeEmail,
    /// Modifying billing/payment info.
    ModifyBilling,
    /// Exporting user data.
    ExportData,
    /// Making purchases.
    MakePurchase,
    /// Sending messages as the user.
    SendMessages,
    /// Custom blocked action.
    Custom(String),
}

impl BlockedAction {
    /// Check if an action string matches this blocked action.
    #[must_use]
    pub fn matches(&self, action: &str) -> bool {
        match self {
            Self::DeleteAccount => action == "delete_account",
            Self::ChangePassword => action == "change_password",
            Self::ChangeMfa => action == "change_mfa",
            Self::ChangeEmail => action == "change_email",
            Self::ModifyBilling => action == "modify_billing",
            Self::ExportData => action == "export_data",
            Self::MakePurchase => action == "make_purchase",
            Self::SendMessages => action == "send_messages",
            Self::Custom(s) => action == s,
        }
    }
}

/// Request to start impersonation.
#[derive(Debug, Clone, Deserialize)]
pub struct ImpersonationRequest {
    /// The admin user ID.
    pub admin_id: String,
    /// The target user ID to impersonate.
    pub target_user_id: String,
    /// Reason for impersonation (e.g., support ticket).
    pub reason: Option<String>,
    /// Custom duration (if different from config default).
    pub duration: Option<Duration>,
}

/// An active impersonation session.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImpersonationSession {
    /// Unique session ID.
    pub session_id: String,
    /// The admin performing impersonation.
    pub admin_id: String,
    /// The user being impersonated.
    pub target_user_id: String,
    /// Reason for impersonation.
    pub reason: Option<String>,
    /// When impersonation started.
    pub started_at: u64,
    /// When impersonation expires.
    pub expires_at: u64,
    /// Actions blocked during this session.
    pub blocked_actions: Vec<BlockedAction>,
}

impl ImpersonationSession {
    /// Check if this session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now >= self.expires_at
    }

    /// Check if an action is blocked in this session.
    #[must_use]
    pub fn is_action_blocked(&self, action: &str) -> bool {
        self.blocked_actions.iter().any(|b| b.matches(action))
    }

    /// Get remaining duration in seconds.
    #[must_use]
    pub fn remaining_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at.saturating_sub(now)
    }
}

/// Claims to include in tokens during impersonation.
///
/// Include these in your JWT to enable impersonation detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpersonationClaims {
    /// The impersonation session ID.
    pub imp_session: String,
    /// The admin performing impersonation.
    pub imp_admin: String,
    /// Actions blocked during impersonation.
    pub imp_blocked: Vec<String>,
}

impl ImpersonationClaims {
    /// Create claims from a session.
    #[must_use]
    pub fn from_session(session: &ImpersonationSession) -> Self {
        Self {
            imp_session: session.session_id.clone(),
            imp_admin: session.admin_id.clone(),
            imp_blocked: session
                .blocked_actions
                .iter()
                .map(|a| format!("{a:?}").to_lowercase())
                .collect(),
        }
    }
}

/// Audit log entry for impersonation events.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImpersonationAuditEntry {
    /// Event type.
    pub event: ImpersonationEvent,
    /// Session ID.
    pub session_id: String,
    /// Admin user ID.
    pub admin_id: String,
    /// Target user ID.
    pub target_user_id: String,
    /// Reason for impersonation.
    pub reason: Option<String>,
    /// Event timestamp.
    pub timestamp: u64,
    /// Additional metadata.
    pub metadata: Option<String>,
}

/// Types of impersonation events.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImpersonationEvent {
    /// Impersonation started.
    Started,
    /// Impersonation ended normally.
    Ended,
    /// Impersonation expired.
    Expired,
    /// Blocked action attempted.
    BlockedAttempt,
    /// Impersonation was extended.
    Extended,
}

/// Trait for impersonation storage operations.
#[async_trait]
pub trait ImpersonationStore: Send + Sync {
    /// Check if a user is an admin who can impersonate.
    async fn is_admin(&self, user_id: &str) -> Result<bool>;

    /// Check if a target user can be impersonated.
    ///
    /// Returns false if the user is an admin (unless config allows).
    async fn can_be_impersonated(&self, user_id: &str) -> Result<bool>;

    /// Get the target user's email for notifications.
    async fn get_user_email(&self, user_id: &str) -> Result<Option<String>>;

    /// Check if user exists.
    async fn user_exists(&self, user_id: &str) -> Result<bool>;

    /// Store a new impersonation session.
    async fn create_session(&self, session: &ImpersonationSession) -> Result<()>;

    /// Get an active impersonation session by ID.
    async fn get_session(&self, session_id: &str) -> Result<Option<ImpersonationSession>>;

    /// Get active impersonation session for a target user.
    async fn get_session_for_user(&self, target_user_id: &str)
        -> Result<Option<ImpersonationSession>>;

    /// Get all active sessions by an admin.
    async fn get_sessions_by_admin(&self, admin_id: &str) -> Result<Vec<ImpersonationSession>>;

    /// End an impersonation session.
    async fn end_session(&self, session_id: &str) -> Result<bool>;

    /// End all impersonation sessions for a target user.
    async fn end_sessions_for_user(&self, target_user_id: &str) -> Result<usize>;

    /// Record an audit log entry.
    async fn record_audit(&self, entry: &ImpersonationAuditEntry) -> Result<()>;

    /// Get audit log for a user (as target or admin).
    async fn get_audit_log(
        &self,
        user_id: &str,
        limit: usize,
    ) -> Result<Vec<ImpersonationAuditEntry>>;

    /// Send notification email to user about impersonation.
    async fn send_notification(
        &self,
        email: &str,
        admin_id: &str,
        event: &ImpersonationEvent,
    ) -> Result<()> {
        let _ = (email, admin_id, event);
        Ok(())
    }
}

/// Manager for impersonation operations.
pub struct ImpersonationManager<S: ImpersonationStore> {
    store: S,
    config: ImpersonationConfig,
}

impl<S: ImpersonationStore> ImpersonationManager<S> {
    /// Create a new impersonation manager.
    #[must_use]
    pub fn new(store: S, config: ImpersonationConfig) -> Self {
        Self { store, config }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults(store: S) -> Self {
        Self::new(store, ImpersonationConfig::default())
    }

    /// Start an impersonation session.
    pub async fn start_impersonation(
        &self,
        req: ImpersonationRequest,
    ) -> Result<ImpersonationSession> {
        // Validate reason requirement
        if self.config.require_reason && req.reason.is_none() {
            tracing::warn!(
                target: "auth.impersonation.rejected",
                admin_id = %req.admin_id,
                target_user_id = %req.target_user_id,
                reason = "no_reason_provided",
                "Impersonation rejected: reason required"
            );
            return Err(TidewayError::BadRequest(
                "Reason required for impersonation".into(),
            ));
        }

        // Check admin permissions
        if !self.store.is_admin(&req.admin_id).await? {
            tracing::warn!(
                target: "auth.impersonation.rejected",
                admin_id = %req.admin_id,
                target_user_id = %req.target_user_id,
                reason = "not_admin",
                "Impersonation rejected: user is not an admin"
            );
            return Err(TidewayError::Forbidden(
                "Only admins can impersonate users".into(),
            ));
        }

        // Check target user exists
        if !self.store.user_exists(&req.target_user_id).await? {
            tracing::warn!(
                target: "auth.impersonation.rejected",
                admin_id = %req.admin_id,
                target_user_id = %req.target_user_id,
                reason = "user_not_found",
                "Impersonation rejected: target user not found"
            );
            return Err(TidewayError::NotFound("Target user not found".into()));
        }

        // Check if target can be impersonated
        if !self.store.can_be_impersonated(&req.target_user_id).await?
            && !self.config.allow_admin_impersonation
        {
            tracing::warn!(
                target: "auth.impersonation.rejected",
                admin_id = %req.admin_id,
                target_user_id = %req.target_user_id,
                reason = "target_is_admin",
                "Impersonation rejected: cannot impersonate admin"
            );
            return Err(TidewayError::Forbidden(
                "Cannot impersonate admin users".into(),
            ));
        }

        // Cannot impersonate self
        if req.admin_id == req.target_user_id {
            tracing::warn!(
                target: "auth.impersonation.rejected",
                admin_id = %req.admin_id,
                reason = "self_impersonation",
                "Impersonation rejected: cannot impersonate self"
            );
            return Err(TidewayError::BadRequest(
                "Cannot impersonate yourself".into(),
            ));
        }

        // Check for existing session
        if let Some(existing) = self
            .store
            .get_session_for_user(&req.target_user_id)
            .await?
        {
            if !existing.is_expired() {
                tracing::warn!(
                    target: "auth.impersonation.rejected",
                    admin_id = %req.admin_id,
                    target_user_id = %req.target_user_id,
                    existing_admin = %existing.admin_id,
                    reason = "already_impersonated",
                    "Impersonation rejected: user already being impersonated"
                );
                return Err(TidewayError::BadRequest(
                    "User is already being impersonated".into(),
                ));
            }
        }

        // Calculate duration
        let duration = req.duration.unwrap_or(self.config.max_duration);
        let actual_duration = duration.min(self.config.max_duration);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Truncate reason
        let reason = req.reason.map(|r| truncate_string(&r, MAX_REASON_LENGTH));

        // Create session
        let session = ImpersonationSession {
            session_id: generate_session_id(),
            admin_id: req.admin_id.clone(),
            target_user_id: req.target_user_id.clone(),
            reason: reason.clone(),
            started_at: now,
            expires_at: now + actual_duration.as_secs(),
            blocked_actions: self.config.blocked_actions.clone(),
        };

        self.store.create_session(&session).await?;

        // Record audit
        let audit = ImpersonationAuditEntry {
            event: ImpersonationEvent::Started,
            session_id: session.session_id.clone(),
            admin_id: req.admin_id.clone(),
            target_user_id: req.target_user_id.clone(),
            reason: reason.clone(),
            timestamp: now,
            metadata: None,
        };
        self.store.record_audit(&audit).await?;

        // Notify user if configured
        if self.config.notify_user {
            if let Ok(Some(email)) = self.store.get_user_email(&req.target_user_id).await {
                let _ = self
                    .store
                    .send_notification(&email, &req.admin_id, &ImpersonationEvent::Started)
                    .await;
            }
        }

        tracing::info!(
            target: "auth.impersonation.started",
            session_id = %session.session_id,
            admin_id = %req.admin_id,
            target_user_id = %req.target_user_id,
            duration_secs = actual_duration.as_secs(),
            reason = reason.as_deref().unwrap_or("none"),
            "Impersonation session started"
        );

        Ok(session)
    }

    /// End an impersonation session.
    pub async fn end_impersonation(&self, session_id: &str) -> Result<()> {
        let session = self
            .store
            .get_session(session_id)
            .await?
            .ok_or_else(|| TidewayError::NotFound("Impersonation session not found".into()))?;

        self.store.end_session(session_id).await?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Record audit
        let audit = ImpersonationAuditEntry {
            event: ImpersonationEvent::Ended,
            session_id: session_id.to_string(),
            admin_id: session.admin_id.clone(),
            target_user_id: session.target_user_id.clone(),
            reason: session.reason.clone(),
            timestamp: now,
            metadata: None,
        };
        self.store.record_audit(&audit).await?;

        // Notify user if configured
        if self.config.notify_on_end {
            if let Ok(Some(email)) = self.store.get_user_email(&session.target_user_id).await {
                let _ = self
                    .store
                    .send_notification(&email, &session.admin_id, &ImpersonationEvent::Ended)
                    .await;
            }
        }

        tracing::info!(
            target: "auth.impersonation.ended",
            session_id = %session_id,
            admin_id = %session.admin_id,
            target_user_id = %session.target_user_id,
            "Impersonation session ended"
        );

        Ok(())
    }

    /// Validate an impersonation session and check if action is allowed.
    pub async fn validate_session(
        &self,
        session_id: &str,
        action: Option<&str>,
    ) -> Result<ImpersonationSession> {
        let session = self
            .store
            .get_session(session_id)
            .await?
            .ok_or_else(|| TidewayError::NotFound("Impersonation session not found".into()))?;

        if session.is_expired() {
            // Clean up expired session
            self.store.end_session(session_id).await?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let audit = ImpersonationAuditEntry {
                event: ImpersonationEvent::Expired,
                session_id: session_id.to_string(),
                admin_id: session.admin_id.clone(),
                target_user_id: session.target_user_id.clone(),
                reason: session.reason.clone(),
                timestamp: now,
                metadata: None,
            };
            self.store.record_audit(&audit).await?;

            tracing::info!(
                target: "auth.impersonation.expired",
                session_id = %session_id,
                admin_id = %session.admin_id,
                target_user_id = %session.target_user_id,
                "Impersonation session expired"
            );

            return Err(TidewayError::Unauthorized(
                "Impersonation session expired".into(),
            ));
        }

        // Check if action is blocked
        if let Some(action) = action {
            if session.is_action_blocked(action) {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let audit = ImpersonationAuditEntry {
                    event: ImpersonationEvent::BlockedAttempt,
                    session_id: session_id.to_string(),
                    admin_id: session.admin_id.clone(),
                    target_user_id: session.target_user_id.clone(),
                    reason: session.reason.clone(),
                    timestamp: now,
                    metadata: Some(format!("Attempted action: {action}")),
                };
                self.store.record_audit(&audit).await?;

                tracing::warn!(
                    target: "auth.impersonation.blocked",
                    session_id = %session_id,
                    admin_id = %session.admin_id,
                    target_user_id = %session.target_user_id,
                    action = %action,
                    "Blocked action attempted during impersonation"
                );

                return Err(TidewayError::Forbidden(format!(
                    "Action '{action}' is not allowed during impersonation"
                )));
            }
        }

        Ok(session)
    }

    /// Get active session for a user (if being impersonated).
    pub async fn get_active_session(
        &self,
        target_user_id: &str,
    ) -> Result<Option<ImpersonationSession>> {
        let session = self.store.get_session_for_user(target_user_id).await?;

        // Filter out expired sessions
        Ok(session.filter(|s| !s.is_expired()))
    }

    /// Get all active sessions by an admin.
    pub async fn get_admin_sessions(&self, admin_id: &str) -> Result<Vec<ImpersonationSession>> {
        let sessions = self.store.get_sessions_by_admin(admin_id).await?;

        // Filter out expired sessions
        Ok(sessions.into_iter().filter(|s| !s.is_expired()).collect())
    }

    /// End all impersonation sessions for a user.
    pub async fn end_all_for_user(&self, target_user_id: &str) -> Result<usize> {
        let count = self.store.end_sessions_for_user(target_user_id).await?;

        if count > 0 {
            tracing::info!(
                target: "auth.impersonation.bulk_ended",
                target_user_id = %target_user_id,
                count = count,
                "Ended all impersonation sessions for user"
            );
        }

        Ok(count)
    }

    /// Get audit log for a user.
    pub async fn get_audit_log(
        &self,
        user_id: &str,
        limit: usize,
    ) -> Result<Vec<ImpersonationAuditEntry>> {
        self.store.get_audit_log(user_id, limit).await
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &ImpersonationConfig {
        &self.config
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// Generate a unique session ID.
fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Simple unique ID using timestamp + random suffix
    format!("imp_{timestamp:x}_{:x}", random_u64())
}

/// Generate a random u64 for session IDs.
fn random_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    RandomState::new().build_hasher().finish()
}

/// Truncate a string to a maximum length (UTF-8 safe).
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
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

    /// In-memory impersonation store for testing.
    #[derive(Default)]
    pub struct InMemoryImpersonationStore {
        admins: RwLock<Vec<String>>,
        users: RwLock<HashMap<String, UserData>>,
        sessions: RwLock<HashMap<String, ImpersonationSession>>,
        audit_log: RwLock<Vec<ImpersonationAuditEntry>>,
        notifications: RwLock<Vec<(String, String, ImpersonationEvent)>>,
    }

    #[derive(Clone)]
    struct UserData {
        email: String,
        is_admin: bool,
    }

    impl InMemoryImpersonationStore {
        /// Create a new in-memory store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a regular user.
        pub fn add_user(&self, user_id: &str, email: &str) {
            self.users.write().unwrap().insert(
                user_id.to_string(),
                UserData {
                    email: email.to_string(),
                    is_admin: false,
                },
            );
        }

        /// Add an admin user.
        pub fn add_admin(&self, user_id: &str, email: &str) {
            self.users.write().unwrap().insert(
                user_id.to_string(),
                UserData {
                    email: email.to_string(),
                    is_admin: true,
                },
            );
            self.admins.write().unwrap().push(user_id.to_string());
        }

        /// Get notifications sent.
        pub fn get_notifications(&self) -> Vec<(String, String, ImpersonationEvent)> {
            self.notifications.read().unwrap().clone()
        }

        /// Get all audit entries.
        pub fn get_all_audit(&self) -> Vec<ImpersonationAuditEntry> {
            self.audit_log.read().unwrap().clone()
        }
    }

    #[async_trait]
    impl ImpersonationStore for InMemoryImpersonationStore {
        async fn is_admin(&self, user_id: &str) -> Result<bool> {
            Ok(self.admins.read().unwrap().contains(&user_id.to_string()))
        }

        async fn can_be_impersonated(&self, user_id: &str) -> Result<bool> {
            // Regular users can be impersonated, admins cannot by default
            Ok(self
                .users
                .read()
                .unwrap()
                .get(user_id)
                .map(|u| !u.is_admin)
                .unwrap_or(false))
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
            Ok(self.users.read().unwrap().contains_key(user_id))
        }

        async fn create_session(&self, session: &ImpersonationSession) -> Result<()> {
            self.sessions
                .write()
                .unwrap()
                .insert(session.session_id.clone(), session.clone());
            Ok(())
        }

        async fn get_session(&self, session_id: &str) -> Result<Option<ImpersonationSession>> {
            Ok(self.sessions.read().unwrap().get(session_id).cloned())
        }

        async fn get_session_for_user(
            &self,
            target_user_id: &str,
        ) -> Result<Option<ImpersonationSession>> {
            Ok(self
                .sessions
                .read()
                .unwrap()
                .values()
                .find(|s| s.target_user_id == target_user_id)
                .cloned())
        }

        async fn get_sessions_by_admin(&self, admin_id: &str) -> Result<Vec<ImpersonationSession>> {
            Ok(self
                .sessions
                .read()
                .unwrap()
                .values()
                .filter(|s| s.admin_id == admin_id)
                .cloned()
                .collect())
        }

        async fn end_session(&self, session_id: &str) -> Result<bool> {
            Ok(self
                .sessions
                .write()
                .unwrap()
                .remove(session_id)
                .is_some())
        }

        async fn end_sessions_for_user(&self, target_user_id: &str) -> Result<usize> {
            let mut sessions = self.sessions.write().unwrap();
            let to_remove: Vec<_> = sessions
                .iter()
                .filter(|(_, s)| s.target_user_id == target_user_id)
                .map(|(id, _)| id.clone())
                .collect();

            let count = to_remove.len();
            for id in to_remove {
                sessions.remove(&id);
            }
            Ok(count)
        }

        async fn record_audit(&self, entry: &ImpersonationAuditEntry) -> Result<()> {
            self.audit_log.write().unwrap().push(entry.clone());
            Ok(())
        }

        async fn get_audit_log(
            &self,
            user_id: &str,
            limit: usize,
        ) -> Result<Vec<ImpersonationAuditEntry>> {
            Ok(self
                .audit_log
                .read()
                .unwrap()
                .iter()
                .filter(|e| e.admin_id == user_id || e.target_user_id == user_id)
                .take(limit)
                .cloned()
                .collect())
        }

        async fn send_notification(
            &self,
            email: &str,
            admin_id: &str,
            event: &ImpersonationEvent,
        ) -> Result<()> {
            self.notifications.write().unwrap().push((
                email.to_string(),
                admin_id.to_string(),
                event.clone(),
            ));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::InMemoryImpersonationStore;

    fn setup_store() -> InMemoryImpersonationStore {
        let store = InMemoryImpersonationStore::new();
        store.add_admin("admin-1", "admin@example.com");
        store.add_admin("admin-2", "admin2@example.com");
        store.add_user("user-1", "user1@example.com");
        store.add_user("user-2", "user2@example.com");
        store
    }

    #[test]
    fn test_config_defaults() {
        let config = ImpersonationConfig::new();
        assert_eq!(config.max_duration, DEFAULT_MAX_DURATION);
        assert!(!config.notify_user);
        assert!(!config.allow_admin_impersonation);
        assert!(config.require_reason);
        assert!(!config.blocked_actions.is_empty());
    }

    #[test]
    fn test_config_strict() {
        let config = ImpersonationConfig::strict();
        assert!(config.notify_user);
        assert!(config.notify_on_end);
        assert!(config.blocked_actions.len() > 4);
    }

    #[test]
    fn test_config_permissive() {
        let config = ImpersonationConfig::permissive();
        assert!(!config.notify_user);
        assert!(!config.require_reason);
        assert_eq!(config.blocked_actions.len(), 1);
    }

    #[test]
    fn test_blocked_action_matches() {
        assert!(BlockedAction::DeleteAccount.matches("delete_account"));
        assert!(BlockedAction::ChangePassword.matches("change_password"));
        assert!(!BlockedAction::DeleteAccount.matches("change_password"));

        let custom = BlockedAction::Custom("custom_action".to_string());
        assert!(custom.matches("custom_action"));
        assert!(!custom.matches("other_action"));
    }

    #[test]
    fn test_session_expiry() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_session = ImpersonationSession {
            session_id: "test".to_string(),
            admin_id: "admin".to_string(),
            target_user_id: "user".to_string(),
            reason: None,
            started_at: now - 7200,
            expires_at: now - 3600,
            blocked_actions: vec![],
        };
        assert!(expired_session.is_expired());

        let valid_session = ImpersonationSession {
            session_id: "test".to_string(),
            admin_id: "admin".to_string(),
            target_user_id: "user".to_string(),
            reason: None,
            started_at: now,
            expires_at: now + 3600,
            blocked_actions: vec![],
        };
        assert!(!valid_session.is_expired());
    }

    #[tokio::test]
    async fn test_start_impersonation_success() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let session = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Support ticket #123".to_string()),
                duration: None,
            })
            .await
            .unwrap();

        assert_eq!(session.admin_id, "admin-1");
        assert_eq!(session.target_user_id, "user-1");
        assert!(session.reason.is_some());
        assert!(!session.is_expired());
    }

    #[tokio::test]
    async fn test_start_impersonation_not_admin() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let result = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "user-1".to_string(), // Not an admin
                target_user_id: "user-2".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_impersonation_target_is_admin() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let result = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "admin-2".to_string(), // Admin
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_impersonation_self() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let result = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "admin-1".to_string(), // Self
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_impersonation_no_reason_when_required() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let result = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: None, // No reason
                duration: None,
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_end_impersonation() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let session = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await
            .unwrap();

        manager.end_impersonation(&session.session_id).await.unwrap();

        // Session should be gone
        let active = manager.get_active_session("user-1").await.unwrap();
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn test_validate_session_blocked_action() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let session = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await
            .unwrap();

        // Allowed action should pass
        let result = manager
            .validate_session(&session.session_id, Some("view_profile"))
            .await;
        assert!(result.is_ok());

        // Blocked action should fail
        let result = manager
            .validate_session(&session.session_id, Some("delete_account"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_notifications() {
        let store = setup_store();
        let config = ImpersonationConfig::strict(); // Notifications enabled
        let manager = ImpersonationManager::new(store, config);

        let session = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await
            .unwrap();

        manager.end_impersonation(&session.session_id).await.unwrap();

        let notifications = manager.store.get_notifications();
        assert_eq!(notifications.len(), 2); // Started + Ended
    }

    #[tokio::test]
    async fn test_audit_log() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        let session = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await
            .unwrap();

        manager.end_impersonation(&session.session_id).await.unwrap();

        let audit = manager.get_audit_log("admin-1", 10).await.unwrap();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].event, ImpersonationEvent::Started);
        assert_eq!(audit[1].event, ImpersonationEvent::Ended);
    }

    #[tokio::test]
    async fn test_already_impersonated() {
        let store = setup_store();
        let manager = ImpersonationManager::new(store, ImpersonationConfig::default());

        // First impersonation
        manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-1".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await
            .unwrap();

        // Second impersonation of same user should fail
        let result = manager
            .start_impersonation(ImpersonationRequest {
                admin_id: "admin-2".to_string(),
                target_user_id: "user-1".to_string(),
                reason: Some("Test".to_string()),
                duration: None,
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_impersonation_claims() {
        let session = ImpersonationSession {
            session_id: "imp_123".to_string(),
            admin_id: "admin-1".to_string(),
            target_user_id: "user-1".to_string(),
            reason: Some("Test".to_string()),
            started_at: 0,
            expires_at: 0,
            blocked_actions: vec![BlockedAction::DeleteAccount, BlockedAction::ChangePassword],
        };

        let claims = ImpersonationClaims::from_session(&session);
        assert_eq!(claims.imp_session, "imp_123");
        assert_eq!(claims.imp_admin, "admin-1");
        assert_eq!(claims.imp_blocked.len(), 2);
    }
}
