//! Session management for active session tracking.
//!
//! This module provides functionality to track, list, and revoke user sessions.
//! Sessions are tied to refresh token families, allowing users to see their
//! active logins and revoke access from specific devices.
//!
//! # Tracing Events
//!
//! - `auth.session.created` - New session created on login
//! - `auth.session.revoked` - Session explicitly revoked by user
//! - `auth.session.revoke_all` - All sessions revoked for user
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::sessions::{SessionManager, SessionStore, SessionInfo};
//!
//! // List active sessions
//! let sessions = session_store.list_sessions("user-123").await?;
//! for session in sessions {
//!     println!("Session: {} from {}", session.id, session.ip_address.unwrap_or_default());
//! }
//!
//! // Revoke a specific session
//! session_manager.revoke_session("user-123", "session-456").await?;
//! ```

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Maximum length for IP address strings (IPv6 max is 45 chars).
const MAX_IP_LENGTH: usize = 45;

/// Maximum length for user agent strings to prevent DoS.
const MAX_USER_AGENT_LENGTH: usize = 512;

/// Maximum length for location strings.
const MAX_LOCATION_LENGTH: usize = 256;

/// Default maximum sessions per user (when limit is enabled).
const DEFAULT_MAX_SESSIONS: usize = 5;

/// Behavior when session limit is exceeded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionOverflowBehavior {
    /// Revoke the oldest session to make room (default).
    ///
    /// This provides the best UX - users can always log in from new devices.
    #[default]
    RevokeOldest,

    /// Reject the new session.
    ///
    /// Users must manually revoke an existing session before logging in.
    RejectNew,
}

/// Configuration for session limits.
///
/// # Note
///
/// Setting `max_sessions` to 0 will reject all new sessions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLimitConfig {
    /// Maximum number of concurrent sessions per user.
    pub max_sessions: usize,
    /// What to do when the limit is exceeded.
    pub overflow_behavior: SessionOverflowBehavior,
}

impl Default for SessionLimitConfig {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            overflow_behavior: SessionOverflowBehavior::default(),
        }
    }
}

impl SessionLimitConfig {
    /// Create a new session limit config.
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            overflow_behavior: SessionOverflowBehavior::default(),
        }
    }

    /// Set the overflow behavior.
    #[must_use]
    pub fn overflow_behavior(mut self, behavior: SessionOverflowBehavior) -> Self {
        self.overflow_behavior = behavior;
        self
    }

    /// Use reject-new behavior (stricter).
    #[must_use]
    pub fn reject_new(mut self) -> Self {
        self.overflow_behavior = SessionOverflowBehavior::RejectNew;
        self
    }

    /// Use revoke-oldest behavior (default, better UX).
    #[must_use]
    pub fn revoke_oldest(mut self) -> Self {
        self.overflow_behavior = SessionOverflowBehavior::RevokeOldest;
        self
    }
}

/// Result of creating a session with limits enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateResult {
    /// Whether the session was created successfully.
    pub created: bool,
    /// Sessions that were revoked to make room (if any).
    pub evicted_sessions: Vec<String>,
}

impl SessionCreateResult {
    /// Create a successful result with no evictions.
    #[must_use]
    fn success() -> Self {
        Self {
            created: true,
            evicted_sessions: Vec::new(),
        }
    }

    /// Create a successful result with evicted sessions.
    #[must_use]
    fn success_with_evictions(evicted: Vec<String>) -> Self {
        Self {
            created: true,
            evicted_sessions: evicted,
        }
    }

    /// Create a rejected result (limit exceeded, reject-new behavior).
    #[must_use]
    fn rejected() -> Self {
        Self {
            created: false,
            evicted_sessions: Vec::new(),
        }
    }

    /// Check if the session was created successfully.
    #[must_use]
    pub fn is_created(&self) -> bool {
        self.created
    }

    /// Check if any sessions were evicted.
    #[must_use]
    pub fn has_evictions(&self) -> bool {
        !self.evicted_sessions.is_empty()
    }
}

/// Information about an active session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique session identifier (same as token family ID).
    pub id: String,

    /// User ID this session belongs to.
    pub user_id: String,

    /// IP address of the client when session was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// User agent string from the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Parsed device/browser info (e.g., "Chrome on macOS").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_info: Option<String>,

    /// Location based on IP (e.g., "San Francisco, CA").
    /// Note: Requires external geolocation service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// When the session was created.
    pub created_at: SystemTime,

    /// When the session was last used (token refreshed).
    pub last_used_at: SystemTime,

    /// Whether this is the current session making the request.
    #[serde(default)]
    pub is_current: bool,
}

impl SessionInfo {
    /// Create a new session info.
    #[must_use]
    pub fn new(id: impl Into<String>, user_id: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id: id.into(),
            user_id: user_id.into(),
            ip_address: None,
            user_agent: None,
            device_info: None,
            location: None,
            created_at: now,
            last_used_at: now,
            is_current: false,
        }
    }

    /// Set the IP address (truncated to 45 chars for IPv6 compatibility).
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        let ip = truncate_string(ip.into(), MAX_IP_LENGTH);
        self.ip_address = Some(ip);
        self
    }

    /// Set the user agent (truncated to prevent DoS).
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        let ua_string = truncate_string(ua.into(), MAX_USER_AGENT_LENGTH);
        self.device_info = Some(parse_user_agent(&ua_string));
        self.user_agent = Some(ua_string);
        self
    }

    /// Set the location.
    #[must_use]
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        let location = truncate_string(location.into(), MAX_LOCATION_LENGTH);
        self.location = Some(location);
        self
    }

    /// Mark as the current session.
    #[must_use]
    pub fn mark_current(mut self) -> Self {
        self.is_current = true;
        self
    }
}

/// Truncate a string to a maximum length, preserving valid UTF-8.
fn truncate_string(s: String, max_len: usize) -> String {
    if s.len() <= max_len {
        s
    } else {
        s.chars().take(max_len).collect()
    }
}

/// Parse a user agent string into a human-readable device description.
fn parse_user_agent(ua: &str) -> String {
    // Simple parsing - production apps might use a proper UA parser crate
    let browser = if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome") {
        "Chrome"
    } else if ua.contains("Safari") {
        "Safari"
    } else if ua.contains("curl") {
        "curl"
    } else {
        "Unknown Browser"
    };

    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        // Check iOS before macOS since iOS user agents contain "Mac OS X"
        "iOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Mac OS X") || ua.contains("macOS") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown OS"
    };

    format!("{} on {}", browser, os)
}

/// Metadata to capture when creating a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionMetadata {
    /// Client IP address.
    pub ip_address: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Pre-computed location (if using external geolocation).
    pub location: Option<String>,
}

impl SessionMetadata {
    /// Create empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IP address (truncated to 45 chars for IPv6 compatibility).
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(truncate_string(ip.into(), MAX_IP_LENGTH));
        self
    }

    /// Set the user agent (truncated to prevent DoS).
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(truncate_string(ua.into(), MAX_USER_AGENT_LENGTH));
        self
    }

    /// Set the location.
    #[must_use]
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(truncate_string(location.into(), MAX_LOCATION_LENGTH));
        self
    }
}

/// Trait for session storage with metadata tracking.
///
/// Implementations should store session metadata alongside the refresh token
/// family information. This enables listing active sessions and providing
/// users with visibility into their account access.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::sessions::{SessionStore, SessionInfo, SessionMetadata};
/// use async_trait::async_trait;
///
/// struct PostgresSessionStore {
///     db: DatabaseConnection,
/// }
///
/// #[async_trait]
/// impl SessionStore for PostgresSessionStore {
///     async fn create_session(
///         &self,
///         session_id: &str,
///         user_id: &str,
///         metadata: SessionMetadata,
///     ) -> Result<()> {
///         // Insert into sessions table
///         sqlx::query!(
///             "INSERT INTO sessions (id, user_id, ip_address, user_agent, created_at, last_used_at)
///              VALUES ($1, $2, $3, $4, NOW(), NOW())",
///             session_id, user_id, metadata.ip_address, metadata.user_agent
///         )
///         .execute(&self.db)
///         .await?;
///         Ok(())
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Create a new session with metadata.
    ///
    /// Called during login to record session information.
    async fn create_session(
        &self,
        session_id: &str,
        user_id: &str,
        metadata: SessionMetadata,
    ) -> Result<()>;

    /// Update the last_used_at timestamp for a session.
    ///
    /// Called during token refresh.
    async fn touch_session(&self, session_id: &str) -> Result<()>;

    /// Get information about a specific session.
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionInfo>>;

    /// List all active (non-revoked) sessions for a user.
    ///
    /// Sessions should be returned in reverse chronological order (newest first).
    async fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionInfo>>;

    /// Revoke a specific session.
    ///
    /// Returns `true` if the session was found and revoked, `false` if not found.
    async fn revoke_session(&self, session_id: &str) -> Result<bool>;

    /// Revoke all sessions for a user.
    ///
    /// Returns the number of sessions revoked.
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize>;

    /// Revoke all sessions for a user except the specified one.
    ///
    /// Useful for "logout other devices" functionality.
    /// Returns the number of sessions revoked.
    async fn revoke_other_sessions(&self, user_id: &str, except_session_id: &str) -> Result<usize>;

    /// Get the count of active sessions for a user.
    ///
    /// Default implementation loads all sessions. Override for efficiency.
    async fn session_count(&self, user_id: &str) -> Result<usize> {
        Ok(self.list_sessions(user_id).await?.len())
    }

    /// List sessions with pagination.
    ///
    /// Default implementation loads all sessions then slices. Override for efficiency.
    /// Returns sessions in reverse chronological order (newest first).
    async fn list_sessions_paginated(
        &self,
        user_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<SessionInfo>> {
        let all = self.list_sessions(user_id).await?;
        Ok(all.into_iter().skip(offset).take(limit).collect())
    }
}

/// Manager for session operations with tracing.
///
/// Wraps a `SessionStore` and adds tracing events for security monitoring.
/// Optionally enforces session limits per user.
///
/// # Session Limits
///
/// ```rust,ignore
/// use tideway::auth::sessions::{SessionManager, SessionLimitConfig};
///
/// // Limit to 5 sessions, revoke oldest when exceeded (default behavior)
/// let manager = SessionManager::new(store)
///     .with_session_limit(SessionLimitConfig::new(5));
///
/// // Limit to 3 sessions, reject new logins when exceeded
/// let manager = SessionManager::new(store)
///     .with_session_limit(SessionLimitConfig::new(3).reject_new());
/// ```
pub struct SessionManager<S: SessionStore> {
    store: S,
    session_limit: Option<SessionLimitConfig>,
}

impl<S: SessionStore> SessionManager<S> {
    /// Create a new session manager without session limits.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            store,
            session_limit: None,
        }
    }

    /// Enable session limits.
    ///
    /// When enabled, `create_session` will enforce the limit by either
    /// revoking the oldest session or rejecting the new one.
    #[must_use]
    pub fn with_session_limit(mut self, config: SessionLimitConfig) -> Self {
        self.session_limit = Some(config);
        self
    }

    /// Create a new session with metadata.
    ///
    /// If session limits are configured, this will enforce them by either:
    /// - Revoking the oldest session(s) to make room (default)
    /// - Returning an error if the limit is exceeded (reject-new mode)
    ///
    /// Returns `SessionCreateResult` with information about any evicted sessions.
    ///
    /// # Note
    ///
    /// Session limits are enforced as a soft limit. Concurrent logins may briefly
    /// exceed the limit due to the check-then-create pattern. For strict enforcement,
    /// implement database-level constraints in your `SessionStore`.
    pub async fn create_session(
        &self,
        session_id: &str,
        user_id: &str,
        metadata: SessionMetadata,
    ) -> Result<SessionCreateResult> {
        let ip_for_logging = metadata.ip_address.clone();
        let mut evicted = Vec::new();

        // Enforce session limit if configured
        if let Some(ref limit_config) = self.session_limit {
            let current_count = self.store.session_count(user_id).await?;

            if current_count >= limit_config.max_sessions {
                match limit_config.overflow_behavior {
                    SessionOverflowBehavior::RejectNew => {
                        tracing::warn!(
                            target: "auth.session.limit_exceeded",
                            user_id = %user_id,
                            current_count = current_count,
                            max_sessions = limit_config.max_sessions,
                            "Session limit exceeded, rejecting new session"
                        );
                        return Ok(SessionCreateResult::rejected());
                    }
                    SessionOverflowBehavior::RevokeOldest => {
                        // Calculate how many to evict
                        let to_evict = current_count - limit_config.max_sessions + 1;
                        evicted = self.evict_oldest_sessions(user_id, to_evict).await?;
                    }
                }
            }
        }

        // Create the new session
        self.store.create_session(session_id, user_id, metadata).await?;

        tracing::info!(
            target: "auth.session.created",
            session_id = %session_id,
            user_id = %user_id,
            ip_address = ip_for_logging.as_deref().unwrap_or("unknown"),
            evicted_count = evicted.len(),
            "New session created"
        );

        if evicted.is_empty() {
            Ok(SessionCreateResult::success())
        } else {
            Ok(SessionCreateResult::success_with_evictions(evicted))
        }
    }

    /// Evict the oldest sessions for a user.
    ///
    /// Returns the IDs of evicted sessions.
    async fn evict_oldest_sessions(&self, user_id: &str, count: usize) -> Result<Vec<String>> {
        let sessions = self.store.list_sessions(user_id).await?;

        // Sessions are returned newest-first, so take from the end
        let to_evict: Vec<_> = sessions
            .iter()
            .rev()
            .take(count)
            .map(|s| s.id.clone())
            .collect();

        for session_id in &to_evict {
            self.store.revoke_session(session_id).await?;

            tracing::info!(
                target: "auth.session.evicted",
                session_id = %session_id,
                user_id = %user_id,
                "Session evicted due to session limit"
            );
        }

        Ok(to_evict)
    }

    /// Update the last_used_at timestamp.
    pub async fn touch_session(&self, session_id: &str) -> Result<()> {
        self.store.touch_session(session_id).await
    }

    /// Get session info.
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionInfo>> {
        self.store.get_session(session_id).await
    }

    /// List all active sessions for a user.
    ///
    /// If `current_session_id` is provided, that session will be marked as current.
    pub async fn list_sessions(
        &self,
        user_id: &str,
        current_session_id: Option<&str>,
    ) -> Result<Vec<SessionInfo>> {
        let mut sessions = self.store.list_sessions(user_id).await?;

        // Mark the current session
        if let Some(current_id) = current_session_id {
            for session in &mut sessions {
                if session.id == current_id {
                    session.is_current = true;
                }
            }
        }

        Ok(sessions)
    }

    /// Revoke a specific session.
    pub async fn revoke_session(&self, user_id: &str, session_id: &str) -> Result<bool> {
        // First verify the session belongs to this user
        if let Some(session) = self.store.get_session(session_id).await? {
            if session.user_id != user_id {
                // Session doesn't belong to this user - don't reveal it exists
                return Ok(false);
            }
        }

        let revoked = self.store.revoke_session(session_id).await?;

        if revoked {
            tracing::info!(
                target: "auth.session.revoked",
                session_id = %session_id,
                user_id = %user_id,
                "Session revoked"
            );
        }

        Ok(revoked)
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize> {
        let count = self.store.revoke_all_sessions(user_id).await?;

        tracing::warn!(
            target: "auth.session.revoke_all",
            user_id = %user_id,
            count = count,
            "All sessions revoked"
        );

        Ok(count)
    }

    /// Revoke all sessions except the current one.
    pub async fn revoke_other_sessions(
        &self,
        user_id: &str,
        current_session_id: &str,
    ) -> Result<usize> {
        let count = self.store.revoke_other_sessions(user_id, current_session_id).await?;

        tracing::info!(
            target: "auth.session.revoke_others",
            user_id = %user_id,
            current_session_id = %current_session_id,
            count = count,
            "Other sessions revoked"
        );

        Ok(count)
    }

    /// Get the count of active sessions.
    pub async fn session_count(&self, user_id: &str) -> Result<usize> {
        self.store.session_count(user_id).await
    }

    /// List sessions with pagination.
    ///
    /// If `current_session_id` is provided, that session will be marked as current.
    pub async fn list_sessions_paginated(
        &self,
        user_id: &str,
        current_session_id: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<SessionInfo>> {
        let mut sessions = self.store.list_sessions_paginated(user_id, offset, limit).await?;

        // Mark the current session
        if let Some(current_id) = current_session_id {
            for session in &mut sessions {
                if session.id == current_id {
                    session.is_current = true;
                }
            }
        }

        Ok(sessions)
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// In-memory session store for testing.
///
/// **Note:** This implementation is intended for testing only. Production
/// implementations should use a database with proper indexing.
#[cfg(any(test, feature = "test-auth-bypass"))]
pub mod test {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::RwLock;

    /// Internal state for the in-memory store.
    /// Using a single struct with one lock prevents deadlocks.
    #[derive(Default)]
    struct InMemoryState {
        sessions: HashMap<String, SessionInfo>,
        user_sessions: HashMap<String, Vec<String>>,
        revoked: HashSet<String>,
    }

    /// In-memory session store for testing.
    ///
    /// Thread-safe via a single `RwLock`. Not suitable for production use
    /// due to memory growth (revoked sessions are not cleaned up).
    #[derive(Default)]
    pub struct InMemorySessionStore {
        state: RwLock<InMemoryState>,
    }

    impl InMemorySessionStore {
        /// Create a new in-memory session store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl SessionStore for InMemorySessionStore {
        async fn create_session(
            &self,
            session_id: &str,
            user_id: &str,
            metadata: SessionMetadata,
        ) -> Result<()> {
            let mut session = SessionInfo::new(session_id, user_id);
            if let Some(ip) = metadata.ip_address {
                session = session.with_ip(ip);
            }
            if let Some(ua) = metadata.user_agent {
                session = session.with_user_agent(ua);
            }
            if let Some(loc) = metadata.location {
                session = session.with_location(loc);
            }

            let mut state = self.state.write().unwrap();
            state.sessions.insert(session_id.to_string(), session);
            state
                .user_sessions
                .entry(user_id.to_string())
                .or_default()
                .push(session_id.to_string());

            Ok(())
        }

        async fn touch_session(&self, session_id: &str) -> Result<()> {
            let mut state = self.state.write().unwrap();
            if let Some(session) = state.sessions.get_mut(session_id) {
                session.last_used_at = SystemTime::now();
            }
            Ok(())
        }

        async fn get_session(&self, session_id: &str) -> Result<Option<SessionInfo>> {
            let state = self.state.read().unwrap();

            if state.revoked.contains(session_id) {
                return Ok(None);
            }

            Ok(state.sessions.get(session_id).cloned())
        }

        async fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionInfo>> {
            let state = self.state.read().unwrap();

            let mut result = Vec::new();
            if let Some(session_ids) = state.user_sessions.get(user_id) {
                for id in session_ids {
                    if !state.revoked.contains(id) {
                        if let Some(session) = state.sessions.get(id) {
                            result.push(session.clone());
                        }
                    }
                }
            }

            // Sort by created_at descending (newest first)
            result.sort_by(|a, b| b.created_at.cmp(&a.created_at));

            Ok(result)
        }

        async fn revoke_session(&self, session_id: &str) -> Result<bool> {
            let mut state = self.state.write().unwrap();
            if state.sessions.contains_key(session_id) && !state.revoked.contains(session_id) {
                state.revoked.insert(session_id.to_string());
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn revoke_all_sessions(&self, user_id: &str) -> Result<usize> {
            let mut state = self.state.write().unwrap();

            // Collect IDs first to avoid borrow conflict
            let ids_to_revoke: Vec<String> = state
                .user_sessions
                .get(user_id)
                .map(|ids| {
                    ids.iter()
                        .filter(|id| !state.revoked.contains(*id))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            let count = ids_to_revoke.len();
            for id in ids_to_revoke {
                state.revoked.insert(id);
            }

            Ok(count)
        }

        async fn revoke_other_sessions(
            &self,
            user_id: &str,
            except_session_id: &str,
        ) -> Result<usize> {
            let mut state = self.state.write().unwrap();

            // Collect IDs first to avoid borrow conflict
            let ids_to_revoke: Vec<String> = state
                .user_sessions
                .get(user_id)
                .map(|ids| {
                    ids.iter()
                        .filter(|id| *id != except_session_id && !state.revoked.contains(*id))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            let count = ids_to_revoke.len();
            for id in ids_to_revoke {
                state.revoked.insert(id);
            }

            Ok(count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::InMemorySessionStore;

    #[tokio::test]
    async fn test_create_and_get_session() {
        let store = InMemorySessionStore::new();

        let metadata = SessionMetadata::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0");

        store.create_session("session-1", "user-1", metadata).await.unwrap();

        let session = store.get_session("session-1").await.unwrap().unwrap();
        assert_eq!(session.id, "session-1");
        assert_eq!(session.user_id, "user-1");
        assert_eq!(session.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(session.device_info, Some("Chrome on macOS".to_string()));
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let store = InMemorySessionStore::new();

        store.create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();
        store.create_session("session-2", "user-1", SessionMetadata::new()).await.unwrap();
        store.create_session("session-3", "user-2", SessionMetadata::new()).await.unwrap();

        let sessions = store.list_sessions("user-1").await.unwrap();
        assert_eq!(sessions.len(), 2);

        let sessions = store.list_sessions("user-2").await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let store = InMemorySessionStore::new();

        store.create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();

        assert!(store.get_session("session-1").await.unwrap().is_some());

        let revoked = store.revoke_session("session-1").await.unwrap();
        assert!(revoked);

        assert!(store.get_session("session-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_revoke_all_sessions() {
        let store = InMemorySessionStore::new();

        store.create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();
        store.create_session("session-2", "user-1", SessionMetadata::new()).await.unwrap();
        store.create_session("session-3", "user-2", SessionMetadata::new()).await.unwrap();

        let count = store.revoke_all_sessions("user-1").await.unwrap();
        assert_eq!(count, 2);

        let sessions = store.list_sessions("user-1").await.unwrap();
        assert_eq!(sessions.len(), 0);

        // user-2's session should be unaffected
        let sessions = store.list_sessions("user-2").await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_other_sessions() {
        let store = InMemorySessionStore::new();

        store.create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();
        store.create_session("session-2", "user-1", SessionMetadata::new()).await.unwrap();
        store.create_session("session-3", "user-1", SessionMetadata::new()).await.unwrap();

        let count = store.revoke_other_sessions("user-1", "session-2").await.unwrap();
        assert_eq!(count, 2);

        let sessions = store.list_sessions("user-1").await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "session-2");
    }

    #[tokio::test]
    async fn test_touch_session() {
        let store = InMemorySessionStore::new();

        store.create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();

        let session1 = store.get_session("session-1").await.unwrap().unwrap();
        let last_used1 = session1.last_used_at;

        // Small delay to ensure time difference
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        store.touch_session("session-1").await.unwrap();

        let session2 = store.get_session("session-1").await.unwrap().unwrap();
        assert!(session2.last_used_at > last_used1);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store);

        let metadata = SessionMetadata::new().with_ip("10.0.0.1");
        manager.create_session("session-1", "user-1", metadata).await.unwrap();

        let sessions = manager.list_sessions("user-1", Some("session-1")).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].is_current);

        let revoked = manager.revoke_session("user-1", "session-1").await.unwrap();
        assert!(revoked);

        let sessions = manager.list_sessions("user-1", None).await.unwrap();
        assert_eq!(sessions.len(), 0);
    }

    #[tokio::test]
    async fn test_session_manager_security() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store);

        manager
            .create_session("session-1", "user-1", SessionMetadata::new())
            .await
            .unwrap();

        // user-2 shouldn't be able to revoke user-1's session
        let revoked = manager.revoke_session("user-2", "session-1").await.unwrap();
        assert!(!revoked);

        // session should still exist
        let sessions = manager.list_sessions("user-1", None).await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_parse_user_agent() {
        assert_eq!(
            parse_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0"),
            "Chrome on macOS"
        );
        assert_eq!(
            parse_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"),
            "Firefox on Windows"
        );
        assert_eq!(
            parse_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1.15"),
            "Safari on iOS"
        );
        assert_eq!(
            parse_user_agent("curl/7.88.1"),
            "curl on Unknown OS"
        );
    }

    #[test]
    fn test_input_truncation() {
        // Test IP address truncation (max 45 chars for IPv6)
        let long_ip = "a".repeat(100);
        let metadata = SessionMetadata::new().with_ip(&long_ip);
        assert_eq!(metadata.ip_address.as_ref().unwrap().len(), 45);

        // Test user agent truncation (max 512 chars)
        let long_ua = "Mozilla/".to_string() + &"x".repeat(1000);
        let metadata = SessionMetadata::new().with_user_agent(&long_ua);
        assert_eq!(metadata.user_agent.as_ref().unwrap().len(), 512);

        // Test location truncation (max 256 chars)
        let long_location = "a".repeat(500);
        let metadata = SessionMetadata::new().with_location(&long_location);
        assert_eq!(metadata.location.as_ref().unwrap().len(), 256);

        // Test SessionInfo builder also truncates
        let session = SessionInfo::new("id", "user")
            .with_ip(&long_ip)
            .with_user_agent(&long_ua)
            .with_location(&long_location);
        assert_eq!(session.ip_address.as_ref().unwrap().len(), 45);
        assert_eq!(session.user_agent.as_ref().unwrap().len(), 512);
        assert_eq!(session.location.as_ref().unwrap().len(), 256);
    }

    #[test]
    fn test_truncate_string_utf8_safe() {
        // Ensure truncation doesn't break UTF-8
        let unicode = "🔐🔐🔐🔐🔐"; // 5 lock emojis (4 bytes each)
        let truncated = truncate_string(unicode.to_string(), 10);
        // Should truncate to 10 chars (not bytes), so all 5 emojis fit
        assert_eq!(truncated, unicode);

        // Truncate to 3 chars
        let truncated = truncate_string(unicode.to_string(), 3);
        assert_eq!(truncated, "🔐🔐🔐");
    }

    // Session limit tests

    #[tokio::test]
    async fn test_session_limit_revoke_oldest() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store)
            .with_session_limit(SessionLimitConfig::new(3));

        // Create 3 sessions (at limit)
        for i in 1..=3 {
            let result = manager
                .create_session(&format!("session-{}", i), "user-1", SessionMetadata::new())
                .await
                .unwrap();
            assert!(result.created);
            assert!(result.evicted_sessions.is_empty());
            // Small delay to ensure different timestamps
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // Create 4th session - should evict session-1 (oldest)
        let result = manager
            .create_session("session-4", "user-1", SessionMetadata::new())
            .await
            .unwrap();

        assert!(result.created);
        assert_eq!(result.evicted_sessions.len(), 1);
        assert_eq!(result.evicted_sessions[0], "session-1");

        // Verify session-1 is gone
        let sessions = manager.list_sessions("user-1", None).await.unwrap();
        assert_eq!(sessions.len(), 3);
        assert!(!sessions.iter().any(|s| s.id == "session-1"));
    }

    #[tokio::test]
    async fn test_session_limit_reject_new() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store)
            .with_session_limit(SessionLimitConfig::new(2).reject_new());

        // Create 2 sessions (at limit)
        for i in 1..=2 {
            let result = manager
                .create_session(&format!("session-{}", i), "user-1", SessionMetadata::new())
                .await
                .unwrap();
            assert!(result.created);
        }

        // Create 3rd session - should be rejected
        let result = manager
            .create_session("session-3", "user-1", SessionMetadata::new())
            .await
            .unwrap();

        assert!(!result.created);
        assert!(result.evicted_sessions.is_empty());

        // Verify only 2 sessions exist
        let sessions = manager.list_sessions("user-1", None).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_session_limit_per_user() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store)
            .with_session_limit(SessionLimitConfig::new(2));

        // Create 2 sessions for user-1
        manager.create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();
        manager.create_session("session-2", "user-1", SessionMetadata::new()).await.unwrap();

        // Create 2 sessions for user-2 (separate limit)
        manager.create_session("session-3", "user-2", SessionMetadata::new()).await.unwrap();
        manager.create_session("session-4", "user-2", SessionMetadata::new()).await.unwrap();

        // Each user has their own limit
        let sessions_1 = manager.list_sessions("user-1", None).await.unwrap();
        let sessions_2 = manager.list_sessions("user-2", None).await.unwrap();
        assert_eq!(sessions_1.len(), 2);
        assert_eq!(sessions_2.len(), 2);
    }

    #[tokio::test]
    async fn test_session_limit_evict_multiple() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store)
            .with_session_limit(SessionLimitConfig::new(2));

        // Create 4 sessions directly via store (bypassing limit)
        manager.store().create_session("session-1", "user-1", SessionMetadata::new()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        manager.store().create_session("session-2", "user-1", SessionMetadata::new()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        manager.store().create_session("session-3", "user-1", SessionMetadata::new()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        manager.store().create_session("session-4", "user-1", SessionMetadata::new()).await.unwrap();

        // Now create via manager - should evict 3 oldest to get down to limit
        let result = manager
            .create_session("session-5", "user-1", SessionMetadata::new())
            .await
            .unwrap();

        assert!(result.created);
        assert_eq!(result.evicted_sessions.len(), 3);

        // Verify only 2 sessions remain
        let sessions = manager.list_sessions("user-1", None).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_session_limit_no_limit_configured() {
        let store = InMemorySessionStore::new();
        let manager = SessionManager::new(store); // No limit configured

        // Create many sessions - should all succeed
        for i in 1..=10 {
            let result = manager
                .create_session(&format!("session-{}", i), "user-1", SessionMetadata::new())
                .await
                .unwrap();
            assert!(result.created);
            assert!(result.evicted_sessions.is_empty());
        }

        let sessions = manager.list_sessions("user-1", None).await.unwrap();
        assert_eq!(sessions.len(), 10);
    }

    #[test]
    fn test_session_limit_config_builder() {
        let config = SessionLimitConfig::new(5)
            .reject_new();
        assert_eq!(config.max_sessions, 5);
        assert_eq!(config.overflow_behavior, SessionOverflowBehavior::RejectNew);

        let config = SessionLimitConfig::new(10)
            .revoke_oldest();
        assert_eq!(config.max_sessions, 10);
        assert_eq!(config.overflow_behavior, SessionOverflowBehavior::RevokeOldest);

        let config = SessionLimitConfig::default();
        assert_eq!(config.max_sessions, 5); // DEFAULT_MAX_SESSIONS
        assert_eq!(config.overflow_behavior, SessionOverflowBehavior::RevokeOldest);
    }

    #[test]
    fn test_session_create_result() {
        let success = SessionCreateResult::success();
        assert!(success.created);
        assert!(success.evicted_sessions.is_empty());

        let evicted = SessionCreateResult::success_with_evictions(vec!["s1".into(), "s2".into()]);
        assert!(evicted.created);
        assert_eq!(evicted.evicted_sessions, vec!["s1", "s2"]);

        let rejected = SessionCreateResult::rejected();
        assert!(!rejected.created);
        assert!(rejected.evicted_sessions.is_empty());
    }
}
