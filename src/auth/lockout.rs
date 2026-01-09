//! Account lockout management.
//!
//! Provides configurable account lockout policies with progressive delays,
//! notifications, and admin unlock capabilities.
//!
//! # Features
//!
//! - Configurable max attempts and lockout duration
//! - Progressive delays before full lockout
//! - Optional email notifications on lock/unlock
//! - Admin unlock capability
//! - IP-based or account-based tracking
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::lockout::{LockoutManager, LockoutPolicy};
//! use std::time::Duration;
//!
//! let policy = LockoutPolicy::new()
//!     .max_attempts(5)
//!     .lockout_duration(Duration::from_secs(900))
//!     .progressive_delays(vec![0, 0, 0, 60, 300]);
//!
//! let manager = LockoutManager::new(store, policy);
//!
//! // Record a failed attempt
//! let status = manager.record_failed_attempt("user-123", None).await?;
//! if let Some(delay) = status.delay_seconds {
//!     println!("Wait {} seconds before retrying", delay);
//! }
//! if status.is_locked {
//!     println!("Account is locked until {:?}", status.locked_until);
//! }
//! ```

use crate::error::Result;
use async_trait::async_trait;
use std::time::{Duration, SystemTime};

/// Default maximum failed attempts before lockout.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default lockout duration (15 minutes).
const DEFAULT_LOCKOUT_DURATION: Duration = Duration::from_secs(15 * 60);

/// Maximum IP address length (prevent DoS).
const MAX_IP_LENGTH: usize = 45; // IPv6 max length

/// Truncate IP address to prevent DoS attacks.
fn truncate_ip(ip: &str) -> &str {
    if ip.len() <= MAX_IP_LENGTH {
        ip
    } else {
        &ip[..MAX_IP_LENGTH]
    }
}

/// Lockout policy configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Maximum failed attempts before account is locked.
    pub max_attempts: u32,
    /// How long the account stays locked.
    pub lockout_duration: Duration,
    /// Progressive delays (seconds) for each attempt before lockout.
    /// Index 0 = delay after 1st failure, etc.
    /// Empty means no delays before lockout.
    pub progressive_delays: Vec<u64>,
    /// Whether to send email notifications on lock/unlock.
    pub send_notifications: bool,
    /// Whether to track by IP address in addition to user.
    pub track_by_ip: bool,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            lockout_duration: DEFAULT_LOCKOUT_DURATION,
            progressive_delays: vec![],
            send_notifications: false,
            track_by_ip: false,
        }
    }
}

impl LockoutPolicy {
    /// Create a new policy with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict policy (3 attempts, 30 min lockout, notifications enabled).
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_attempts: 3,
            lockout_duration: Duration::from_secs(30 * 60),
            progressive_delays: vec![0, 30, 60],
            send_notifications: true,
            track_by_ip: true,
        }
    }

    /// Create a lenient policy (10 attempts, 5 min lockout).
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            max_attempts: 10,
            lockout_duration: Duration::from_secs(5 * 60),
            progressive_delays: vec![],
            send_notifications: false,
            track_by_ip: false,
        }
    }

    /// Set the maximum failed attempts before lockout.
    ///
    /// Note: Setting to 0 will lock accounts on first failed attempt.
    /// Minimum recommended value is 3.
    #[must_use]
    pub fn max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = max;
        self
    }

    /// Set the lockout duration.
    #[must_use]
    pub fn lockout_duration(mut self, duration: Duration) -> Self {
        self.lockout_duration = duration;
        self
    }

    /// Set progressive delays (seconds) for each attempt.
    ///
    /// Example: `vec![0, 0, 0, 60, 300]` means:
    /// - Attempts 1-3: No delay
    /// - Attempt 4: 60 second delay
    /// - Attempt 5: 300 second delay
    /// - Attempt 6+: Full lockout
    #[must_use]
    pub fn progressive_delays(mut self, delays: Vec<u64>) -> Self {
        self.progressive_delays = delays;
        self
    }

    /// Enable email notifications on lock/unlock.
    #[must_use]
    pub fn with_notifications(mut self) -> Self {
        self.send_notifications = true;
        self
    }

    /// Enable IP-based tracking (in addition to user-based).
    #[must_use]
    pub fn track_by_ip(mut self, track: bool) -> Self {
        self.track_by_ip = track;
        self
    }

    /// Get the delay (in seconds) for a given attempt number.
    ///
    /// Returns `None` if the account should be locked.
    #[must_use]
    pub fn get_delay_for_attempt(&self, attempt: u32) -> Option<u64> {
        if attempt >= self.max_attempts {
            return None; // Should be locked
        }

        let index = attempt.saturating_sub(1) as usize;
        if index < self.progressive_delays.len() {
            Some(self.progressive_delays[index])
        } else if !self.progressive_delays.is_empty() {
            // Use last delay for attempts beyond the configured delays
            Some(*self.progressive_delays.last().unwrap())
        } else {
            Some(0) // No delay configured
        }
    }
}

/// Current lockout status for a user/IP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockoutStatus {
    /// Number of failed attempts.
    pub failed_attempts: u32,
    /// Whether the account is currently locked.
    pub is_locked: bool,
    /// When the lockout expires (if locked).
    pub locked_until: Option<SystemTime>,
    /// Required delay before next attempt (seconds).
    pub delay_seconds: Option<u64>,
    /// When the delay expires (if any).
    pub delay_until: Option<SystemTime>,
    /// When the last failed attempt occurred.
    pub last_attempt_at: Option<SystemTime>,
}

impl LockoutStatus {
    /// Check if the user can attempt login now.
    #[must_use]
    pub fn can_attempt_now(&self) -> bool {
        if self.is_locked {
            if let Some(until) = self.locked_until {
                return SystemTime::now() >= until;
            }
            return false;
        }

        if let Some(until) = self.delay_until {
            return SystemTime::now() >= until;
        }

        true
    }

    /// Get remaining wait time in seconds (0 if can attempt now).
    #[must_use]
    pub fn remaining_wait_seconds(&self) -> u64 {
        let now = SystemTime::now();

        if self.is_locked {
            if let Some(until) = self.locked_until {
                if let Ok(duration) = until.duration_since(now) {
                    return duration.as_secs();
                }
            }
        }

        if let Some(until) = self.delay_until {
            if let Ok(duration) = until.duration_since(now) {
                return duration.as_secs();
            }
        }

        0
    }
}

/// Result of recording a failed attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedAttemptResult {
    /// Updated lockout status.
    pub status: LockoutStatus,
    /// Whether this attempt triggered a lockout.
    pub just_locked: bool,
    /// Whether a notification was sent.
    pub notification_sent: bool,
}

impl FailedAttemptResult {
    /// Check if user can retry now.
    #[must_use]
    pub fn can_retry_now(&self) -> bool {
        self.status.can_attempt_now()
    }

    /// Get wait time before retry in seconds.
    #[must_use]
    pub fn wait_seconds(&self) -> u64 {
        self.status.remaining_wait_seconds()
    }
}

/// Trait for lockout storage operations.
#[async_trait]
pub trait LockoutStore: Send + Sync {
    /// Get the current failed attempt count for a user.
    async fn get_failed_attempts(&self, user_id: &str) -> Result<u32>;

    /// Get the lockout status for a user.
    async fn get_lockout_status(&self, user_id: &str) -> Result<Option<LockoutStatus>>;

    /// Record a failed attempt and return the new count.
    async fn increment_failed_attempts(&self, user_id: &str) -> Result<u32>;

    /// Set the lockout for a user.
    async fn set_lockout(&self, user_id: &str, until: SystemTime) -> Result<()>;

    /// Set a delay for the next attempt.
    async fn set_delay(&self, user_id: &str, until: SystemTime) -> Result<()>;

    /// Clear all lockout state for a user (on successful login or admin unlock).
    async fn clear_lockout(&self, user_id: &str) -> Result<()>;

    /// Get the user's email for notifications (optional).
    async fn get_user_email(&self, user_id: &str) -> Result<Option<String>> {
        let _ = user_id;
        Ok(None)
    }

    /// Send lockout notification email (optional).
    async fn send_lockout_notification(
        &self,
        user_id: &str,
        email: &str,
        locked_until: SystemTime,
    ) -> Result<()> {
        let _ = (user_id, email, locked_until);
        Ok(())
    }

    /// Send unlock notification email (optional).
    async fn send_unlock_notification(&self, user_id: &str, email: &str) -> Result<()> {
        let _ = (user_id, email);
        Ok(())
    }

    // IP-based tracking methods (optional)

    /// Get failed attempts by IP address.
    async fn get_failed_attempts_by_ip(&self, ip: &str) -> Result<u32> {
        let _ = ip;
        Ok(0)
    }

    /// Increment failed attempts by IP address.
    async fn increment_failed_attempts_by_ip(&self, ip: &str) -> Result<u32> {
        let _ = ip;
        Ok(0)
    }

    /// Set lockout by IP address.
    async fn set_lockout_by_ip(&self, ip: &str, until: SystemTime) -> Result<()> {
        let _ = (ip, until);
        Ok(())
    }

    /// Check if IP is locked out.
    async fn is_ip_locked(&self, ip: &str) -> Result<Option<SystemTime>> {
        let _ = ip;
        Ok(None)
    }

    /// Clear IP lockout.
    async fn clear_ip_lockout(&self, ip: &str) -> Result<()> {
        let _ = ip;
        Ok(())
    }
}

/// Manager for account lockout operations.
pub struct LockoutManager<S: LockoutStore> {
    store: S,
    policy: LockoutPolicy,
}

impl<S: LockoutStore> LockoutManager<S> {
    /// Create a new lockout manager.
    #[must_use]
    pub fn new(store: S, policy: LockoutPolicy) -> Self {
        Self { store, policy }
    }

    /// Create a lockout manager with default policy.
    #[must_use]
    pub fn with_defaults(store: S) -> Self {
        Self::new(store, LockoutPolicy::default())
    }

    /// Check if a user can attempt login.
    ///
    /// Returns the lockout status if blocked, None if allowed.
    pub async fn check_can_attempt(
        &self,
        user_id: &str,
        ip: Option<&str>,
    ) -> Result<Option<LockoutStatus>> {
        // Check user lockout
        if let Some(status) = self.store.get_lockout_status(user_id).await? {
            if !status.can_attempt_now() {
                tracing::debug!(
                    target: "auth.lockout.blocked",
                    user_id = %user_id,
                    is_locked = status.is_locked,
                    remaining_seconds = status.remaining_wait_seconds(),
                    "Login attempt blocked by lockout"
                );
                return Ok(Some(status));
            }
        }

        // Check IP lockout if enabled
        if self.policy.track_by_ip {
            if let Some(ip) = ip.map(truncate_ip) {
                if let Some(locked_until) = self.store.is_ip_locked(ip).await? {
                    if SystemTime::now() < locked_until {
                        tracing::debug!(
                            target: "auth.lockout.ip_blocked",
                            ip = %ip,
                            "Login attempt blocked by IP lockout"
                        );
                        return Ok(Some(LockoutStatus {
                            failed_attempts: 0,
                            is_locked: true,
                            locked_until: Some(locked_until),
                            delay_seconds: None,
                            delay_until: None,
                            last_attempt_at: None,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Record a failed login attempt.
    ///
    /// Returns the result including new lockout status and whether notifications were sent.
    pub async fn record_failed_attempt(
        &self,
        user_id: &str,
        ip: Option<&str>,
    ) -> Result<FailedAttemptResult> {
        let new_count = self.store.increment_failed_attempts(user_id).await?;
        let mut just_locked = false;
        let mut notification_sent = false;

        // Also track by IP if enabled
        if self.policy.track_by_ip {
            if let Some(ip) = ip.map(truncate_ip) {
                let ip_count = self.store.increment_failed_attempts_by_ip(ip).await?;
                if ip_count >= self.policy.max_attempts {
                    let until = SystemTime::now() + self.policy.lockout_duration;
                    self.store.set_lockout_by_ip(ip, until).await?;
                    tracing::warn!(
                        target: "auth.lockout.ip_locked",
                        ip = %ip,
                        attempts = ip_count,
                        duration_secs = self.policy.lockout_duration.as_secs(),
                        "IP address locked out"
                    );
                }
            }
        }

        let now = SystemTime::now();

        // Check if we should lock the account
        if new_count >= self.policy.max_attempts {
            let until = now + self.policy.lockout_duration;
            self.store.set_lockout(user_id, until).await?;
            just_locked = true;

            tracing::warn!(
                target: "auth.lockout.account_locked",
                user_id = %user_id,
                attempts = new_count,
                duration_secs = self.policy.lockout_duration.as_secs(),
                "Account locked due to failed attempts"
            );

            // Send notification if enabled
            if self.policy.send_notifications {
                if let Ok(Some(email)) = self.store.get_user_email(user_id).await {
                    if self
                        .store
                        .send_lockout_notification(user_id, &email, until)
                        .await
                        .is_ok()
                    {
                        notification_sent = true;
                        tracing::info!(
                            target: "auth.lockout.notification_sent",
                            user_id = %user_id,
                            email = %email,
                            "Lockout notification email sent"
                        );
                    }
                }
            }

            return Ok(FailedAttemptResult {
                status: LockoutStatus {
                    failed_attempts: new_count,
                    is_locked: true,
                    locked_until: Some(until),
                    delay_seconds: None,
                    delay_until: None,
                    last_attempt_at: Some(now),
                },
                just_locked,
                notification_sent,
            });
        }

        // Check for progressive delay
        let delay_seconds = self.policy.get_delay_for_attempt(new_count);
        let delay_until = delay_seconds.map(|secs| {
            if secs > 0 {
                now + Duration::from_secs(secs)
            } else {
                now
            }
        });

        if let Some(secs) = delay_seconds {
            if secs > 0 {
                if let Some(until) = delay_until {
                    self.store.set_delay(user_id, until).await?;
                }

                tracing::info!(
                    target: "auth.lockout.delay_applied",
                    user_id = %user_id,
                    attempts = new_count,
                    delay_seconds = secs,
                    "Progressive delay applied"
                );
            }
        }

        Ok(FailedAttemptResult {
            status: LockoutStatus {
                failed_attempts: new_count,
                is_locked: false,
                locked_until: None,
                delay_seconds,
                delay_until,
                last_attempt_at: Some(now),
            },
            just_locked,
            notification_sent,
        })
    }

    /// Record a successful login (clears lockout state).
    pub async fn record_successful_login(&self, user_id: &str, ip: Option<&str>) -> Result<()> {
        self.store.clear_lockout(user_id).await?;

        if self.policy.track_by_ip {
            if let Some(ip) = ip.map(truncate_ip) {
                self.store.clear_ip_lockout(ip).await?;
            }
        }

        tracing::debug!(
            target: "auth.lockout.cleared",
            user_id = %user_id,
            "Lockout state cleared on successful login"
        );

        Ok(())
    }

    /// Admin unlock - forcefully clear lockout for a user.
    pub async fn admin_unlock(&self, user_id: &str, admin_id: &str) -> Result<bool> {
        let had_lockout = self.store.get_lockout_status(user_id).await?.is_some();

        self.store.clear_lockout(user_id).await?;

        tracing::warn!(
            target: "auth.lockout.admin_unlock",
            user_id = %user_id,
            admin_id = %admin_id,
            had_lockout = had_lockout,
            "Account unlocked by admin"
        );

        // Send notification if enabled
        if self.policy.send_notifications && had_lockout {
            if let Ok(Some(email)) = self.store.get_user_email(user_id).await {
                let _ = self.store.send_unlock_notification(user_id, &email).await;
            }
        }

        Ok(had_lockout)
    }

    /// Get the current lockout status for a user.
    pub async fn get_status(&self, user_id: &str) -> Result<Option<LockoutStatus>> {
        self.store.get_lockout_status(user_id).await
    }

    /// Get the current policy.
    #[must_use]
    pub fn policy(&self) -> &LockoutPolicy {
        &self.policy
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// In-memory store for testing.
#[cfg(any(test, feature = "test-auth-bypass"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[derive(Default)]
    struct UserLockoutState {
        failed_attempts: u32,
        locked_until: Option<SystemTime>,
        delay_until: Option<SystemTime>,
        last_attempt_at: Option<SystemTime>,
    }

    /// In-memory lockout store for testing.
    #[derive(Default)]
    pub struct InMemoryLockoutStore {
        users: RwLock<HashMap<String, UserLockoutState>>,
        ips: RwLock<HashMap<String, (u32, Option<SystemTime>)>>,
        emails: RwLock<HashMap<String, String>>,
        notifications: RwLock<Vec<(String, String, String)>>, // (user_id, email, type)
    }

    impl InMemoryLockoutStore {
        /// Create a new in-memory store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Set email for a user (for notification testing).
        pub fn set_email(&self, user_id: &str, email: &str) {
            self.emails
                .write()
                .unwrap()
                .insert(user_id.to_string(), email.to_string());
        }

        /// Get sent notifications.
        pub fn get_notifications(&self) -> Vec<(String, String, String)> {
            self.notifications.read().unwrap().clone()
        }
    }

    #[async_trait]
    impl LockoutStore for InMemoryLockoutStore {
        async fn get_failed_attempts(&self, user_id: &str) -> Result<u32> {
            Ok(self
                .users
                .read()
                .unwrap()
                .get(user_id)
                .map(|s| s.failed_attempts)
                .unwrap_or(0))
        }

        async fn get_lockout_status(&self, user_id: &str) -> Result<Option<LockoutStatus>> {
            let users = self.users.read().unwrap();
            let state = match users.get(user_id) {
                Some(s) => s,
                None => return Ok(None),
            };

            if state.failed_attempts == 0
                && state.locked_until.is_none()
                && state.delay_until.is_none()
            {
                return Ok(None);
            }

            let is_locked = state
                .locked_until
                .map(|until| SystemTime::now() < until)
                .unwrap_or(false);

            Ok(Some(LockoutStatus {
                failed_attempts: state.failed_attempts,
                is_locked,
                locked_until: state.locked_until,
                delay_seconds: None,
                delay_until: state.delay_until,
                last_attempt_at: state.last_attempt_at,
            }))
        }

        async fn increment_failed_attempts(&self, user_id: &str) -> Result<u32> {
            let mut users = self.users.write().unwrap();
            let state = users.entry(user_id.to_string()).or_default();
            state.failed_attempts += 1;
            state.last_attempt_at = Some(SystemTime::now());
            Ok(state.failed_attempts)
        }

        async fn set_lockout(&self, user_id: &str, until: SystemTime) -> Result<()> {
            let mut users = self.users.write().unwrap();
            let state = users.entry(user_id.to_string()).or_default();
            state.locked_until = Some(until);
            Ok(())
        }

        async fn set_delay(&self, user_id: &str, until: SystemTime) -> Result<()> {
            let mut users = self.users.write().unwrap();
            let state = users.entry(user_id.to_string()).or_default();
            state.delay_until = Some(until);
            Ok(())
        }

        async fn clear_lockout(&self, user_id: &str) -> Result<()> {
            let mut users = self.users.write().unwrap();
            users.remove(user_id);
            Ok(())
        }

        async fn get_user_email(&self, user_id: &str) -> Result<Option<String>> {
            Ok(self.emails.read().unwrap().get(user_id).cloned())
        }

        async fn send_lockout_notification(
            &self,
            user_id: &str,
            email: &str,
            _locked_until: SystemTime,
        ) -> Result<()> {
            self.notifications.write().unwrap().push((
                user_id.to_string(),
                email.to_string(),
                "locked".to_string(),
            ));
            Ok(())
        }

        async fn send_unlock_notification(&self, user_id: &str, email: &str) -> Result<()> {
            self.notifications.write().unwrap().push((
                user_id.to_string(),
                email.to_string(),
                "unlocked".to_string(),
            ));
            Ok(())
        }

        async fn get_failed_attempts_by_ip(&self, ip: &str) -> Result<u32> {
            Ok(self
                .ips
                .read()
                .unwrap()
                .get(ip)
                .map(|(count, _)| *count)
                .unwrap_or(0))
        }

        async fn increment_failed_attempts_by_ip(&self, ip: &str) -> Result<u32> {
            let mut ips = self.ips.write().unwrap();
            let entry = ips.entry(ip.to_string()).or_insert((0, None));
            entry.0 += 1;
            Ok(entry.0)
        }

        async fn set_lockout_by_ip(&self, ip: &str, until: SystemTime) -> Result<()> {
            let mut ips = self.ips.write().unwrap();
            let entry = ips.entry(ip.to_string()).or_insert((0, None));
            entry.1 = Some(until);
            Ok(())
        }

        async fn is_ip_locked(&self, ip: &str) -> Result<Option<SystemTime>> {
            Ok(self.ips.read().unwrap().get(ip).and_then(|(_, until)| *until))
        }

        async fn clear_ip_lockout(&self, ip: &str) -> Result<()> {
            self.ips.write().unwrap().remove(ip);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::InMemoryLockoutStore;

    #[test]
    fn test_policy_defaults() {
        let policy = LockoutPolicy::new();
        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.lockout_duration, Duration::from_secs(15 * 60));
        assert!(policy.progressive_delays.is_empty());
        assert!(!policy.send_notifications);
        assert!(!policy.track_by_ip);
    }

    #[test]
    fn test_policy_strict() {
        let policy = LockoutPolicy::strict();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.lockout_duration, Duration::from_secs(30 * 60));
        assert!(!policy.progressive_delays.is_empty());
        assert!(policy.send_notifications);
        assert!(policy.track_by_ip);
    }

    #[test]
    fn test_policy_builder() {
        let policy = LockoutPolicy::new()
            .max_attempts(10)
            .lockout_duration(Duration::from_secs(60))
            .progressive_delays(vec![0, 30, 60])
            .with_notifications()
            .track_by_ip(true);

        assert_eq!(policy.max_attempts, 10);
        assert_eq!(policy.lockout_duration, Duration::from_secs(60));
        assert_eq!(policy.progressive_delays, vec![0, 30, 60]);
        assert!(policy.send_notifications);
        assert!(policy.track_by_ip);
    }

    #[test]
    fn test_get_delay_for_attempt() {
        let policy = LockoutPolicy::new()
            .max_attempts(5)
            .progressive_delays(vec![0, 0, 30, 60]);

        assert_eq!(policy.get_delay_for_attempt(1), Some(0));
        assert_eq!(policy.get_delay_for_attempt(2), Some(0));
        assert_eq!(policy.get_delay_for_attempt(3), Some(30));
        assert_eq!(policy.get_delay_for_attempt(4), Some(60));
        assert_eq!(policy.get_delay_for_attempt(5), None); // Should be locked
    }

    #[test]
    fn test_get_delay_extends_last() {
        let policy = LockoutPolicy::new()
            .max_attempts(10)
            .progressive_delays(vec![0, 30]);

        // Attempts beyond configured delays should use last delay
        assert_eq!(policy.get_delay_for_attempt(3), Some(30));
        assert_eq!(policy.get_delay_for_attempt(9), Some(30));
    }

    #[tokio::test]
    async fn test_record_failed_attempts() {
        let store = InMemoryLockoutStore::new();
        let policy = LockoutPolicy::new().max_attempts(3);
        let manager = LockoutManager::new(store, policy);

        // First attempt
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.failed_attempts, 1);
        assert!(!result.status.is_locked);
        assert!(!result.just_locked);

        // Second attempt
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.failed_attempts, 2);
        assert!(!result.status.is_locked);

        // Third attempt - should trigger lockout
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.failed_attempts, 3);
        assert!(result.status.is_locked);
        assert!(result.just_locked);
        assert!(result.status.locked_until.is_some());
    }

    #[tokio::test]
    async fn test_check_can_attempt_when_locked() {
        let store = InMemoryLockoutStore::new();
        let policy = LockoutPolicy::new().max_attempts(1);
        let manager = LockoutManager::new(store, policy);

        // Lock the account
        manager.record_failed_attempt("user-1", None).await.unwrap();

        // Should not be able to attempt
        let status = manager.check_can_attempt("user-1", None).await.unwrap();
        assert!(status.is_some());
        assert!(status.unwrap().is_locked);
    }

    #[tokio::test]
    async fn test_successful_login_clears_lockout() {
        let store = InMemoryLockoutStore::new();
        let policy = LockoutPolicy::new().max_attempts(3);
        let manager = LockoutManager::new(store, policy);

        // Record some failures
        manager.record_failed_attempt("user-1", None).await.unwrap();
        manager.record_failed_attempt("user-1", None).await.unwrap();

        // Successful login
        manager
            .record_successful_login("user-1", None)
            .await
            .unwrap();

        // Should be able to attempt again with clean slate
        let status = manager.check_can_attempt("user-1", None).await.unwrap();
        assert!(status.is_none());
    }

    #[tokio::test]
    async fn test_admin_unlock() {
        let store = InMemoryLockoutStore::new();
        let policy = LockoutPolicy::new().max_attempts(1);
        let manager = LockoutManager::new(store, policy);

        // Lock the account
        manager.record_failed_attempt("user-1", None).await.unwrap();

        // Verify locked
        let status = manager.check_can_attempt("user-1", None).await.unwrap();
        assert!(status.is_some());

        // Admin unlock
        let had_lockout = manager.admin_unlock("user-1", "admin-1").await.unwrap();
        assert!(had_lockout);

        // Should be unlocked
        let status = manager.check_can_attempt("user-1", None).await.unwrap();
        assert!(status.is_none());
    }

    #[tokio::test]
    async fn test_progressive_delays() {
        let store = InMemoryLockoutStore::new();
        let policy = LockoutPolicy::new()
            .max_attempts(5)
            .progressive_delays(vec![0, 0, 30, 60]);
        let manager = LockoutManager::new(store, policy);

        // First two attempts - no delay
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.delay_seconds, Some(0));

        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.delay_seconds, Some(0));

        // Third attempt - 30 second delay
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.delay_seconds, Some(30));

        // Fourth attempt - 60 second delay
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert_eq!(result.status.delay_seconds, Some(60));
    }

    #[tokio::test]
    async fn test_notifications() {
        let store = InMemoryLockoutStore::new();
        store.set_email("user-1", "user@example.com");

        let policy = LockoutPolicy::new().max_attempts(1).with_notifications();
        let manager = LockoutManager::new(store, policy);

        // Trigger lockout
        let result = manager.record_failed_attempt("user-1", None).await.unwrap();
        assert!(result.notification_sent);

        // Check notification was recorded
        let notifications = manager.store.get_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].0, "user-1");
        assert_eq!(notifications[0].1, "user@example.com");
        assert_eq!(notifications[0].2, "locked");
    }

    #[tokio::test]
    async fn test_ip_tracking() {
        let store = InMemoryLockoutStore::new();
        let policy = LockoutPolicy::new().max_attempts(2).track_by_ip(true);
        let manager = LockoutManager::new(store, policy);

        // Lock by IP
        manager
            .record_failed_attempt("user-1", Some("1.2.3.4"))
            .await
            .unwrap();
        manager
            .record_failed_attempt("user-2", Some("1.2.3.4"))
            .await
            .unwrap();

        // IP should be locked for any user
        let status = manager
            .check_can_attempt("user-3", Some("1.2.3.4"))
            .await
            .unwrap();
        assert!(status.is_some());
        assert!(status.unwrap().is_locked);

        // Different IP should be fine
        let status = manager
            .check_can_attempt("user-3", Some("5.6.7.8"))
            .await
            .unwrap();
        assert!(status.is_none());
    }

    #[test]
    fn test_lockout_status_can_attempt() {
        let now = SystemTime::now();

        // Locked and not expired
        let status = LockoutStatus {
            failed_attempts: 5,
            is_locked: true,
            locked_until: Some(now + Duration::from_secs(60)),
            delay_seconds: None,
            delay_until: None,
            last_attempt_at: Some(now),
        };
        assert!(!status.can_attempt_now());

        // Has delay that hasn't expired
        let status = LockoutStatus {
            failed_attempts: 3,
            is_locked: false,
            locked_until: None,
            delay_seconds: Some(30),
            delay_until: Some(now + Duration::from_secs(30)),
            last_attempt_at: Some(now),
        };
        assert!(!status.can_attempt_now());

        // Not locked, no delay
        let status = LockoutStatus {
            failed_attempts: 2,
            is_locked: false,
            locked_until: None,
            delay_seconds: None,
            delay_until: None,
            last_attempt_at: Some(now),
        };
        assert!(status.can_attempt_now());
    }
}
