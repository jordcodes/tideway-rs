//! Invitation rate limiting.
//!
//! Provides rate limiting for invitation operations to prevent abuse.
//!
//! # Tracing Events
//!
//! - `orgs.invitation.rate_limited` - Invitation blocked due to rate limiting

use super::error::{OrganizationError, Result};
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::keyed::DashMapStateStore,
    Quota, RateLimiter,
};
use std::{
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

/// Shrink the state store every N requests to prevent unbounded memory growth.
const SHRINK_INTERVAL: u64 = 1000;

/// Configuration for invitation rate limiting.
#[derive(Clone, Debug)]
pub struct InvitationRateLimitConfig {
    /// Maximum invitations per organization per window.
    pub max_per_org: u32,
    /// Maximum invitations per actor (user) per window.
    pub max_per_actor: u32,
    /// Time window in seconds.
    pub window_seconds: u64,
}

impl Default for InvitationRateLimitConfig {
    fn default() -> Self {
        Self {
            // 50 invitations per org per hour is reasonable for most use cases
            max_per_org: 50,
            // 20 invitations per actor per hour
            max_per_actor: 20,
            window_seconds: 3600, // 1 hour
        }
    }
}

impl InvitationRateLimitConfig {
    /// Create a new configuration with specified limits.
    pub fn new(max_per_org: u32, max_per_actor: u32, window_seconds: u64) -> Self {
        Self {
            max_per_org,
            max_per_actor,
            window_seconds,
        }
    }

    /// Create a strict configuration for high-security applications.
    ///
    /// Allows only 10 invitations per org and 5 per actor per hour.
    pub fn strict() -> Self {
        Self {
            max_per_org: 10,
            max_per_actor: 5,
            window_seconds: 3600,
        }
    }

    /// Create a lenient configuration for larger organizations.
    ///
    /// Allows 200 invitations per org and 50 per actor per hour.
    pub fn lenient() -> Self {
        Self {
            max_per_org: 200,
            max_per_actor: 50,
            window_seconds: 3600,
        }
    }
}

/// Type alias for the keyed rate limiter
type KeyedLimiter =
    RateLimiter<String, DashMapStateStore<String>, DefaultClock, NoOpMiddleware>;

/// Rate limiter for invitation operations.
///
/// Provides dual rate limiting:
/// - Per organization: prevents bulk invitation spam to any single org
/// - Per actor: prevents a single user from sending too many invitations
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{InvitationManager, InvitationRateLimiter, InvitationRateLimitConfig};
///
/// let rate_limiter = InvitationRateLimiter::new(InvitationRateLimitConfig::default());
///
/// let manager = InvitationManager::new(...)
///     .with_rate_limiter(rate_limiter);
/// ```
#[derive(Clone)]
pub struct InvitationRateLimiter {
    org_limiter: Arc<KeyedLimiter>,
    actor_limiter: Arc<KeyedLimiter>,
    config: InvitationRateLimitConfig,
    request_count: Arc<AtomicU64>,
}

impl InvitationRateLimiter {
    /// Create a new invitation rate limiter with the given configuration.
    pub fn new(config: InvitationRateLimitConfig) -> Self {
        let max_per_org = NonZeroU32::new(config.max_per_org.max(1))
            .expect("max_per_org should be positive");
        let max_per_actor = NonZeroU32::new(config.max_per_actor.max(1))
            .expect("max_per_actor should be positive");

        let window = Duration::from_secs(config.window_seconds);

        let org_quota = Quota::with_period(window)
            .expect("window_seconds should be positive")
            .allow_burst(max_per_org);

        let actor_quota = Quota::with_period(window)
            .expect("window_seconds should be positive")
            .allow_burst(max_per_actor);

        Self {
            org_limiter: Arc::new(RateLimiter::keyed(org_quota)),
            actor_limiter: Arc::new(RateLimiter::keyed(actor_quota)),
            config,
            request_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check if an invitation from the given actor to the given org is allowed.
    ///
    /// Returns `Ok(())` if allowed, or `Err` with retry-after seconds if blocked.
    pub fn check(&self, org_id: &str, actor_id: &str) -> std::result::Result<(), (String, u64)> {
        // Periodically shrink the state stores
        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        if count % SHRINK_INTERVAL == 0 && count > 0 {
            self.org_limiter.retain_recent();
            self.actor_limiter.retain_recent();
        }

        // Check org limit first
        if let Err(not_until) = self.org_limiter.check_key(&org_id.to_string()) {
            let wait = not_until
                .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
            return Err(("organization".to_string(), wait.as_secs().max(1)));
        }

        // Then check actor limit
        if let Err(not_until) = self.actor_limiter.check_key(&actor_id.to_string()) {
            let wait = not_until
                .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
            return Err(("actor".to_string(), wait.as_secs().max(1)));
        }

        Ok(())
    }

    /// Get the configuration.
    pub fn config(&self) -> &InvitationRateLimitConfig {
        &self.config
    }
}

/// Trait for optional rate limiter in InvitationManager.
pub trait OptionalInvitationRateLimiter: Send + Sync + Clone + 'static {
    /// Check rate limit, returning error if blocked.
    fn check_invitation_rate(&self, org_id: &str, actor_id: &str) -> Result<()>;
}

/// No-op implementation when rate limiting is not configured.
impl OptionalInvitationRateLimiter for () {
    fn check_invitation_rate(&self, _org_id: &str, _actor_id: &str) -> Result<()> {
        Ok(())
    }
}

/// Wrapper to use a real InvitationRateLimiter.
#[derive(Clone)]
pub struct WithInvitationRateLimiter(pub InvitationRateLimiter);

impl OptionalInvitationRateLimiter for WithInvitationRateLimiter {
    fn check_invitation_rate(&self, org_id: &str, actor_id: &str) -> Result<()> {
        match self.0.check(org_id, actor_id) {
            Ok(()) => Ok(()),
            Err((limit_type, retry_after)) => {
                tracing::warn!(
                    target: "orgs.invitation.rate_limited",
                    org_id = %org_id,
                    actor_id = %actor_id,
                    limit_type = %limit_type,
                    retry_after_secs = retry_after,
                    max_per_org = self.0.config.max_per_org,
                    max_per_actor = self.0.config.max_per_actor,
                    window_secs = self.0.config.window_seconds,
                    "Invitation rate limited"
                );
                Err(OrganizationError::RateLimited {
                    retry_after_seconds: retry_after,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_requests_under_limit() {
        let config = InvitationRateLimitConfig::new(5, 3, 60);
        let limiter = InvitationRateLimiter::new(config);

        // Should allow 3 requests (limited by actor)
        for i in 0..3 {
            let result = limiter.check("org_1", "actor_1");
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }
    }

    #[test]
    fn test_rate_limit_blocks_requests_over_actor_limit() {
        let config = InvitationRateLimitConfig::new(10, 3, 60);
        let limiter = InvitationRateLimiter::new(config);

        // Use up the actor quota
        for _ in 0..3 {
            limiter.check("org_1", "actor_1").unwrap();
        }

        // 4th request should be blocked by actor limit
        let result = limiter.check("org_1", "actor_1");
        assert!(result.is_err(), "4th request should be blocked");
        if let Err((limit_type, _)) = result {
            assert_eq!(limit_type, "actor");
        }
    }

    #[test]
    fn test_rate_limit_blocks_requests_over_org_limit() {
        let config = InvitationRateLimitConfig::new(3, 10, 60);
        let limiter = InvitationRateLimiter::new(config);

        // Use up the org quota with different actors
        for i in 0..3 {
            limiter.check("org_1", &format!("actor_{i}")).unwrap();
        }

        // 4th request should be blocked by org limit
        let result = limiter.check("org_1", "actor_new");
        assert!(result.is_err(), "4th request should be blocked");
        if let Err((limit_type, _)) = result {
            assert_eq!(limit_type, "organization");
        }
    }

    #[test]
    fn test_rate_limit_per_org_isolation() {
        let config = InvitationRateLimitConfig::new(3, 10, 60);
        let limiter = InvitationRateLimiter::new(config);

        // Fill quota for org 1
        for _ in 0..3 {
            limiter.check("org_1", "actor_1").unwrap();
        }

        // Org 2 should still be allowed
        let result = limiter.check("org_2", "actor_1");
        assert!(result.is_ok(), "Different org should have separate quota");
    }

    #[test]
    fn test_rate_limit_per_actor_isolation() {
        let config = InvitationRateLimitConfig::new(10, 3, 60);
        let limiter = InvitationRateLimiter::new(config);

        // Fill quota for actor 1
        for _ in 0..3 {
            limiter.check("org_1", "actor_1").unwrap();
        }

        // Actor 2 should still be allowed
        let result = limiter.check("org_1", "actor_2");
        assert!(result.is_ok(), "Different actor should have separate quota");
    }

    #[test]
    fn test_optional_rate_limiter_noop() {
        let noop: () = ();
        // Should always succeed
        assert!(noop.check_invitation_rate("org_1", "actor_1").is_ok());
    }

    #[test]
    fn test_optional_rate_limiter_with_limiter() {
        let config = InvitationRateLimitConfig::new(10, 2, 60);
        let limiter = WithInvitationRateLimiter(InvitationRateLimiter::new(config));

        // Should allow 2 requests
        assert!(limiter.check_invitation_rate("org_1", "actor_1").is_ok());
        assert!(limiter.check_invitation_rate("org_1", "actor_1").is_ok());

        // Third should be blocked
        assert!(limiter.check_invitation_rate("org_1", "actor_1").is_err());
    }

    #[test]
    fn test_config_presets() {
        let default = InvitationRateLimitConfig::default();
        assert_eq!(default.max_per_org, 50);
        assert_eq!(default.max_per_actor, 20);
        assert_eq!(default.window_seconds, 3600);

        let strict = InvitationRateLimitConfig::strict();
        assert_eq!(strict.max_per_org, 10);
        assert_eq!(strict.max_per_actor, 5);
        assert_eq!(strict.window_seconds, 3600);

        let lenient = InvitationRateLimitConfig::lenient();
        assert_eq!(lenient.max_per_org, 200);
        assert_eq!(lenient.max_per_actor, 50);
        assert_eq!(lenient.window_seconds, 3600);
    }
}
