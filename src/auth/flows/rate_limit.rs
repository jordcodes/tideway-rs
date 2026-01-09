//! Login-specific rate limiting.
//!
//! Provides IP-based rate limiting for login attempts to protect against
//! brute force attacks. This is separate from the global rate limiting
//! middleware and specifically designed for authentication endpoints.
//!
//! # Tracing Events
//!
//! - `auth.login.rate_limited` - Login blocked due to rate limiting

use crate::error::{Result, TidewayError};
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

/// Configuration for login rate limiting.
#[derive(Clone, Debug)]
pub struct LoginRateLimitConfig {
    /// Maximum login attempts per window.
    pub max_attempts: u32,
    /// Time window in seconds.
    pub window_seconds: u64,
}

impl Default for LoginRateLimitConfig {
    fn default() -> Self {
        Self {
            // 5 login attempts per 15 minutes is a reasonable default
            // This is per-IP, so legitimate users on shared IPs may need higher limits
            max_attempts: 5,
            window_seconds: 900, // 15 minutes
        }
    }
}

impl LoginRateLimitConfig {
    /// Create a new configuration with specified limits.
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            max_attempts,
            window_seconds,
        }
    }

    /// Create a strict configuration for high-security applications.
    ///
    /// Allows only 3 attempts per 30 minutes.
    pub fn strict() -> Self {
        Self {
            max_attempts: 3,
            window_seconds: 1800, // 30 minutes
        }
    }

    /// Create a lenient configuration for user-facing applications.
    ///
    /// Allows 10 attempts per 15 minutes.
    pub fn lenient() -> Self {
        Self {
            max_attempts: 10,
            window_seconds: 900, // 15 minutes
        }
    }
}

/// Type alias for the keyed rate limiter
type KeyedLimiter =
    RateLimiter<String, DashMapStateStore<String>, DefaultClock, NoOpMiddleware>;

/// Rate limiter for login attempts, keyed by IP address.
///
/// This provides brute force protection at the IP level, complementing
/// the per-user lockout mechanism in `UserStore::record_failed_attempt`.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::flows::{LoginFlow, LoginRateLimiter, LoginRateLimitConfig};
///
/// let rate_limiter = LoginRateLimiter::new(LoginRateLimitConfig::default());
///
/// let flow = LoginFlow::new(user_store, mfa_store, token_issuer, config)
///     .with_rate_limiter(rate_limiter);
///
/// // In your handler:
/// async fn login_handler(
///     ConnectInfo(addr): ConnectInfo<SocketAddr>,
///     State(flow): State<LoginFlow<...>>,
///     Json(req): Json<LoginRequest>,
/// ) -> Result<Json<LoginResponse>> {
///     let response = flow.login_with_ip(req, Some(addr.ip().to_string())).await?;
///     Ok(Json(response))
/// }
/// ```
#[derive(Clone)]
pub struct LoginRateLimiter {
    limiter: Arc<KeyedLimiter>,
    config: LoginRateLimitConfig,
    request_count: Arc<AtomicU64>,
}

impl LoginRateLimiter {
    /// Create a new login rate limiter with the given configuration.
    pub fn new(config: LoginRateLimitConfig) -> Self {
        let max_attempts = NonZeroU32::new(config.max_attempts.max(1))
            .expect("max_attempts should be positive");

        // Create quota: max_attempts per window_seconds
        let quota = Quota::with_period(Duration::from_secs(config.window_seconds))
            .expect("window_seconds should be positive")
            .allow_burst(max_attempts);

        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
            config,
            request_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check if a login attempt from the given IP is allowed.
    ///
    /// Returns `Ok(())` if allowed, or `Err` with retry-after seconds if blocked.
    pub fn check(&self, ip: &str) -> std::result::Result<(), u64> {
        // Periodically shrink the state store
        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        if count % SHRINK_INTERVAL == 0 && count > 0 {
            self.limiter.retain_recent();
        }

        match self.limiter.check_key(&ip.to_string()) {
            Ok(_) => Ok(()),
            Err(not_until) => {
                let wait = not_until
                    .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
                Err(wait.as_secs().max(1))
            }
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &LoginRateLimitConfig {
        &self.config
    }
}

/// Trait for optional rate limiter in LoginFlow.
pub trait OptionalRateLimiter: Send + Sync + Clone {
    /// Check rate limit, returning error if blocked.
    fn check_rate_limit(&self, ip: Option<&str>) -> Result<()>;
}

/// No-op implementation when rate limiting is not configured.
impl OptionalRateLimiter for () {
    fn check_rate_limit(&self, _ip: Option<&str>) -> Result<()> {
        Ok(())
    }
}

/// Wrapper to use a real LoginRateLimiter.
#[derive(Clone)]
pub struct WithRateLimiter(pub LoginRateLimiter);

impl OptionalRateLimiter for WithRateLimiter {
    fn check_rate_limit(&self, ip: Option<&str>) -> Result<()> {
        let Some(ip) = ip else {
            // No IP provided, allow the request
            // (caller should provide IP when possible)
            return Ok(());
        };

        match self.0.check(ip) {
            Ok(()) => Ok(()),
            Err(retry_after) => {
                tracing::warn!(
                    target: "auth.login.rate_limited",
                    ip = %ip,
                    retry_after_secs = retry_after,
                    max_attempts = self.0.config.max_attempts,
                    window_secs = self.0.config.window_seconds,
                    "Login rate limited"
                );
                Err(TidewayError::TooManyRequests(format!(
                    "Too many login attempts. Please try again in {} seconds.",
                    retry_after
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_requests_under_limit() {
        let config = LoginRateLimitConfig::new(5, 60);
        let limiter = LoginRateLimiter::new(config);

        // Should allow 5 requests
        for i in 0..5 {
            let result = limiter.check("192.168.1.1");
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }
    }

    #[test]
    fn test_rate_limit_blocks_requests_over_limit() {
        let config = LoginRateLimitConfig::new(5, 60);
        let limiter = LoginRateLimiter::new(config);

        // Use up the quota
        for _ in 0..5 {
            limiter.check("192.168.1.1").unwrap();
        }

        // 6th request should be blocked
        let result = limiter.check("192.168.1.1");
        assert!(result.is_err(), "6th request should be blocked");
    }

    #[test]
    fn test_rate_limit_per_ip_isolation() {
        let config = LoginRateLimitConfig::new(5, 60);
        let limiter = LoginRateLimiter::new(config);

        // Fill quota for IP 1
        for _ in 0..5 {
            limiter.check("192.168.1.1").unwrap();
        }

        // IP 2 should still be allowed
        let result = limiter.check("192.168.1.2");
        assert!(result.is_ok(), "Different IP should have separate quota");
    }

    #[test]
    fn test_rate_limit_returns_retry_after() {
        let config = LoginRateLimitConfig::new(1, 60);
        let limiter = LoginRateLimiter::new(config);

        // Use up the single allowed request
        limiter.check("192.168.1.1").unwrap();

        // Second request should be blocked with retry_after
        let result = limiter.check("192.168.1.1");
        assert!(result.is_err());
        if let Err(retry_after) = result {
            assert!(retry_after > 0, "Should return positive retry_after");
            assert!(retry_after <= 60, "retry_after should be within window");
        }
    }

    #[test]
    fn test_optional_rate_limiter_noop() {
        let noop: () = ();
        // Should always succeed
        assert!(noop.check_rate_limit(Some("192.168.1.1")).is_ok());
        assert!(noop.check_rate_limit(None).is_ok());
    }

    #[test]
    fn test_optional_rate_limiter_with_limiter() {
        let config = LoginRateLimitConfig::new(2, 60);
        let limiter = WithRateLimiter(LoginRateLimiter::new(config));

        // Should allow 2 requests
        assert!(limiter.check_rate_limit(Some("192.168.1.1")).is_ok());
        assert!(limiter.check_rate_limit(Some("192.168.1.1")).is_ok());

        // Third should be blocked
        assert!(limiter.check_rate_limit(Some("192.168.1.1")).is_err());

        // No IP should be allowed
        assert!(limiter.check_rate_limit(None).is_ok());
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let config = LoginRateLimitConfig::new(100, 60);
        let limiter = LoginRateLimiter::new(config);

        // Spawn multiple threads
        let mut handles = vec![];
        for i in 0..10 {
            let limiter = limiter.clone();
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let ip = format!("192.168.{}.{}", i, j % 256);
                    let _ = limiter.check(&ip);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should still work after concurrent access
        let result = limiter.check("10.0.0.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_presets() {
        let default = LoginRateLimitConfig::default();
        assert_eq!(default.max_attempts, 5);
        assert_eq!(default.window_seconds, 900);

        let strict = LoginRateLimitConfig::strict();
        assert_eq!(strict.max_attempts, 3);
        assert_eq!(strict.window_seconds, 1800);

        let lenient = LoginRateLimitConfig::lenient();
        assert_eq!(lenient.max_attempts, 10);
        assert_eq!(lenient.window_seconds, 900);
    }
}
