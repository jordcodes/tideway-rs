//! Rate limiting layer backed by governor
//!
//! Uses the governor crate for a production-grade rate limiter with:
//! - Lock-free atomic operations (GCRA algorithm)
//! - Per-IP rate limiting with keyed rate limiters
//! - Automatic cleanup of stale entries via periodic shrinking
//! - High performance under concurrent load

use super::{client_ip::ClientIpResolver, config::RateLimitConfig};
use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
};
use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tower::{Layer, Service};

/// Shrink the keyed state store every N requests to prevent unbounded memory growth.
/// This is a balance between memory efficiency and performance overhead.
const SHRINK_INTERVAL: u64 = 1000;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ClientKey {
    Ip(std::net::IpAddr),
    Unknown,
}

/// Custom error response for rate limit exceeded
#[derive(serde::Serialize)]
struct RateLimitError {
    error: String,
    message: String,
    retry_after: u64,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", self.retry_after.to_string())],
            axum::Json(self),
        )
            .into_response()
    }
}

/// Type alias for a global (non-keyed) rate limiter
type GlobalLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Type alias for a per-IP (keyed) rate limiter
type KeyedLimiter = RateLimiter<
    ClientKey,
    governor::state::keyed::DashMapStateStore<ClientKey>,
    DefaultClock,
    NoOpMiddleware,
>;

/// Rate limiter state that can be either global or per-IP
#[derive(Clone)]
enum LimiterState {
    Global(Arc<GlobalLimiter>),
    PerIp(Arc<KeyedLimiter>),
}

/// Rate limiter state and configuration
#[derive(Clone)]
struct RateLimitState {
    limiter: LimiterState,
    client_ip_resolver: ClientIpResolver,
    /// Counter for periodic shrinking of keyed state store
    request_count: Arc<AtomicU64>,
}

impl RateLimitState {
    fn new(config: RateLimitConfig) -> Self {
        let max_requests = NonZeroU32::new(config.max_requests.max(1)).unwrap_or(NonZeroU32::MIN);

        // Create quota: max_requests per window_seconds
        let quota =
            Quota::with_period(std::time::Duration::from_secs(config.window_seconds.max(1)))
                .unwrap_or_else(|| Quota::per_second(max_requests))
                .allow_burst(max_requests);

        let limiter = if config.strategy == "per_ip" {
            LimiterState::PerIp(Arc::new(RateLimiter::keyed(quota)))
        } else {
            LimiterState::Global(Arc::new(RateLimiter::direct(quota)))
        };

        let client_ip_resolver = match ClientIpResolver::new(&config.trusted_proxies) {
            Ok(resolver) => resolver,
            Err(error) => {
                tracing::error!(%error, "invalid rate-limit trusted proxy configuration; forwarded headers will be ignored");
                ClientIpResolver::default()
            }
        };

        if config.trust_proxy && client_ip_resolver.is_empty() {
            tracing::warn!(
                "RATE_LIMIT_TRUST_PROXY no longer trusts forwarded headers without RATE_LIMIT_TRUSTED_PROXIES; using the direct peer IP"
            );
        }

        Self {
            limiter,
            client_ip_resolver,
            request_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn check_rate_limit(&self, ip: Option<std::net::IpAddr>) -> Result<(), u64> {
        match &self.limiter {
            LimiterState::PerIp(limiter) => {
                // Periodically shrink the state store to remove stale entries
                // This prevents unbounded memory growth from many unique IPs
                let count = self.request_count.fetch_add(1, Ordering::Relaxed);
                if count.is_multiple_of(SHRINK_INTERVAL) && count > 0 {
                    limiter.retain_recent();
                }

                let key = ip.map(ClientKey::Ip).unwrap_or(ClientKey::Unknown);
                match limiter.check_key(&key) {
                    Ok(_) => Ok(()),
                    Err(not_until) => {
                        let wait = not_until
                            .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
                        Err(wait.as_secs().max(1))
                    }
                }
            }
            LimiterState::Global(limiter) => match limiter.check() {
                Ok(_) => Ok(()),
                Err(not_until) => {
                    let wait = not_until
                        .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
                    Err(wait.as_secs().max(1))
                }
            },
        }
    }
}

/// Tower layer for rate limiting
#[derive(Clone)]
pub struct RateLimitLayer {
    state: RateLimitState,
}

impl RateLimitLayer {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            state: RateLimitState::new(config),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Tower service for rate limiting
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    state: RateLimitState,
}

impl<S> Service<Request> for RateLimitService<S>
where
    S: Service<Request> + Clone + Send + Sync + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // Skip rate limiting for health check endpoints
        let path = req.uri().path();
        if path == "/health" || path.starts_with("/health/") {
            let mut svc = self.inner.clone();
            return Box::pin(async move {
                let response = svc.call(req).await?;
                Ok(response.into_response())
            });
        }

        // Forwarded headers are only considered when the socket peer belongs to
        // the explicit trusted-proxy allowlist. Without ConnectInfo, requests use
        // the shared unknown bucket rather than an attacker-controlled header.
        let ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|address| {
                self.state
                    .client_ip_resolver
                    .resolve(address.ip(), req.headers())
            });

        // Check rate limit
        match self.state.check_rate_limit(ip) {
            Ok(()) => {
                let mut svc = self.inner.clone();
                Box::pin(async move {
                    let response = svc.call(req).await?;
                    Ok(response.into_response())
                })
            }
            Err(retry_after) => {
                let error = RateLimitError {
                    error: "rate_limit_exceeded".to_string(),
                    message: format!(
                        "Rate limit exceeded. Please try again in {} seconds",
                        retry_after
                    ),
                    retry_after,
                };
                Box::pin(async move { Ok(error.into_response()) })
            }
        }
    }
}

/// Build a rate limit layer from RateLimitConfig
///
/// Returns None if rate limiting is disabled.
/// Uses governor's GCRA algorithm for efficient, lock-free rate limiting.
/// For per-IP rate limiting, uses a DashMap-backed keyed rate limiter.
pub fn build_rate_limit_layer(config: &RateLimitConfig) -> Option<RateLimitLayer> {
    if !config.enabled {
        return None;
    }

    Some(RateLimitLayer::new(config.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            max_requests: 5,
            window_seconds: 60,
            strategy: "per_ip".to_string(),
            trust_proxy: false,
            trusted_proxies: Vec::new(),
        }
    }

    fn ip(value: &str) -> std::net::IpAddr {
        value.parse().expect("valid test IP")
    }

    #[test]
    fn test_rate_limit_allows_requests_under_limit() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Should allow 5 requests (burst size)
        for i in 0..5 {
            let result = state.check_rate_limit(Some(ip("192.168.1.1")));
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }
    }

    #[test]
    fn test_rate_limit_blocks_requests_over_limit() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Use up the quota (burst)
        for _ in 0..5 {
            state.check_rate_limit(Some(ip("192.168.1.1"))).unwrap();
        }

        // 6th request should be blocked
        let result = state.check_rate_limit(Some(ip("192.168.1.1")));
        assert!(result.is_err(), "6th request should be blocked");
    }

    #[test]
    fn test_rate_limit_per_ip_isolation() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Fill quota for IP 1
        for _ in 0..5 {
            state.check_rate_limit(Some(ip("192.168.1.1"))).unwrap();
        }

        // IP 2 should still be allowed
        let result = state.check_rate_limit(Some(ip("192.168.1.2")));
        assert!(result.is_ok(), "Different IP should have separate quota");
    }

    #[test]
    fn test_global_rate_limiting() {
        let mut config = test_config();
        config.strategy = "global".to_string();
        let state = RateLimitState::new(config);

        // All requests share the same quota regardless of IP
        for _ in 0..5 {
            state.check_rate_limit(Some(ip("192.168.1.1"))).unwrap();
        }

        // Even a different IP should be blocked
        let result = state.check_rate_limit(Some(ip("192.168.1.2")));
        assert!(result.is_err(), "Global limit should block all IPs");
    }

    #[test]
    fn test_rate_limit_returns_retry_after() {
        let config = RateLimitConfig {
            enabled: true,
            max_requests: 1,
            window_seconds: 60,
            strategy: "per_ip".to_string(),
            trust_proxy: false,
            trusted_proxies: Vec::new(),
        };
        let state = RateLimitState::new(config);

        // Use up the single allowed request
        state.check_rate_limit(Some(ip("192.168.1.1"))).unwrap();

        // Second request should be blocked with retry_after
        let result = state.check_rate_limit(Some(ip("192.168.1.1")));
        assert!(result.is_err());
        if let Err(retry_after) = result {
            assert!(retry_after > 0, "Should return positive retry_after");
            assert!(retry_after <= 60, "retry_after should be within window");
        }
    }

    #[test]
    fn test_missing_ip_uses_shared_bucket() {
        let config = RateLimitConfig {
            enabled: true,
            max_requests: 1,
            window_seconds: 60,
            strategy: "per_ip".to_string(),
            trust_proxy: false,
            trusted_proxies: Vec::new(),
        };
        let state = RateLimitState::new(config);

        assert!(state.check_rate_limit(None).is_ok());
        assert!(state.check_rate_limit(None).is_err());
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let config = RateLimitConfig {
            enabled: true,
            max_requests: 100,
            window_seconds: 60,
            strategy: "per_ip".to_string(),
            trust_proxy: false,
            trusted_proxies: Vec::new(),
        };
        let state = RateLimitState::new(config);

        // Spawn multiple threads to access the rate limiter concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let state = state.clone();
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let address = format!("192.168.{}.{}", i, j % 256);
                    let _ = state.check_rate_limit(Some(ip(&address)));
                }
            }));
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Rate limiter should still be functional
        let result = state.check_rate_limit(Some(ip("10.0.0.1")));
        assert!(result.is_ok(), "Should still work after concurrent access");
    }
}
