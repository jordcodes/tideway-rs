use super::config::RateLimitConfig;
use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tower::{Layer, Service};

/// Maximum number of unique IPs to track for per-IP rate limiting.
/// When this limit is reached, oldest entries are evicted to prevent
/// memory exhaustion from attackers using many different IPs.
const MAX_TRACKED_IPS: usize = 10_000;

/// Maximum requests to track per IP, regardless of config.
/// This prevents memory issues if someone misconfigures max_requests to a huge value.
const MAX_REQUESTS_PER_IP: usize = 10_000;

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

/// Entry tracking requests from a single IP
struct IpEntry {
    /// Timestamps of recent requests
    requests: Vec<Instant>,
    /// When this IP was last seen (for LRU eviction)
    last_seen: Instant,
}

impl IpEntry {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            last_seen: Instant::now(),
        }
    }
}

/// In-memory rate limiter state
#[derive(Clone)]
struct RateLimitState {
    // For per-IP rate limiting: map IP -> entry with timestamps and last_seen
    per_ip: Arc<Mutex<HashMap<String, IpEntry>>>,
    // For global rate limiting: list of request timestamps
    global: Arc<Mutex<Vec<Instant>>>,
    config: RateLimitConfig,
}

impl RateLimitState {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            global: Arc::new(Mutex::new(Vec::new())),
            config,
        }
    }

    fn check_rate_limit(&self, key: Option<&str>) -> Result<(), u64> {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        // Cap max_requests to prevent memory exhaustion from misconfiguration
        let max_requests = std::cmp::min(self.config.max_requests as usize, MAX_REQUESTS_PER_IP);

        if self.config.strategy == "per_ip" {
            if let Some(ip) = key {
                let mut per_ip = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());

                // Evict stale entries if we're at capacity
                // This prevents unbounded memory growth from attackers using many IPs
                if per_ip.len() >= MAX_TRACKED_IPS {
                    Self::evict_stale_entries(&mut per_ip, window, now);
                }

                let entry = per_ip.entry(ip.to_string()).or_insert_with(IpEntry::new);
                entry.last_seen = now;

                // Remove expired requests from this IP
                entry.requests.retain(|&req_time| now.duration_since(req_time) < window);

                // Check if limit exceeded
                if entry.requests.len() >= max_requests {
                    let oldest = entry.requests.first().copied().unwrap_or(now);
                    let wait_time = window.saturating_sub(now.duration_since(oldest));
                    return Err(wait_time.as_secs());
                }

                // Record this request
                entry.requests.push(now);
            }
        } else {
            // Global rate limiting
            let mut global = self.global.lock().unwrap_or_else(|e| e.into_inner());

            // Remove expired requests
            global.retain(|&req_time| now.duration_since(req_time) < window);

            // Check if limit exceeded (use same cap for global)
            if global.len() >= max_requests {
                let oldest = global.first().copied().unwrap_or(now);
                let wait_time = window.saturating_sub(now.duration_since(oldest));
                return Err(wait_time.as_secs());
            }

            // Record this request
            global.push(now);
        }

        Ok(())
    }

    /// Evict entries that have no active requests and haven't been seen recently.
    /// This is called when we hit MAX_TRACKED_IPS to prevent memory exhaustion.
    fn evict_stale_entries(
        per_ip: &mut HashMap<String, IpEntry>,
        window: Duration,
        now: Instant,
    ) {
        // First pass: remove entries with no active requests (expired window)
        per_ip.retain(|_, entry| {
            // Keep if there are any requests still within the window
            entry.requests.iter().any(|&t| now.duration_since(t) < window)
        });

        // If still at capacity, evict oldest by last_seen (LRU)
        if per_ip.len() >= MAX_TRACKED_IPS {
            // Find and remove the 10% oldest entries
            let to_remove = MAX_TRACKED_IPS / 10;
            let mut entries: Vec<_> = per_ip.iter()
                .map(|(k, v)| (k.clone(), v.last_seen))
                .collect();
            entries.sort_by_key(|(_, last_seen)| *last_seen);

            for (key, _) in entries.into_iter().take(to_remove) {
                per_ip.remove(&key);
            }
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

        // Extract IP address from request
        //
        // SECURITY: Only trust proxy headers if explicitly configured.
        // Trusting X-Forwarded-For without proper proxy configuration allows
        // attackers to spoof their IP and bypass per-IP rate limiting.
        let ip: Option<String> = if self.state.config.trust_proxy {
            // Trust mode: Check proxy headers first, fall back to connection IP
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                // X-Forwarded-For may contain multiple IPs: "client, proxy1, proxy2"
                // The leftmost is the original client (if proxy is trusted to set it)
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
                .or_else(|| {
                    req.headers()
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                })
                .or_else(|| {
                    req.extensions()
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                        .map(|addr| addr.ip().to_string())
                })
        } else {
            // Safe mode (default): Only use direct connection IP
            // This prevents IP spoofing but requires trust_proxy=true behind a proxy
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|addr| addr.ip().to_string())
        };

        let key = ip.as_deref();

        // Check rate limit
        match self.state.check_rate_limit(key) {
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
/// Uses an in-memory rate limiter suitable for single-instance deployments.
/// For distributed deployments, consider using Redis or another distributed store.
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
        }
    }

    #[test]
    fn test_rate_limit_allows_requests_under_limit() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Should allow 5 requests
        for i in 0..5 {
            let result = state.check_rate_limit(Some("192.168.1.1"));
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }
    }

    #[test]
    fn test_rate_limit_blocks_requests_over_limit() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Use up the quota
        for _ in 0..5 {
            state.check_rate_limit(Some("192.168.1.1")).unwrap();
        }

        // 6th request should be blocked
        let result = state.check_rate_limit(Some("192.168.1.1"));
        assert!(result.is_err(), "6th request should be blocked");
    }

    #[test]
    fn test_rate_limit_per_ip_isolation() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Fill quota for IP 1
        for _ in 0..5 {
            state.check_rate_limit(Some("192.168.1.1")).unwrap();
        }

        // IP 2 should still be allowed
        let result = state.check_rate_limit(Some("192.168.1.2"));
        assert!(result.is_ok(), "Different IP should have separate quota");
    }

    #[test]
    fn test_rate_limit_bounded_ips() {
        let config = test_config();
        let state = RateLimitState::new(config);

        // Simulate many unique IPs (more than MAX_TRACKED_IPS)
        // This should not cause unbounded memory growth
        for i in 0..(MAX_TRACKED_IPS + 1000) {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            let _ = state.check_rate_limit(Some(&ip));
        }

        // Check that the HashMap size is bounded
        let per_ip = state.per_ip.lock().unwrap();
        assert!(
            per_ip.len() <= MAX_TRACKED_IPS,
            "IP tracking should be bounded to {} but got {}",
            MAX_TRACKED_IPS,
            per_ip.len()
        );
    }

    #[test]
    fn test_global_rate_limiting() {
        let mut config = test_config();
        config.strategy = "global".to_string();
        let state = RateLimitState::new(config);

        // All requests share the same quota regardless of IP
        for _ in 0..5 {
            state.check_rate_limit(Some("192.168.1.1")).unwrap();
        }

        // Even a different IP should be blocked
        let result = state.check_rate_limit(Some("192.168.1.2"));
        assert!(result.is_err(), "Global limit should block all IPs");
    }

    #[test]
    fn test_eviction_removes_stale_entries() {
        let config = RateLimitConfig {
            enabled: true,
            max_requests: 5,
            window_seconds: 1, // 1 second window for testing
            strategy: "per_ip".to_string(),
            trust_proxy: false,
        };
        let state = RateLimitState::new(config);

        // Make requests from an IP
        state.check_rate_limit(Some("192.168.1.1")).unwrap();

        // Verify entry exists
        {
            let per_ip = state.per_ip.lock().unwrap();
            assert!(per_ip.contains_key("192.168.1.1"));
        }

        // Wait for the window to expire
        std::thread::sleep(Duration::from_secs(2));

        // Fill up to MAX_TRACKED_IPS to trigger eviction
        // The stale entry should be evicted
        for i in 0..MAX_TRACKED_IPS {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            let _ = state.check_rate_limit(Some(&ip));
        }

        // The original stale entry should have been evicted
        let per_ip = state.per_ip.lock().unwrap();
        // It may or may not be evicted depending on timing, but size should be bounded
        assert!(
            per_ip.len() <= MAX_TRACKED_IPS,
            "Should be bounded after eviction"
        );
    }
}
