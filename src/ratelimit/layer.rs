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

/// In-memory rate limiter state
#[derive(Clone)]
struct RateLimitState {
    // For per-IP rate limiting: map IP -> list of request timestamps
    per_ip: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
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
        let max_requests = self.config.max_requests as usize;

        if self.config.strategy == "per_ip" {
            if let Some(ip) = key {
                let mut per_ip = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
                let requests = per_ip.entry(ip.to_string()).or_default();

                // Remove expired requests
                requests.retain(|&req_time| now.duration_since(req_time) < window);

                // Check if limit exceeded
                if requests.len() >= max_requests {
                    let oldest = requests.first().copied().unwrap_or(now);
                    let wait_time = window.saturating_sub(now.duration_since(oldest));
                    return Err(wait_time.as_secs());
                }

                // Record this request
                requests.push(now);
            }
        } else {
            // Global rate limiting
            let mut global = self.global.lock().unwrap_or_else(|e| e.into_inner());

            // Remove expired requests
            global.retain(|&req_time| now.duration_since(req_time) < window);

            // Check if limit exceeded
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
