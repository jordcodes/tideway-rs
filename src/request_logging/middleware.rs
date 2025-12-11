use super::config::{LogLevel, RequestLoggingConfig};
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum::body::Body;
use futures::future::BoxFuture;
use std::time::Instant;
use tower::Service;

/// Build a Tower layer for request/response logging
pub fn build_request_logging_layer(
    config: &RequestLoggingConfig,
) -> Option<RequestLoggingLayer> {
    if !config.enabled {
        return None;
    }

    Some(RequestLoggingLayer {
        config: config.clone(),
    })
}

/// Tower layer for request/response logging
#[derive(Clone)]
pub struct RequestLoggingLayer {
    config: RequestLoggingConfig,
}

impl<S> tower::Layer<S> for RequestLoggingLayer {
    type Service = RequestLoggingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLoggingService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower service for request/response logging
#[derive(Clone)]
pub struct RequestLoggingService<S> {
    inner: S,
    config: RequestLoggingConfig,
}

impl<S> Service<Request> for RequestLoggingService<S>
where
    S: Service<Request, Response = Response<Body>> + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let config = self.config.clone();
        let start = Instant::now();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let query = uri.query().map(|q| q.to_string());

        // Extract request ID if present
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Extract headers if configured
        let headers = if config.include_headers {
            Some(req.headers().clone())
        } else {
            None
        };

        let fut = self.inner.call(req);

        Box::pin(async move {
            let response = fut.await?;
            let status = response.status();
            let duration = start.elapsed();

            // Extract response headers if configured
            let response_headers = if config.include_response_headers {
                Some(response.headers().clone())
            } else {
                None
            };

            // Determine log level based on status code
            let log_level = if status.is_success() {
                config.success_level
            } else if status.is_client_error() {
                config.client_error_level
            } else {
                config.server_error_level
            };

            // Log the request/response (move owned values to avoid Send issues)
            let method_str = method.clone();
            let path_str = path.clone();
            let query_str = query.clone();
            let request_id_str = request_id.clone();
            let headers_clone = headers.clone();
            let response_headers_clone = response_headers.clone();

            log_request_response(
                &config,
                log_level,
                &method_str,
                &path_str,
                query_str.as_deref(),
                status,
                duration,
                request_id_str.as_deref(),
                headers_clone.as_ref(),
                response_headers_clone.as_ref(),
            );

            Ok(response)
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn log_request_response(
    _config: &RequestLoggingConfig,
    level: LogLevel,
    method: &axum::http::Method,
    path: &str,
    query: Option<&str>,
    status: StatusCode,
    duration: std::time::Duration,
    request_id: Option<&str>,
    headers: Option<&HeaderMap>,
    response_headers: Option<&HeaderMap>,
) {
    let mut uri = path.to_string();
    if let Some(q) = query {
        uri.push('?');
        uri.push_str(q);
    }

    let _span = if let Some(id) = request_id {
        tracing::span!(
            tracing::Level::TRACE,
            "request",
            method = %method,
            path = %path,
            status = status.as_u16(),
            duration_ms = duration.as_millis(),
            request_id = %id,
        )
    } else {
        tracing::span!(
            tracing::Level::TRACE,
            "request",
            method = %method,
            path = %path,
            status = status.as_u16(),
            duration_ms = duration.as_millis(),
        )
    };

    let _guard = _span.enter();

    let message = format!(
        "{} {} {} {}ms",
        method,
        uri,
        status.as_u16(),
        duration.as_millis()
    );

    match level {
        LogLevel::Trace => {
            tracing::trace!(
                method = %method,
                path = %path,
                query = ?query,
                status = status.as_u16(),
                duration_ms = duration.as_millis(),
                request_id = ?request_id,
                headers = ?headers,
                response_headers = ?response_headers,
                "{}",
                message
            );
        }
        LogLevel::Debug => {
            tracing::debug!(
                method = %method,
                path = %path,
                query = ?query,
                status = status.as_u16(),
                duration_ms = duration.as_millis(),
                request_id = ?request_id,
                headers = ?headers,
                response_headers = ?response_headers,
                "{}",
                message
            );
        }
        LogLevel::Info => {
            tracing::info!(
                method = %method,
                path = %path,
                query = ?query,
                status = status.as_u16(),
                duration_ms = duration.as_millis(),
                request_id = ?request_id,
                "{}",
                message
            );
        }
        LogLevel::Warn => {
            tracing::warn!(
                method = %method,
                path = %path,
                query = ?query,
                status = status.as_u16(),
                duration_ms = duration.as_millis(),
                request_id = ?request_id,
                "{}",
                message
            );
        }
        LogLevel::Error => {
            tracing::error!(
                method = %method,
                path = %path,
                query = ?query,
                status = status.as_u16(),
                duration_ms = duration.as_millis(),
                request_id = ?request_id,
                "{}",
                message
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_logging() {
        let config = RequestLoggingConfig {
            enabled: false,
            ..Default::default()
        };
        let layer = build_request_logging_layer(&config);
        assert!(layer.is_none());
    }

    #[test]
    fn test_log_level_selection() {
        let config = RequestLoggingConfig::default();

        // Success (2xx) should use success_level
        let status = StatusCode::OK;
        let level = if status.is_success() {
            config.success_level
        } else if status.is_client_error() {
            config.client_error_level
        } else {
            config.server_error_level
        };
        assert_eq!(level, LogLevel::Info);

        // Client error (4xx) should use client_error_level
        let status = StatusCode::BAD_REQUEST;
        let level = if status.is_success() {
            config.success_level
        } else if status.is_client_error() {
            config.client_error_level
        } else {
            config.server_error_level
        };
        assert_eq!(level, LogLevel::Warn);

        // Server error (5xx) should use server_error_level
        let status = StatusCode::INTERNAL_SERVER_ERROR;
        let level = if status.is_success() {
            config.success_level
        } else if status.is_client_error() {
            config.client_error_level
        } else {
            config.server_error_level
        };
        assert_eq!(level, LogLevel::Error);
    }
}
