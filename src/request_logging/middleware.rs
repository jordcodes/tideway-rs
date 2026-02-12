use super::config::{LogLevel, RequestLoggingConfig};
use axum::body::Body;
use axum::{
    extract::{MatchedPath, Request},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures::future::BoxFuture;
use std::sync::OnceLock;
use std::time::Instant;
use tower::Service;

/// Build a Tower layer for request/response logging
pub fn build_request_logging_layer(config: &RequestLoggingConfig) -> Option<RequestLoggingLayer> {
    if !config.enabled {
        return None;
    }

    if config.body_preview_size > 0 {
        static BODY_PREVIEW_WARNED: OnceLock<()> = OnceLock::new();
        BODY_PREVIEW_WARNED.get_or_init(|| {
            tracing::warn!(
                body_preview_size = config.body_preview_size,
                "request body preview is not implemented yet; REQUEST_LOGGING_BODY_PREVIEW_SIZE is currently ignored"
            );
        });
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
        let matched_path = req
            .extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str().to_string());
        let path = matched_path.unwrap_or_else(|| uri.path().to_string());
        let query = sanitize_query(uri.query());

        // Extract request ID if present
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let any_logging_enabled = is_log_level_enabled(config.success_level)
            || is_log_level_enabled(config.client_error_level)
            || is_log_level_enabled(config.server_error_level);

        // Extract headers if configured
        let headers = if config.include_headers && any_logging_enabled {
            Some(req.headers().clone())
        } else {
            None
        };

        let fut = self.inner.call(req);

        Box::pin(async move {
            let response = fut.await?;
            let status = response.status();
            let duration = start.elapsed();

            // Determine log level based on status code
            let log_level = if status.is_success() {
                config.success_level
            } else if status.is_client_error() {
                config.client_error_level
            } else {
                config.server_error_level
            };

            if !is_log_level_enabled(log_level) {
                return Ok(response);
            }

            // Extract response headers if configured
            let response_headers = if config.include_response_headers {
                Some(response.headers().clone())
            } else {
                None
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

fn is_log_level_enabled(level: LogLevel) -> bool {
    match level {
        LogLevel::Trace => tracing::enabled!(tracing::Level::TRACE),
        LogLevel::Debug => tracing::enabled!(tracing::Level::DEBUG),
        LogLevel::Info => tracing::enabled!(tracing::Level::INFO),
        LogLevel::Warn => tracing::enabled!(tracing::Level::WARN),
        LogLevel::Error => tracing::enabled!(tracing::Level::ERROR),
    }
}

const REDACTED_QUERY_VALUE: &str = "[REDACTED]";

fn sanitize_query(query: Option<&str>) -> Option<String> {
    query.map(|q| {
        q.split('&')
            .map(|pair| {
                if let Some((key, value)) = pair.split_once('=') {
                    if is_sensitive_query_key_decoded(key) {
                        format!("{key}={REDACTED_QUERY_VALUE}")
                    } else {
                        format!("{key}={value}")
                    }
                } else if is_sensitive_query_key_decoded(pair) {
                    format!("{pair}={REDACTED_QUERY_VALUE}")
                } else {
                    pair.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("&")
    })
}

fn is_sensitive_query_key_decoded(raw_key: &str) -> bool {
    let decoded_key = decode_query_component(raw_key);
    is_sensitive_query_key(&decoded_key)
}

fn decode_query_component(raw_value: &str) -> String {
    if !raw_value
        .as_bytes()
        .iter()
        .any(|c| *c == b'%' || *c == b'+')
    {
        return raw_value.to_string();
    }

    let encoded = format!("{raw_value}=");
    if let Some((decoded, _)) = url::form_urlencoded::parse(encoded.as_bytes()).next() {
        decoded.into_owned()
    } else {
        raw_value.to_string()
    }
}

fn is_sensitive_query_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "password"
            | "secret"
            | "api_key"
            | "signature"
            | "sig"
            | "code"
            | "auth"
            | "authorization"
    ) || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;
    use tracing_subscriber::fmt::Subscriber;

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

    #[test]
    fn test_log_level_enabled_guard() {
        let subscriber = Subscriber::builder().with_max_level(Level::INFO).finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            assert!(!is_log_level_enabled(LogLevel::Debug));
            assert!(is_log_level_enabled(LogLevel::Info));
        });
    }

    #[test]
    fn test_sanitize_query_redacts_sensitive_keys() {
        let query = Some("token=abc123&page=2&api_key=xyz");
        let sanitized = sanitize_query(query).unwrap();
        assert_eq!(sanitized, "token=[REDACTED]&page=2&api_key=[REDACTED]");
    }

    #[test]
    fn test_sanitize_query_preserves_non_sensitive_values() {
        let query = Some("page=2&sort=asc");
        let sanitized = sanitize_query(query).unwrap();
        assert_eq!(sanitized, "page=2&sort=asc");
    }

    #[test]
    fn test_sanitize_query_redacts_urlencoded_sensitive_keys() {
        let query = Some("access%5Ftoken=abc123&page=2");
        let sanitized = sanitize_query(query).unwrap();
        assert_eq!(sanitized, "access%5Ftoken=[REDACTED]&page=2");
    }

    #[test]
    fn test_sanitize_query_decodes_values_without_mutation_for_non_sensitive_keys() {
        let query = Some("filter=abc%2Bdef&page=2");
        let sanitized = sanitize_query(query).unwrap();
        assert_eq!(sanitized, "filter=abc%2Bdef&page=2");
    }
}
