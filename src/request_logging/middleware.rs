use super::config::{LogLevel, RequestLoggingConfig};
use axum::body::Body;
use axum::{
    extract::{MatchedPath, Request},
    http::{
        HeaderMap, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};
use futures::future::BoxFuture;
use std::time::Instant;
use tower::Service;

/// Build a Tower layer for request/response logging
pub fn build_request_logging_layer(config: &RequestLoggingConfig) -> Option<RequestLoggingLayer> {
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
    S: Service<Request, Response = Response<Body>> + Send + 'static + Clone,
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
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        // Extract request ID if present
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let any_logging_enabled = is_log_level_enabled(config.success_level)
            || is_log_level_enabled(config.client_error_level)
            || is_log_level_enabled(config.server_error_level);

        let inner = self.inner.clone();

        // Extract headers if configured
        let headers = if config.include_headers && any_logging_enabled {
            Some(redact_headers(req.headers()))
        } else {
            None
        };

        Box::pin(async move {
            let mut inner = inner.clone();
            let preview_allowed = !is_path_excluded(&path, &config.excluded_paths);
            let (req, request_body_preview) =
                if config.body_preview_size > 0 && any_logging_enabled && preview_allowed {
                    match extract_request_body_preview(req, config.body_preview_size).await {
                        Ok(preview) => preview,
                        Err(response) => return Ok(response),
                    }
                } else {
                    (req, None)
                };
            let request_body_preview = request_body_preview
                .and_then(|body| sanitize_body_preview(&body, content_type.as_deref(), &config));

            let response = inner.call(req).await?;
            let status = response.status();
            let duration = start.elapsed();
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

            let response_headers = if config.include_response_headers {
                Some(redact_headers(response.headers()))
            } else {
                None
            };

            // Log the request/response (move owned values to avoid Send issues)
            let method_str = method.clone();
            let path_str = path.clone();
            let query_str = query.clone();
            let request_id_str = request_id.clone();
            let request_body_preview = request_body_preview.clone();
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
                request_body_preview.as_deref(),
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
    request_body_preview: Option<&str>,
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
                request_body = request_body_preview,
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
                request_body = request_body_preview,
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
                request_body = request_body_preview,
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
                request_body = request_body_preview,
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
                request_body = request_body_preview,
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

async fn extract_request_body_preview(
    request: Request,
    max_bytes: usize,
) -> Result<(Request, Option<String>), Response> {
    if max_bytes == 0 {
        return Ok((request, None));
    }

    let Some(content_length) = request.headers().get(CONTENT_LENGTH).and_then(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
    }) else {
        return Ok((request, None));
    };

    if content_length == 0 || content_length > max_bytes {
        return Ok((request, None));
    }

    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, max_bytes).await.map_err(|_| {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeded the configured logging preview limit",
        )
            .into_response()
    })?;

    let request = Request::from_parts(parts, Body::from(bytes.clone()));
    let preview = String::from_utf8_lossy(&bytes).to_string();
    Ok((request, Some(preview)))
}

const REDACTED_HEADER_VALUE: &str = "[REDACTED]";

fn redact_headers(headers: &HeaderMap) -> HeaderMap {
    let mut redacted = headers.clone();
    for name in [
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    ] {
        if redacted.contains_key(name) {
            redacted.insert(
                name,
                REDACTED_HEADER_VALUE.parse().expect("static header value"),
            );
        }
    }
    redacted
}

fn is_path_excluded(path: &str, excluded_paths: &[String]) -> bool {
    excluded_paths
        .iter()
        .any(|excluded| path == excluded || path.starts_with(&format!("{excluded}/")))
}

fn sanitize_body_preview(
    body: &str,
    content_type: Option<&str>,
    config: &RequestLoggingConfig,
) -> Option<String> {
    let content_type = content_type?.split(';').next()?.trim();
    if !config.body_preview_redaction {
        return matches!(
            content_type,
            "application/json" | "application/x-www-form-urlencoded" | "text/plain"
        )
        .then(|| body.to_string());
    }

    match content_type {
        "application/json" => {
            let mut value: serde_json::Value = serde_json::from_str(body).ok()?;
            redact_json_value(&mut value, &config.sensitive_body_fields);
            serde_json::to_string(&value).ok()
        }
        "application/x-www-form-urlencoded" => {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
                let value = if is_sensitive_body_field(&key, &config.sensitive_body_fields) {
                    REDACTED_QUERY_VALUE
                } else {
                    value.as_ref()
                };
                serializer.append_pair(&key, value);
            }
            Some(serializer.finish())
        }
        _ => None,
    }
}

fn redact_json_value(value: &mut serde_json::Value, sensitive_fields: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if is_sensitive_body_field(key, sensitive_fields) {
                    *value = serde_json::Value::String(REDACTED_QUERY_VALUE.to_string());
                } else {
                    redact_json_value(value, sensitive_fields);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_value(value, sensitive_fields);
            }
        }
        _ => {}
    }
}

fn is_sensitive_body_field(field: &str, sensitive_fields: &[String]) -> bool {
    sensitive_fields
        .iter()
        .any(|sensitive| field.eq_ignore_ascii_case(sensitive))
        || is_sensitive_query_key(field)
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
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::http::header::CONTENT_LENGTH;
    use axum::{Router, routing::post};
    use tower::ServiceExt;
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

    #[tokio::test]
    async fn test_extract_request_body_preview_preserves_small_body() {
        let request = Request::builder()
            .method("POST")
            .uri("/users")
            .header(CONTENT_LENGTH, "11")
            .body(Body::from("hello-world"))
            .expect("failed to build request");

        let (request, preview) = extract_request_body_preview(request, 20)
            .await
            .expect("preview should succeed");
        assert_eq!(preview.as_deref(), Some("hello-world"));

        let body = to_bytes(request.into_body(), 20)
            .await
            .expect("failed to extract body");
        assert_eq!(body.as_ref(), b"hello-world");
    }

    #[tokio::test]
    async fn test_extract_request_body_preview_skips_large_body_and_preserves_payload() {
        let request = Request::builder()
            .method("POST")
            .uri("/users")
            .header(CONTENT_LENGTH, "12")
            .body(Body::from("hello-world!!"))
            .expect("failed to build request");

        let (request, preview) = extract_request_body_preview(request, 5)
            .await
            .expect("large declared bodies should be skipped");
        assert!(preview.is_none());

        let body = to_bytes(request.into_body(), 20)
            .await
            .expect("failed to extract body");
        assert_eq!(body.as_ref(), b"hello-world!!");
    }

    #[tokio::test]
    async fn test_extract_request_body_preview_skips_missing_content_length() {
        let request = Request::builder()
            .method("POST")
            .uri("/users")
            .body(Body::from("hello-world"))
            .expect("failed to build request");

        let (request, preview) = extract_request_body_preview(request, 5)
            .await
            .expect("missing content length should be skipped");
        assert!(preview.is_none());

        let body = to_bytes(request.into_body(), 20)
            .await
            .expect("failed to extract body");
        assert_eq!(body.as_ref(), b"hello-world");
    }

    async fn echo_body_handler(body: String) -> String {
        body
    }

    #[tokio::test]
    async fn test_request_logging_layer_preserves_request_body() {
        let config = RequestLoggingConfig {
            body_preview_size: 16,
            ..Default::default()
        };
        let layer =
            build_request_logging_layer(&config).expect("request logging layer should be enabled");

        let app = Router::new()
            .route("/echo", post(echo_body_handler))
            .layer(layer);
        let request = Request::builder()
            .uri("/echo")
            .method("POST")
            .header(CONTENT_LENGTH, "11")
            .body(Body::from("hello-world"))
            .expect("failed to build request");

        let response = app.oneshot(request).await.expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 20)
            .await
            .expect("failed to read response body");
        assert_eq!(body.as_ref(), b"hello-world");
    }

    #[test]
    fn test_redact_headers_removes_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret".parse().unwrap());
        headers.insert("cookie", "session=secret".parse().unwrap());
        headers.insert("x-api-key", "key".parse().unwrap());
        headers.insert("x-request-id", "request-1".parse().unwrap());

        let redacted = redact_headers(&headers);
        assert_eq!(redacted["authorization"], REDACTED_HEADER_VALUE);
        assert_eq!(redacted["cookie"], REDACTED_HEADER_VALUE);
        assert_eq!(redacted["x-api-key"], REDACTED_HEADER_VALUE);
        assert_eq!(redacted["x-request-id"], "request-1");
    }

    #[test]
    fn test_json_body_preview_redacts_nested_sensitive_fields() {
        let config = RequestLoggingConfig::default();
        let preview = sanitize_body_preview(
            r#"{"email":"user@example.com","password":"secret","nested":{"access_token":"token"}}"#,
            Some("application/json; charset=utf-8"),
            &config,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&preview).unwrap();
        assert_eq!(value["email"], "user@example.com");
        assert_eq!(value["password"], REDACTED_QUERY_VALUE);
        assert_eq!(value["nested"]["access_token"], REDACTED_QUERY_VALUE);
    }

    #[test]
    fn test_form_body_preview_redacts_sensitive_fields() {
        let config = RequestLoggingConfig::default();
        let preview = sanitize_body_preview(
            "email=user%40example.com&password=secret",
            Some("application/x-www-form-urlencoded"),
            &config,
        )
        .unwrap();
        assert!(preview.contains("email=user%40example.com"));
        assert!(preview.contains("password=%5BREDACTED%5D"));
        assert!(!preview.contains("secret"));
    }

    #[test]
    fn test_body_preview_skips_unknown_content_type_and_excluded_paths() {
        let config = RequestLoggingConfig::default();
        assert!(
            sanitize_body_preview("secret", Some("application/octet-stream"), &config).is_none()
        );
        assert!(is_path_excluded(
            "/auth/login/mfa",
            &["/auth/login".to_string()]
        ));
    }

    #[tokio::test]
    async fn test_body_preview_rejects_body_larger_than_preview_limit() {
        let request = Request::builder()
            .uri("/echo")
            .method("POST")
            .header(CONTENT_LENGTH, "4")
            .body(Body::from("body larger than declared"))
            .unwrap();

        let response = extract_request_body_preview(request, 16)
            .await
            .expect_err("oversized streamed body should be rejected");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
