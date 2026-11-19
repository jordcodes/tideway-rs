//! Request/Response dumper middleware for development
//!
//! Logs complete request and response details in JSON format for debugging.

use crate::request_logging::sanitize_query;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, Uri},
    response::Response,
};
use serde_json::json;
use std::sync::Arc;
use tower::Service;

/// Build a request dumper layer
///
/// The layer is inert in production-like environments (see
/// [`DevConfig::is_dev_mode`](crate::dev::DevConfig::is_dev_mode)).
pub fn build_request_dumper_layer(config: Arc<crate::dev::DevConfig>) -> RequestDumperLayer {
    RequestDumperLayer {
        config: crate::dev::config::effective_config(config),
    }
}

/// Request dumper layer
#[derive(Debug, Clone)]
pub struct RequestDumperLayer {
    config: Arc<crate::dev::DevConfig>,
}

impl<S> tower::Layer<S> for RequestDumperLayer {
    type Service = RequestDumperService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestDumperService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Request dumper service
#[derive(Debug, Clone)]
pub struct RequestDumperService<S> {
    inner: S,
    config: Arc<crate::dev::DevConfig>,
}

impl<S> Service<Request> for RequestDumperService<S>
where
    S: Service<Request, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
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
        if !self.config.enable_request_dumper {
            return Box::pin(self.inner.call(req));
        }

        // Check if path matches pattern
        let should_dump = match &self.config.dump_path_pattern {
            Some(pattern) => req.uri().path().contains(pattern),
            None => true,
        };

        if !should_dump {
            return Box::pin(self.inner.call(req));
        }

        let mut inner = self.inner.clone();
        let method = req.method().clone();
        let uri = format_uri(req.uri());
        let headers = req.headers().clone();

        Box::pin(async move {
            // Extract request ID if available
            let request_id = headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            // Log request details
            let request_info = json!({
                "type": "request",
                "request_id": request_id,
                "method": method.as_str(),
                "uri": uri,
                "headers": format_headers(&headers),
            });

            tracing::debug!(
                "{}",
                serde_json::to_string_pretty(&request_info).unwrap_or_default()
            );

            let response = inner.call(req).await?;

            // Log response details
            let status = response.status();
            let response_headers = response.headers();
            let response_info = json!({
                "type": "response",
                "request_id": request_id,
                "status": status.as_u16(),
                "status_text": status.canonical_reason(),
                "headers": format_headers(response_headers),
            });

            tracing::debug!(
                "{}",
                serde_json::to_string_pretty(&response_info).unwrap_or_default()
            );

            Ok(response)
        })
    }
}

/// Format the request path plus its query string with sensitive values (tokens, keys) redacted.
fn format_uri(uri: &Uri) -> String {
    match sanitize_query(uri.query()) {
        Some(query) => format!("{}?{}", uri.path(), query),
        None => uri.path().to_string(),
    }
}

fn format_headers(headers: &HeaderMap) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in headers.iter() {
        let value_str = if is_sensitive_header(key.as_str()) {
            "[REDACTED]".to_string()
        } else {
            value.to_str().unwrap_or("<invalid>").to_string()
        };
        map.insert(key.to_string(), json!(value_str));
    }
    json!(map)
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "proxy-authorization"
            | "x-api-key"
            | "x-auth-token"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn request_dumper_redacts_sensitive_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer secret-token"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=secret-session"));
        headers.insert("x-api-key", HeaderValue::from_static("secret-api-key"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let formatted = format_headers(&headers);

        assert_eq!(formatted["authorization"], "[REDACTED]");
        assert_eq!(formatted["cookie"], "[REDACTED]");
        assert_eq!(formatted["x-api-key"], "[REDACTED]");
        assert_eq!(formatted["content-type"], "application/json");
        let serialized = formatted.to_string();
        assert!(!serialized.contains("secret-token"));
        assert!(!serialized.contains("secret-session"));
        assert!(!serialized.contains("secret-api-key"));
    }

    #[test]
    fn request_dumper_redacts_sensitive_query_values() {
        let uri: Uri = "/ws?token=secret-token&room=lobby&api_key=secret-key"
            .parse()
            .unwrap();

        let formatted = format_uri(&uri);

        assert_eq!(
            formatted,
            "/ws?token=[REDACTED]&room=lobby&api_key=[REDACTED]"
        );
        assert!(!formatted.contains("secret-token"));
        assert!(!formatted.contains("secret-key"));
    }

    #[test]
    fn request_dumper_logs_path_without_query() {
        let uri: Uri = "http://example.com/users/1".parse().unwrap();

        assert_eq!(format_uri(&uri), "/users/1");
    }

    #[test]
    fn response_dumper_redacts_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "set-cookie",
            HeaderValue::from_static("session=secret-session; HttpOnly"),
        );

        let formatted = format_headers(&headers);

        assert_eq!(formatted["set-cookie"], "[REDACTED]");
        assert!(!formatted.to_string().contains("secret-session"));
    }
}
