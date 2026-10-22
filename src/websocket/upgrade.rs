//! WebSocket upgrade request metadata
//!
//! This module provides the request data available to `WebSocketHandler::on_upgrade`
//! and, after the upgrade, to every other hook through `Connection::request`.

use axum::http::{HeaderMap, Uri};
use std::collections::HashMap;

/// HTTP request metadata captured during the WebSocket upgrade
///
/// Passed to [`WebSocketHandler::on_upgrade`](super::WebSocketHandler::on_upgrade) so the
/// connection can be authenticated before it is accepted. A user ID or metadata set here is
/// copied onto the [`Connection`](super::Connection) before `on_connect` runs.
#[derive(Debug, Clone, Default)]
pub struct UpgradeRequest {
    headers: HeaderMap,
    uri: Uri,
    user_id: Option<String>,
    metadata: HashMap<String, String>,
}

impl UpgradeRequest {
    /// Create upgrade request metadata from request headers and URI
    pub fn new(headers: HeaderMap, uri: Uri) -> Self {
        Self {
            headers,
            uri,
            user_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Get the request headers
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a header value, if present and valid UTF-8
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Get a cookie value from the `Cookie` header(s)
    pub fn cookie(&self, name: &str) -> Option<&str> {
        cookie_from_headers(&self.headers, name)
    }

    /// Get the `Origin` header, if present and valid UTF-8
    pub fn origin(&self) -> Option<&str> {
        self.header("origin")
    }

    /// Reject the upgrade unless its `Origin` is one of `allowed` (e.g. `https://app.example.com`).
    ///
    /// Call this in `on_upgrade` when the socket is authenticated by a cookie: CORS does not
    /// apply to WebSocket handshakes, so without it any site the browser visits can open an
    /// authenticated socket with the user's cookie (cross-site WebSocket hijacking). Origins are
    /// compared case-insensitively, ignoring a trailing slash. A request without an `Origin`
    /// header is allowed, since browsers always send one and other clients cannot use a
    /// victim's browser cookies.
    pub fn require_origin(&self, allowed: &[&str]) -> crate::error::Result<()> {
        let Some(origin) = self.headers.get(axum::http::header::ORIGIN) else {
            return Ok(());
        };
        let normalize = |value: &str| value.trim().trim_end_matches('/').to_ascii_lowercase();
        let origin = origin.to_str().map(normalize).unwrap_or_default();
        if allowed.iter().any(|allowed| normalize(allowed) == origin) {
            Ok(())
        } else {
            Err(crate::error::TidewayError::forbidden(
                "WebSocket origin not allowed",
            ))
        }
    }

    /// Get the request URI (path and query)
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Get the user ID that will be assigned to the connection
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Set the user ID to assign to the connection once it is accepted
    pub fn set_user_id(&mut self, user_id: impl Into<String>) {
        self.user_id = Some(user_id.into());
    }

    /// Get the metadata that will be copied to the connection
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Set a metadata value to copy to the connection once it is accepted
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    pub(crate) fn into_parts(self) -> (HeaderMap, Uri, Option<String>, HashMap<String, String>) {
        (self.headers, self.uri, self.user_id, self.metadata)
    }
}

pub(crate) fn cookie_from_headers<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(origin: Option<&str>) -> UpgradeRequest {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(axum::http::header::ORIGIN, origin.parse().unwrap());
        }
        UpgradeRequest::new(headers, "/ws".parse().unwrap())
    }

    #[test]
    fn require_origin_rejects_foreign_and_sibling_origins() {
        let allowed = ["https://app.example.com"];
        assert!(
            request(Some("https://app.example.com"))
                .require_origin(&allowed)
                .is_ok()
        );
        assert!(
            request(Some("HTTPS://App.Example.com/"))
                .require_origin(&allowed)
                .is_ok()
        );
        assert!(request(None).require_origin(&allowed).is_ok());

        for origin in [
            "https://evil.example",
            "https://sibling.example.com",
            "http://app.example.com",
            "null",
        ] {
            assert!(
                matches!(
                    request(Some(origin)).require_origin(&allowed),
                    Err(crate::error::TidewayError::Forbidden(_))
                ),
                "{origin}"
            );
        }
    }
}
