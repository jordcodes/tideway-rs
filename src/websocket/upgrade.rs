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
