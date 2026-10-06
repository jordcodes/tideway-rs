//! File storage trait for uploads, downloads, and presigned URLs
//!
//! This trait abstracts object storage backends, allowing applications to swap
//! between the local filesystem (development), S3, Cloudflare R2, or a custom
//! implementation without changing handlers.

use crate::error::Result;
use async_trait::async_trait;
use axum::body::Bytes;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// Default lifetime for presigned URLs.
pub const DEFAULT_PRESIGN_EXPIRY: Duration = Duration::from_secs(15 * 60);

/// Maximum lifetime for presigned URLs (matches the S3 SigV4 limit of 7 days).
pub const MAX_PRESIGN_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Metadata about a stored object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredObject {
    /// Object key (e.g. `avatars/0b7c...png`)
    pub key: String,
    /// Size in bytes
    pub size: u64,
    /// Entity tag reported by the backend, if any
    pub e_tag: Option<String>,
}

/// Constraints folded into a presigned upload URL.
///
/// When `content_type` is set, the client must send exactly that `Content-Type`
/// or the backend rejects the upload. `content_length` is enforced by
/// [`LocalStorage`](crate::storage::LocalStorage), but S3-compatible backends
/// cannot bind a length into a presigned `PUT`; check the stored size after upload
/// with [`UploadPolicy::confirm`](crate::storage::UploadPolicy::confirm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignOptions {
    /// How long the URL stays valid (capped at [`MAX_PRESIGN_EXPIRY`])
    pub expires_in: Duration,
    /// Required `Content-Type` header for the upload
    pub content_type: Option<String>,
    /// Required `Content-Length` header (exact size in bytes, where supported)
    pub content_length: Option<u64>,
}

impl Default for PresignOptions {
    fn default() -> Self {
        Self {
            expires_in: DEFAULT_PRESIGN_EXPIRY,
            content_type: None,
            content_length: None,
        }
    }
}

impl PresignOptions {
    /// Create options with the default expiry and no constraints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set how long the URL stays valid.
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Require the upload to use this `Content-Type`.
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Require the upload to be exactly this many bytes.
    pub fn content_length(mut self, content_length: u64) -> Self {
        self.content_length = Some(content_length);
        self
    }
}

/// A presigned HTTP request that a client can perform without credentials.
///
/// Serializable so handlers can return it directly as JSON to browsers or
/// mobile clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PresignedRequest {
    /// Object key the request targets
    pub key: String,
    /// HTTP method to use (`PUT` for uploads, `GET` for downloads)
    pub method: String,
    /// Fully signed URL
    pub url: String,
    /// Headers the client must send with the request
    pub headers: BTreeMap<String, String>,
    /// Seconds until the URL expires
    pub expires_in: u64,
}

/// Object storage backend.
///
/// Keys are `/`-separated paths made of ASCII letters, digits, `-`, `_`, `.`
/// and `=`. Use [`crate::storage::object_key`] to generate collision-free keys
/// from user-supplied filenames.
#[async_trait]
pub trait FileStorage: Send + Sync {
    /// Store `data` under `key`, replacing any existing object.
    async fn put(&self, key: &str, data: Bytes, content_type: Option<&str>)
    -> Result<StoredObject>;

    /// Read the full object. Returns `TidewayError::NotFound` if it does not exist.
    async fn get(&self, key: &str) -> Result<Bytes>;

    /// Fetch object metadata, or `None` if it does not exist.
    async fn head(&self, key: &str) -> Result<Option<StoredObject>>;

    /// Delete the object. Deleting a missing object is not an error.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Create a presigned `PUT` URL that lets a client upload directly to storage.
    async fn presign_upload(&self, key: &str, options: PresignOptions) -> Result<PresignedRequest>;

    /// Create a presigned `GET` URL that lets a client download the object.
    async fn presign_download(&self, key: &str, expires_in: Duration) -> Result<PresignedRequest>;

    /// Whether an object exists under `key`.
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.head(key).await?.is_some())
    }
}
