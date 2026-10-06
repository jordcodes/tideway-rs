//! File storage for avatars, logos, attachments, and exports
//!
//! This module provides a [`FileStorage`] abstraction over the
//! [`object_store`](https://docs.rs/object_store) crate with these backends:
//! - [`LocalStorage`] - Local filesystem with HMAC-signed URLs served by [`LocalStorage::router`]
//! - [`ObjectStorage::in_memory`] - In-memory store for tests
//! - [`ObjectStorage::s3`] / [`ObjectStorage::r2`] - AWS S3, Cloudflare R2, and other
//!   S3-compatible services (requires the `storage-s3` feature)
//!
//! # Presigned uploads
//!
//! Clients upload directly to storage with a short-lived URL, so large files never
//! pass through your API process. [`UploadPolicy`] validates the declared type and
//! size, generates a unique key, and binds both into the signature:
//!
//! ```rust,ignore
//! use tideway::storage::UploadPolicy;
//!
//! let storage = ctx.storage()?;
//! let upload = UploadPolicy::avatar()
//!     .presign(storage.as_ref(), "me.png", "image/png", 48_213)
//!     .await?;
//! // Return `upload` as JSON; the client sends `PUT upload.url` with `upload.headers`,
//! // then reports `upload.key` back to your API, which verifies it before saving:
//! let object = UploadPolicy::avatar().confirm(storage.as_ref(), &key).await?;
//! ```
//!
//! The content type is always bound into the signature. Size is enforced at upload
//! time by [`LocalStorage`], but S3 presigned `PUT`s cannot carry a size limit, so
//! always call [`UploadPolicy::confirm`] before trusting a client-reported key.
//!
//! # Server-side writes (exports)
//!
//! ```rust,ignore
//! use std::time::Duration;
//! use tideway::storage::object_key;
//!
//! let key = object_key("exports", "users.csv")?;
//! storage.put(&key, csv_bytes.into(), Some("text/csv")).await?;
//! let download = storage.presign_download(&key, Duration::from_secs(3600)).await?;
//! ```

mod local;
mod object;

pub use local::LocalStorage;
pub use object::ObjectStorage;
#[cfg(feature = "storage-s3")]
pub use object::{R2Config, S3Config};

pub use crate::traits::storage::{
    DEFAULT_PRESIGN_EXPIRY, FileStorage, MAX_PRESIGN_EXPIRY, PresignOptions, PresignedRequest,
    StoredObject,
};

use crate::error::{Result, TidewayError};
use std::time::Duration;

/// Maximum key length in bytes (matches the S3 limit).
const MAX_KEY_LEN: usize = 1024;

/// Validate an object key and convert it into an `object_store` path.
///
/// Keys are restricted to a URL-safe character set so they never need encoding
/// and cannot escape the storage root.
pub(crate) fn parse_key(key: &str) -> Result<object_store::path::Path> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(TidewayError::bad_request(format!(
            "Storage key must be between 1 and {MAX_KEY_LEN} bytes"
        )));
    }
    for segment in key.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TidewayError::bad_request(
                "Storage key must not contain empty, '.' or '..' segments",
            ));
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
        {
            return Err(TidewayError::bad_request(
                "Storage key may only contain ASCII letters, digits, '/', '-', '_', '.' and '='",
            ));
        }
    }
    object_store::path::Path::parse(key)
        .map_err(|e| TidewayError::bad_request(format!("Invalid storage key: {e}")))
}

/// Generate a unique key under `prefix`, keeping the (sanitized) file extension.
///
/// ```rust
/// # #[cfg(feature = "storage")] {
/// let key = tideway::storage::object_key("avatars/user-42", "Profile Photo.PNG").unwrap();
/// assert!(key.starts_with("avatars/user-42/"));
/// assert!(key.ends_with(".png"));
/// # }
/// ```
pub fn object_key(prefix: &str, filename: &str) -> Result<String> {
    let prefix = prefix.trim_matches('/');
    let extension = filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| {
            !ext.is_empty() && ext.len() <= 10 && ext.bytes().all(|b| b.is_ascii_alphanumeric())
        });
    let name = match extension {
        Some(ext) => format!("{}.{ext}", uuid::Uuid::new_v4()),
        None => uuid::Uuid::new_v4().to_string(),
    };
    let key = if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    };
    parse_key(&key)?;
    Ok(key)
}

/// Clamp a requested presign lifetime to the supported range.
pub(crate) fn clamp_expiry(expires_in: Duration) -> Duration {
    expires_in.clamp(Duration::from_secs(1), MAX_PRESIGN_EXPIRY)
}

pub(crate) fn map_store_error(err: object_store::Error) -> TidewayError {
    match err {
        object_store::Error::NotFound { path, .. } => {
            TidewayError::not_found(format!("Stored object not found: {path}"))
        }
        object_store::Error::InvalidPath { source } => {
            TidewayError::bad_request(format!("Invalid storage key: {source}"))
        }
        other => TidewayError::internal(format!("Storage error: {other}")),
    }
}

/// Validation rules for a category of client uploads.
///
/// Presets cover the common SaaS cases; adjust them with the builder methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPolicy {
    /// Key prefix uploads are stored under (e.g. `avatars`)
    pub prefix: String,
    /// Maximum upload size in bytes
    pub max_bytes: u64,
    /// Allowed MIME types; empty allows any type
    pub allowed_content_types: Vec<String>,
    /// Lifetime of the presigned URL
    pub expires_in: Duration,
}

const IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

impl UploadPolicy {
    /// Create a policy that accepts any content type up to `max_bytes`.
    pub fn new(prefix: impl Into<String>, max_bytes: u64) -> Self {
        Self {
            prefix: prefix.into(),
            max_bytes,
            allowed_content_types: Vec::new(),
            expires_in: DEFAULT_PRESIGN_EXPIRY,
        }
    }

    /// User avatars: raster images up to 5 MiB under `avatars/`.
    pub fn avatar() -> Self {
        Self::new("avatars", 5 * 1024 * 1024).allow_content_types(IMAGE_TYPES.iter().copied())
    }

    /// Organization logos: raster images up to 5 MiB under `logos/`.
    ///
    /// SVG is excluded by default because it can carry scripts; add it explicitly
    /// if you serve logos from a separate origin.
    pub fn logo() -> Self {
        Self::new("logos", 5 * 1024 * 1024).allow_content_types(IMAGE_TYPES.iter().copied())
    }

    /// Attachments: any type up to 25 MiB under `attachments/`.
    pub fn attachment() -> Self {
        Self::new("attachments", 25 * 1024 * 1024)
    }

    /// Set the key prefix.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Set the maximum size in bytes.
    pub fn max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Replace the allowed MIME types.
    pub fn allow_content_types<I, S>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_content_types = types.into_iter().map(Into::into).collect();
        self
    }

    /// Set the presigned URL lifetime.
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Check a declared upload against this policy.
    pub fn validate(&self, content_type: &str, content_length: u64) -> Result<()> {
        if content_length == 0 {
            return Err(TidewayError::bad_request("Upload must not be empty"));
        }
        if content_length > self.max_bytes {
            return Err(TidewayError::bad_request(format!(
                "Upload exceeds the {} byte limit",
                self.max_bytes
            )));
        }
        let content_type = content_type.trim();
        if !self.allowed_content_types.is_empty()
            && !self
                .allowed_content_types
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(content_type))
        {
            return Err(TidewayError::bad_request(format!(
                "Content type '{content_type}' is not allowed"
            )));
        }
        Ok(())
    }

    /// Validate the declared upload, generate a key, and presign a `PUT` bound to
    /// the content type (and, for [`LocalStorage`], the exact length).
    pub async fn presign(
        &self,
        storage: &dyn FileStorage,
        filename: &str,
        content_type: &str,
        content_length: u64,
    ) -> Result<PresignedRequest> {
        self.validate(content_type, content_length)?;
        let key = object_key(&self.prefix, filename)?;
        storage
            .presign_upload(
                &key,
                PresignOptions::new()
                    .expires_in(self.expires_in)
                    .content_type(content_type.trim())
                    .content_length(content_length),
            )
            .await
    }

    /// Verify a completed client upload before recording it.
    ///
    /// Checks that `key` belongs to this policy's prefix, that the object exists,
    /// and that its stored size is within limits. Oversized or empty objects are
    /// deleted. Call this from the endpoint where the client reports a finished
    /// upload: S3-compatible backends cannot enforce size in the presigned URL.
    pub async fn confirm(&self, storage: &dyn FileStorage, key: &str) -> Result<StoredObject> {
        parse_key(key)?;
        let prefix = self.prefix.trim_matches('/');
        if !prefix.is_empty()
            && !key
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(TidewayError::bad_request(format!(
                "Storage key is not under '{prefix}/'"
            )));
        }
        let object = storage
            .head(key)
            .await?
            .ok_or_else(|| TidewayError::not_found("Upload not found"))?;
        if object.size == 0 || object.size > self.max_bytes {
            storage.delete(key).await?;
            return Err(TidewayError::bad_request(format!(
                "Upload must be between 1 and {} bytes",
                self.max_bytes
            )));
        }
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_rejects_traversal_and_unsafe_characters() {
        for bad in [
            "", "/abs", "a//b", "a/../b", "./a", "a/", "a b", "a?b", "a%2Fb", "ü",
        ] {
            assert!(parse_key(bad).is_err(), "expected {bad:?} to be rejected");
        }
        assert!(parse_key("avatars/user-1/abc_def.v2=1.png").is_ok());
    }

    #[test]
    fn object_key_sanitizes_extension() {
        let key = object_key("/logos/", "../../etc/passwd").unwrap();
        assert!(key.starts_with("logos/"));
        assert!(!key.contains(".."));

        let key = object_key("exports", "report.CSV").unwrap();
        assert!(key.starts_with("exports/") && key.ends_with(".csv"));

        let key = object_key("x", "evil.p h p").unwrap();
        assert!(!key.contains(' '));
    }

    #[test]
    fn upload_policy_validates_type_and_size() {
        let policy = UploadPolicy::avatar();
        assert!(policy.validate("image/png", 1024).is_ok());
        assert!(policy.validate("IMAGE/PNG", 1024).is_ok());
        assert!(policy.validate("image/svg+xml", 1024).is_err());
        assert!(policy.validate("image/png", 0).is_err());
        assert!(policy.validate("image/png", 6 * 1024 * 1024).is_err());
        assert!(
            UploadPolicy::attachment()
                .validate("application/zip", 1024)
                .is_ok()
        );
    }
}
