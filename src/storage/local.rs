//! Local filesystem storage with HMAC-signed upload and download URLs.

use super::{ObjectStorage, clamp_expiry, parse_key};
use crate::error::{Result, TidewayError};
use crate::traits::storage::{FileStorage, PresignOptions, PresignedRequest, StoredObject};
use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Minimum signing secret length in bytes.
const MIN_SECRET_LEN: usize = 32;

/// Default maximum body size accepted by [`LocalStorage::router`].
const DEFAULT_MAX_UPLOAD_BYTES: u64 = 25 * 1024 * 1024;

/// [`FileStorage`] on the local filesystem.
///
/// Presigned URLs point at [`LocalStorage::router`], which must be mounted so that
/// `base_url` resolves to it. This gives development and single-node deployments
/// the same direct-upload flow as S3/R2.
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use tideway::storage::LocalStorage;
///
/// let storage = LocalStorage::new("./uploads", "http://localhost:8000/files", secret)?;
/// let router = axum::Router::new().nest("/files", storage.router());
/// let ctx = AppContext::builder().with_storage(Arc::new(storage)).build();
/// ```
#[derive(Clone)]
pub struct LocalStorage {
    inner: ObjectStorage,
    base_url: Arc<str>,
    secret: Arc<[u8]>,
    max_upload_bytes: u64,
}

impl fmt::Debug for LocalStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStorage")
            .field("store", &self.inner.inner().to_string())
            .field("base_url", &self.base_url)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .finish()
    }
}

impl LocalStorage {
    /// Store files under `root`, issuing URLs under `base_url` signed with `secret`.
    ///
    /// `secret` must be at least 32 bytes. `root` is created if missing.
    pub fn new(
        root: impl AsRef<std::path::Path>,
        base_url: impl Into<String>,
        secret: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let secret = secret.as_ref();
        if secret.len() < MIN_SECRET_LEN {
            return Err(TidewayError::internal(format!(
                "Local storage signing secret must be at least {MIN_SECRET_LEN} bytes"
            )));
        }
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(|e| {
            TidewayError::internal(format!(
                "Failed to create storage root {}: {e}",
                root.display()
            ))
        })?;
        let store = object_store::local::LocalFileSystem::new_with_prefix(root)
            .map_err(|e| TidewayError::internal(format!("Invalid storage root: {e}")))?;
        Ok(Self {
            inner: ObjectStorage::new(Arc::new(store)).without_attributes(),
            base_url: base_url.into().trim_end_matches('/').into(),
            secret: secret.into(),
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        })
    }

    /// Set the largest upload body [`LocalStorage::router`] accepts (default 25 MiB).
    pub fn max_upload_bytes(mut self, max_upload_bytes: u64) -> Self {
        self.max_upload_bytes = max_upload_bytes;
        self
    }

    /// Router serving presigned `PUT` uploads and `GET` downloads at `/{key}`.
    ///
    /// Mount it so that `base_url` points at it, e.g.
    /// `Router::new().nest("/files", storage.router())` with base URL
    /// `https://api.example.com/files`.
    pub fn router<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        Router::new()
            .route("/{*key}", get(download).put(upload))
            .with_state(self.clone())
    }

    fn sign(&self, method: &str, key: &str, expires: u64, ct: &str, len: Option<u64>) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts keys of any length");
        let len = len.map(|l| l.to_string()).unwrap_or_default();
        mac.update(format!("{method}\n{key}\n{expires}\n{ct}\n{len}").as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn verify(&self, method: &str, key: &str, query: &SignedQuery) -> Result<()> {
        if query.expires < unix_now() {
            return Err(TidewayError::forbidden("Signed URL has expired"));
        }
        let expected = self.sign(
            method,
            key,
            query.expires,
            query.ct.as_deref().unwrap_or(""),
            query.len,
        );
        if !bool::from(expected.as_bytes().ct_eq(query.sig.as_bytes())) {
            return Err(TidewayError::forbidden("Invalid signature"));
        }
        Ok(())
    }

    fn presign(
        &self,
        method: &str,
        key: &str,
        expires_in: Duration,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<PresignedRequest> {
        parse_key(key)?;
        let expires_in = clamp_expiry(expires_in);
        let expires = unix_now() + expires_in.as_secs();
        let sig = self.sign(
            method,
            key,
            expires,
            content_type.unwrap_or(""),
            content_length,
        );

        let mut url = format!("{}/{key}?expires={expires}", self.base_url);
        let mut headers = BTreeMap::new();
        if let Some(content_type) = content_type {
            url.push_str("&ct=");
            url.push_str(&urlencoding::encode(content_type));
            headers.insert("content-type".to_string(), content_type.to_string());
        }
        if let Some(length) = content_length {
            url.push_str(&format!("&len={length}"));
            headers.insert("content-length".to_string(), length.to_string());
        }
        url.push_str("&sig=");
        url.push_str(&sig);

        Ok(PresignedRequest {
            key: key.to_string(),
            method: method.to_string(),
            url,
            headers,
            expires_in: expires_in.as_secs(),
        })
    }
}

#[async_trait]
impl FileStorage for LocalStorage {
    async fn put(
        &self,
        key: &str,
        data: Bytes,
        content_type: Option<&str>,
    ) -> Result<StoredObject> {
        self.inner.put(key, data, content_type).await
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        self.inner.get(key).await
    }

    async fn head(&self, key: &str) -> Result<Option<StoredObject>> {
        self.inner.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }

    async fn presign_upload(&self, key: &str, options: PresignOptions) -> Result<PresignedRequest> {
        self.presign(
            "PUT",
            key,
            options.expires_in,
            options.content_type.as_deref(),
            options.content_length,
        )
    }

    async fn presign_download(&self, key: &str, expires_in: Duration) -> Result<PresignedRequest> {
        self.presign("GET", key, expires_in, None, None)
    }
}

#[derive(Debug, Deserialize)]
struct SignedQuery {
    expires: u64,
    sig: String,
    ct: Option<String>,
    len: Option<u64>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn upload(
    State(storage): State<LocalStorage>,
    Path(key): Path<String>,
    Query(query): Query<SignedQuery>,
    request: Request,
) -> Response {
    // Authenticate before reading the body so unsigned requests cost nothing.
    if let Err(e) = storage.verify("PUT", &key, &query) {
        return e.into_response();
    }
    if let Some(expected) = &query.ct {
        let sent = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        if sent != Some(expected.as_str()) {
            return TidewayError::forbidden("Content-Type does not match signed URL")
                .into_response();
        }
    }

    let limit = query
        .len
        .unwrap_or(storage.max_upload_bytes)
        .min(storage.max_upload_bytes);
    let body = match axum::body::to_bytes(request.into_body(), limit as usize).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload exceeds the allowed size",
            )
                .into_response();
        }
    };
    if let Some(expected) = query.len
        && body.len() as u64 != expected
    {
        return TidewayError::bad_request("Content-Length does not match signed URL")
            .into_response();
    }

    match storage.inner.put(&key, body, None).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn download(
    State(storage): State<LocalStorage>,
    Path(key): Path<String>,
    Query(query): Query<SignedQuery>,
) -> Response {
    if let Err(e) = storage.verify("GET", &key, &query) {
        return e.into_response();
    }
    match storage.inner.get(&key).await {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type_for(&key)),
            );
            // User uploads are untrusted: never let browsers sniff or execute them.
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("sandbox"),
            );
            response
        }
        Err(e) => e.into_response(),
    }
}

/// Map safe, inert extensions to MIME types; everything else downloads as binary.
fn content_type_for(key: &str) -> &'static str {
    let ext = key
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase());
    match ext.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("csv") => "text/csv; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}
