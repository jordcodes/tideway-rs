//! [`FileStorage`] implementation over any `object_store` backend.

#[cfg(feature = "storage-s3")]
use super::clamp_expiry;
use super::{map_store_error, parse_key};
use crate::error::{Result, TidewayError};
use crate::traits::storage::{FileStorage, PresignOptions, PresignedRequest, StoredObject};
use async_trait::async_trait;
use axum::body::Bytes;
#[cfg(feature = "storage-s3")]
use object_store::signer::{HeaderName, HeaderValue, Method, SignedUrlOptions, Signer};
use object_store::{Attribute, Attributes, ObjectStore, ObjectStoreExt, PutOptions};
#[cfg(feature = "storage-s3")]
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// [`FileStorage`] backed by an [`ObjectStore`], with optional native URL signing.
///
/// Use the S3/R2 constructors for production, [`ObjectStorage::in_memory`] for
/// tests, or `ObjectStorage::new` / `ObjectStorage::with_signer` to wrap any
/// other `object_store` backend. Presigned URLs require a signing backend, which
/// needs the `storage-s3` feature.
#[derive(Clone)]
pub struct ObjectStorage {
    store: Arc<dyn ObjectStore>,
    #[cfg(feature = "storage-s3")]
    signer: Option<Arc<dyn Signer>>,
    supports_attributes: bool,
}

impl fmt::Debug for ObjectStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStorage")
            .field("store", &self.store.to_string())
            .field("presign", &self.can_presign())
            .finish()
    }
}

impl ObjectStorage {
    /// Wrap a store that cannot presign URLs.
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            #[cfg(feature = "storage-s3")]
            signer: None,
            supports_attributes: true,
        }
    }

    /// Whether this backend can create presigned URLs.
    pub fn can_presign(&self) -> bool {
        #[cfg(feature = "storage-s3")]
        return self.signer.is_some();
        #[cfg(not(feature = "storage-s3"))]
        false
    }

    /// Wrap a store that can also presign URLs (e.g. `AmazonS3`).
    #[cfg(feature = "storage-s3")]
    pub fn with_signer<T: ObjectStore + Signer>(store: Arc<T>) -> Self {
        Self {
            store: store.clone(),
            signer: Some(store),
            supports_attributes: true,
        }
    }

    /// In-memory store for tests. Presigned URLs are not supported.
    pub fn in_memory() -> Self {
        Self::new(Arc::new(object_store::memory::InMemory::new()))
    }

    /// Mark the store as unable to persist object attributes such as content type.
    pub(crate) fn without_attributes(mut self) -> Self {
        self.supports_attributes = false;
        self
    }

    /// The underlying `object_store` backend, for operations outside [`FileStorage`].
    pub fn inner(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    /// AWS S3 or any S3-compatible service.
    #[cfg(feature = "storage-s3")]
    pub fn s3(config: S3Config) -> Result<Self> {
        let mut builder = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(config.bucket)
            .with_region(config.region)
            .with_access_key_id(config.access_key_id)
            .with_secret_access_key(config.secret_access_key)
            .with_allow_http(config.allow_http)
            .with_virtual_hosted_style_request(config.virtual_hosted_style);
        if let Some(endpoint) = config.endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        let s3 = builder
            .build()
            .map_err(|e| TidewayError::internal(format!("Invalid S3 configuration: {e}")))?;
        Ok(Self::with_signer(Arc::new(s3)))
    }

    /// AWS S3 configured from standard `AWS_*` environment variables
    /// (`AWS_BUCKET`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
    /// `AWS_ENDPOINT`, ...).
    #[cfg(feature = "storage-s3")]
    pub fn s3_from_env() -> Result<Self> {
        let s3 = object_store::aws::AmazonS3Builder::from_env()
            .build()
            .map_err(|e| TidewayError::internal(format!("Invalid S3 configuration: {e}")))?;
        Ok(Self::with_signer(Arc::new(s3)))
    }

    /// Cloudflare R2.
    #[cfg(feature = "storage-s3")]
    pub fn r2(config: R2Config) -> Result<Self> {
        Self::s3(config.into())
    }
}

#[async_trait]
impl FileStorage for ObjectStorage {
    async fn put(
        &self,
        key: &str,
        data: Bytes,
        content_type: Option<&str>,
    ) -> Result<StoredObject> {
        let path = parse_key(key)?;
        let size = data.len() as u64;
        let mut attributes = Attributes::new();
        if let (Some(content_type), true) = (content_type, self.supports_attributes) {
            attributes.insert(Attribute::ContentType, content_type.to_string().into());
        }
        let result = self
            .store
            .put_opts(
                &path,
                data.into(),
                PutOptions {
                    attributes,
                    ..Default::default()
                },
            )
            .await
            .map_err(map_store_error)?;
        Ok(StoredObject {
            key: key.to_string(),
            size,
            e_tag: result.e_tag,
        })
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = parse_key(key)?;
        let result = self.store.get(&path).await.map_err(map_store_error)?;
        result.bytes().await.map_err(map_store_error)
    }

    async fn head(&self, key: &str) -> Result<Option<StoredObject>> {
        let path = parse_key(key)?;
        match self.store.head(&path).await {
            Ok(meta) => Ok(Some(StoredObject {
                key: key.to_string(),
                size: meta.size,
                e_tag: meta.e_tag,
            })),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(map_store_error(e)),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = parse_key(key)?;
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(map_store_error(e)),
        }
    }

    async fn presign_upload(&self, key: &str, options: PresignOptions) -> Result<PresignedRequest> {
        #[cfg(feature = "storage-s3")]
        {
            let mut signed = SignedUrlOptions::new();
            let mut headers = BTreeMap::new();
            if let Some(content_type) = &options.content_type {
                let value = HeaderValue::from_str(content_type)
                    .map_err(|_| TidewayError::bad_request("Invalid content type"))?;
                signed = signed.with_signed_header(HeaderName::from_static("content-type"), value);
                headers.insert("content-type".to_string(), content_type.clone());
            }
            // SigV4 drops `content-length` from presigned URL signatures, so S3-compatible
            // backends cannot enforce `options.content_length`. Callers verify the stored
            // size after upload (see `UploadPolicy::confirm`).
            self.presign(Method::PUT, key, options.expires_in, &signed, headers)
                .await
        }
        #[cfg(not(feature = "storage-s3"))]
        {
            let _ = options;
            Err(self.presign_unsupported(key))
        }
    }

    async fn presign_download(&self, key: &str, expires_in: Duration) -> Result<PresignedRequest> {
        #[cfg(feature = "storage-s3")]
        {
            self.presign(
                Method::GET,
                key,
                expires_in,
                &SignedUrlOptions::new(),
                BTreeMap::new(),
            )
            .await
        }
        #[cfg(not(feature = "storage-s3"))]
        {
            let _ = expires_in;
            Err(self.presign_unsupported(key))
        }
    }
}

impl ObjectStorage {
    fn presign_unsupported(&self, key: &str) -> TidewayError {
        match parse_key(key) {
            Err(e) => e,
            Ok(_) => TidewayError::internal(format!(
                "Storage backend {} does not support presigned URLs",
                self.store
            )),
        }
    }

    #[cfg(feature = "storage-s3")]
    async fn presign(
        &self,
        method: Method,
        key: &str,
        expires_in: Duration,
        options: &SignedUrlOptions,
        headers: BTreeMap<String, String>,
    ) -> Result<PresignedRequest> {
        let path = parse_key(key)?;
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| self.presign_unsupported(key))?;
        let expires_in = clamp_expiry(expires_in);
        let url = signer
            .signed_url_opts(method.clone(), &path, expires_in, options)
            .await
            .map_err(map_store_error)?;
        Ok(PresignedRequest {
            key: key.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            headers,
            expires_in: expires_in.as_secs(),
        })
    }
}

/// Configuration for AWS S3 or an S3-compatible service.
#[cfg(feature = "storage-s3")]
#[derive(Clone)]
pub struct S3Config {
    /// Bucket name
    pub bucket: String,
    /// Region (e.g. `us-east-1`; `auto` for R2)
    pub region: String,
    /// Access key ID
    pub access_key_id: String,
    /// Secret access key
    pub secret_access_key: String,
    /// Custom endpoint for S3-compatible services (MinIO, R2, ...)
    pub endpoint: Option<String>,
    /// Allow plain HTTP endpoints (local MinIO only)
    pub allow_http: bool,
    /// Use `https://{bucket}.{endpoint}` instead of path-style URLs
    pub virtual_hosted_style: bool,
}

#[cfg(feature = "storage-s3")]
impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint)
            .field("allow_http", &self.allow_http)
            .field("virtual_hosted_style", &self.virtual_hosted_style)
            .finish()
    }
}

#[cfg(feature = "storage-s3")]
impl S3Config {
    /// Create a configuration for AWS S3.
    pub fn new(
        bucket: impl Into<String>,
        region: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            endpoint: None,
            allow_http: false,
            virtual_hosted_style: false,
        }
    }

    /// Use a custom endpoint (MinIO, other S3-compatible services).
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Allow plain HTTP endpoints.
    pub fn allow_http(mut self, allow_http: bool) -> Self {
        self.allow_http = allow_http;
        self
    }

    /// Use virtual-hosted-style request URLs.
    pub fn virtual_hosted_style(mut self, enabled: bool) -> Self {
        self.virtual_hosted_style = enabled;
        self
    }
}

/// Configuration for Cloudflare R2.
#[cfg(feature = "storage-s3")]
#[derive(Clone)]
pub struct R2Config {
    /// Cloudflare account ID
    pub account_id: String,
    /// Bucket name
    pub bucket: String,
    /// R2 API token access key ID
    pub access_key_id: String,
    /// R2 API token secret access key
    pub secret_access_key: String,
}

#[cfg(feature = "storage-s3")]
impl fmt::Debug for R2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("R2Config")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "storage-s3")]
impl R2Config {
    /// Create a configuration for Cloudflare R2.
    pub fn new(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            bucket: bucket.into(),
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
        }
    }

    /// Read `R2_ACCOUNT_ID`, `R2_BUCKET`, `R2_ACCESS_KEY_ID`, and `R2_SECRET_ACCESS_KEY`.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .map_err(|_| TidewayError::internal(format!("{name} must be set for R2 storage")))
        };
        Ok(Self::new(
            var("R2_ACCOUNT_ID")?,
            var("R2_BUCKET")?,
            var("R2_ACCESS_KEY_ID")?,
            var("R2_SECRET_ACCESS_KEY")?,
        ))
    }
}

#[cfg(feature = "storage-s3")]
impl From<R2Config> for S3Config {
    fn from(config: R2Config) -> Self {
        S3Config::new(
            config.bucket,
            "auto",
            config.access_key_id,
            config.secret_access_key,
        )
        .endpoint(format!(
            "https://{}.r2.cloudflarestorage.com",
            config.account_id
        ))
    }
}
