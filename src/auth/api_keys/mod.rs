//! Organization-scoped API keys (personal access tokens).
//!
//! Provides hashed, scoped, revocable API keys bound to an organization, with
//! last-used tracking, plus extractors that accept API keys on their own or
//! alongside JWT-authenticated users.
//!
//! # Security
//!
//! - Only a SHA-256 hash of the key is stored; the plaintext is returned once at creation
//! - Keys embed a public lookup ID so verification is a single indexed lookup
//!   followed by a constant-time hash comparison
//! - Keys can be revoked individually or per organization, and may expire
//! - `last_used_at` writes are throttled to avoid a database write on every request
//!
//! # Key format
//!
//! `{prefix}_{id}_{secret}`, e.g. `tw_3f2c…_q8Zr…`. The prefix (default `tw`)
//! makes keys easy to recognize in secret scanners and lets [`Principal`]
//! distinguish API keys from JWTs in the `Authorization` header.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::api_keys::{ApiKeyExtension, ApiKeyManager, ApiKeyConfig, NewApiKey};
//!
//! let manager = ApiKeyManager::new(store, ApiKeyConfig::default());
//!
//! // Issue a key (show `created.plaintext` to the user exactly once)
//! let created = manager
//!     .create(NewApiKey::new("org-123", "CI deploy").scopes(["projects:read"]))
//!     .await?;
//!
//! // Accept API keys in handlers
//! let app = Router::new()
//!     .route("/projects", get(list_projects))
//!     .layer(Extension(ApiKeyExtension::new(manager)));
//!
//! async fn list_projects(ApiKeyAuth(key): ApiKeyAuth) -> Result<Json<Vec<Project>>> {
//!     key.require_scope("projects:read")?;
//!     // Query projects for key.organization_id ...
//! }
//! ```

use crate::auth::extractors::AuthUser;
use crate::auth::provider::AuthProvider;
use crate::error::{Result, TidewayError};
use async_trait::async_trait;
use axum::{extract::FromRequestParts, http::request::Parts};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;

#[cfg(feature = "api-keys-seaorm")]
mod sea_orm_store;
#[cfg(feature = "api-keys-seaorm")]
pub use sea_orm_store::SeaOrmApiKeyStore;

/// Default key prefix.
const DEFAULT_PREFIX: &str = "tw";

/// Length of the random secret portion (32 bytes = 256 bits).
const SECRET_LENGTH: usize = 32;

/// Default minimum interval between `last_used_at` writes.
const DEFAULT_LAST_USED_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum length of a key name.
const MAX_NAME_LENGTH: usize = 255;

/// Maximum length of a single scope.
const MAX_SCOPE_LENGTH: usize = 128;

/// Header accepted for API keys in addition to `Authorization: Bearer`.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Scope that grants every permission.
pub const WILDCARD_SCOPE: &str = "*";

/// Configuration for API keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyConfig {
    /// Prefix for generated keys (default: `tw`). ASCII alphanumeric only.
    pub prefix: String,
    /// Expiry applied when a key is created without one (default: never).
    pub default_ttl: Option<Duration>,
    /// Maximum active keys per organization (default: unlimited).
    pub max_keys_per_organization: Option<usize>,
    /// Minimum interval between `last_used_at` writes (default: 60 seconds).
    pub last_used_update_interval: Duration,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            prefix: DEFAULT_PREFIX.to_string(),
            default_ttl: None,
            max_keys_per_organization: None,
            last_used_update_interval: DEFAULT_LAST_USED_INTERVAL,
        }
    }
}

impl ApiKeyConfig {
    /// Create a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the key prefix.
    ///
    /// The prefix must be non-empty ASCII alphanumeric; this is checked by
    /// [`ApiKeyManager::new`].
    #[must_use]
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Set the default expiry for keys created without one.
    #[must_use]
    pub fn default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    /// Limit the number of active keys per organization.
    #[must_use]
    pub fn max_keys_per_organization(mut self, max: usize) -> Self {
        self.max_keys_per_organization = Some(max);
        self
    }

    /// Set the minimum interval between `last_used_at` writes.
    ///
    /// Use `Duration::ZERO` to record every use.
    #[must_use]
    pub fn last_used_update_interval(mut self, interval: Duration) -> Self {
        self.last_used_update_interval = interval;
        self
    }
}

/// A stored API key. Never contains the plaintext secret.
#[derive(Clone, Debug)]
pub struct ApiKey {
    /// Public key ID (embedded in the key and safe to display).
    pub id: String,
    /// Organization the key belongs to and acts on behalf of.
    pub organization_id: String,
    /// Human-readable name (e.g. "CI deploy").
    pub name: String,
    /// SHA-256 hash (hex) of the full key.
    pub key_hash: String,
    /// Granted scopes, e.g. `projects:read`, `projects:*`, or `*`.
    pub scopes: Vec<String>,
    /// User who created the key, if known.
    pub created_by: Option<String>,
    /// When the key was created.
    pub created_at: SystemTime,
    /// When the key expires, if ever.
    pub expires_at: Option<SystemTime>,
    /// Last time the key successfully authenticated (throttled).
    pub last_used_at: Option<SystemTime>,
    /// When the key was revoked, if it has been.
    pub revoked_at: Option<SystemTime>,
}

impl ApiKey {
    /// Check if the key has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| SystemTime::now() >= expires_at)
    }

    /// Check if the key has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if the key can currently be used.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.is_revoked() && !self.is_expired()
    }

    /// Check whether the key grants `scope`.
    ///
    /// Matches exactly, via the `*` wildcard, or via a `resource:*` wildcard
    /// covering `resource:<anything>`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|granted| scope_matches(granted, scope))
    }

    /// Return a 403 error unless the key grants `scope`.
    pub fn require_scope(&self, scope: &str) -> Result<()> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(TidewayError::forbidden(format!(
                "API key is missing required scope '{scope}'"
            )))
        }
    }
}

fn scope_matches(granted: &str, requested: &str) -> bool {
    if granted == WILDCARD_SCOPE || granted == requested {
        return true;
    }
    granted
        .strip_suffix(":*")
        .and_then(|resource| requested.strip_prefix(resource))
        .is_some_and(|rest| rest.starts_with(':'))
}

/// Parameters for creating an API key.
#[derive(Clone, Debug)]
pub struct NewApiKey {
    /// Organization the key belongs to.
    pub organization_id: String,
    /// Human-readable name.
    pub name: String,
    /// Scopes to grant.
    pub scopes: Vec<String>,
    /// User creating the key.
    pub created_by: Option<String>,
    /// Lifetime of the key; falls back to [`ApiKeyConfig::default_ttl`].
    pub expires_in: Option<Duration>,
}

impl NewApiKey {
    /// Start building a key for an organization.
    #[must_use]
    pub fn new(organization_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            organization_id: organization_id.into(),
            name: name.into(),
            scopes: Vec::new(),
            created_by: None,
            expires_in: None,
        }
    }

    /// Set the granted scopes.
    #[must_use]
    pub fn scopes<I, T>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Record the user creating the key.
    #[must_use]
    pub fn created_by(mut self, user_id: impl Into<String>) -> Self {
        self.created_by = Some(user_id.into());
        self
    }

    /// Set the key lifetime.
    #[must_use]
    pub fn expires_in(mut self, ttl: Duration) -> Self {
        self.expires_in = Some(ttl);
        self
    }
}

/// A newly created key along with its plaintext.
///
/// The plaintext cannot be recovered later; return it to the user once.
#[derive(Clone)]
pub struct CreatedApiKey {
    /// Stored key metadata.
    pub api_key: ApiKey,
    /// The full plaintext key.
    pub plaintext: String,
}

impl std::fmt::Debug for CreatedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedApiKey")
            .field("api_key", &self.api_key)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

/// Trait for API key storage.
///
/// Implementations should index `id` (primary key) and `organization_id`.
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Store a new API key.
    async fn create_api_key(&self, key: &ApiKey) -> Result<()>;

    /// Find a key by its public ID, including revoked and expired keys.
    async fn find_api_key(&self, id: &str) -> Result<Option<ApiKey>>;

    /// List all keys for an organization (including revoked), newest first.
    async fn list_api_keys(&self, organization_id: &str) -> Result<Vec<ApiKey>>;

    /// Set `last_used_at` for a key.
    async fn touch_api_key(&self, id: &str, used_at: SystemTime) -> Result<()>;

    /// Set `revoked_at` for a key. Returns false if the key does not exist
    /// or was already revoked.
    async fn revoke_api_key(&self, id: &str, revoked_at: SystemTime) -> Result<bool>;

    /// Revoke every active key for an organization. Returns the number revoked.
    async fn revoke_all_api_keys(
        &self,
        organization_id: &str,
        revoked_at: SystemTime,
    ) -> Result<usize> {
        let mut count = 0;
        for key in self.list_api_keys(organization_id).await? {
            if !key.is_revoked() && self.revoke_api_key(&key.id, revoked_at).await? {
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Manager for API key operations.
pub struct ApiKeyManager<S: ApiKeyStore> {
    store: Arc<S>,
    config: ApiKeyConfig,
}

impl<S: ApiKeyStore> Clone for ApiKeyManager<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            config: self.config.clone(),
        }
    }
}

impl<S: ApiKeyStore> ApiKeyManager<S> {
    /// Create a new API key manager.
    ///
    /// # Panics
    ///
    /// Panics if the configured prefix is empty or not ASCII alphanumeric.
    #[must_use]
    pub fn new(store: S, config: ApiKeyConfig) -> Self {
        Self::from_arc(Arc::new(store), config)
    }

    /// Create a manager from a shared store.
    ///
    /// # Panics
    ///
    /// Panics if the configured prefix is empty or not ASCII alphanumeric.
    #[must_use]
    pub fn from_arc(store: Arc<S>, config: ApiKeyConfig) -> Self {
        assert!(
            !config.prefix.is_empty() && config.prefix.chars().all(|c| c.is_ascii_alphanumeric()),
            "API key prefix must be non-empty ASCII alphanumeric"
        );
        Self { store, config }
    }

    /// Create a new API key.
    pub async fn create(&self, request: NewApiKey) -> Result<CreatedApiKey> {
        let organization_id = request.organization_id.trim();
        if organization_id.is_empty() {
            return Err(TidewayError::bad_request("organization_id is required"));
        }
        let name = request.name.trim();
        if name.is_empty() || name.len() > MAX_NAME_LENGTH {
            return Err(TidewayError::bad_request(format!(
                "API key name must be between 1 and {MAX_NAME_LENGTH} characters"
            )));
        }
        let mut scopes = Vec::with_capacity(request.scopes.len());
        for scope in request.scopes {
            let scope = scope.trim();
            if scope.is_empty()
                || scope.len() > MAX_SCOPE_LENGTH
                || scope.chars().any(char::is_whitespace)
            {
                return Err(TidewayError::bad_request(format!(
                    "Invalid API key scope '{scope}'"
                )));
            }
            if !scopes.iter().any(|s| s == scope) {
                scopes.push(scope.to_string());
            }
        }

        if let Some(max) = self.config.max_keys_per_organization {
            let active = self
                .store
                .list_api_keys(organization_id)
                .await?
                .iter()
                .filter(|key| key.is_active())
                .count();
            if active >= max {
                return Err(TidewayError::conflict(format!(
                    "Organization already has the maximum of {max} active API keys"
                )));
            }
        }

        let id = uuid::Uuid::new_v4().simple().to_string();
        let plaintext = format!("{}_{}_{}", self.config.prefix, id, generate_secret());
        let now = SystemTime::now();
        let api_key = ApiKey {
            id: id.clone(),
            organization_id: organization_id.to_string(),
            name: name.to_string(),
            key_hash: hash_key(&plaintext),
            scopes,
            created_by: request.created_by,
            created_at: now,
            expires_at: request
                .expires_in
                .or(self.config.default_ttl)
                .map(|ttl| now + ttl),
            last_used_at: None,
            revoked_at: None,
        };

        self.store.create_api_key(&api_key).await?;

        tracing::info!(
            target: "auth.api_key.created",
            organization_id = %api_key.organization_id,
            api_key_id = %id,
            "API key created"
        );

        Ok(CreatedApiKey { api_key, plaintext })
    }

    /// Authenticate a plaintext key.
    ///
    /// Returns 401 for malformed, unknown, revoked, or expired keys. All
    /// failures use the same message so callers cannot probe key state.
    pub async fn authenticate(&self, raw_key: &str) -> Result<ApiKey> {
        let invalid = || TidewayError::unauthorized("Invalid API key");

        let id = self.parse_key_id(raw_key).ok_or_else(invalid)?;
        let mut key = self.store.find_api_key(id).await?.ok_or_else(invalid)?;

        let hash = hash_key(raw_key);
        if !bool::from(hash.as_bytes().ct_eq(key.key_hash.as_bytes())) {
            return Err(invalid());
        }

        if !key.is_active() {
            tracing::debug!(
                target: "auth.api_key.inactive",
                api_key_id = %key.id,
                revoked = key.is_revoked(),
                "Inactive API key presented"
            );
            return Err(invalid());
        }

        let now = SystemTime::now();
        let stale = key.last_used_at.is_none_or(|last| {
            now.duration_since(last).unwrap_or_default() >= self.config.last_used_update_interval
        });
        if stale {
            if let Err(error) = self.store.touch_api_key(&key.id, now).await {
                tracing::warn!(
                    target: "auth.api_key.touch_failed",
                    api_key_id = %key.id,
                    error = %error,
                    "Failed to record API key usage"
                );
            } else {
                key.last_used_at = Some(now);
            }
        }

        Ok(key)
    }

    /// Get a key belonging to an organization.
    pub async fn get(&self, organization_id: &str, key_id: &str) -> Result<Option<ApiKey>> {
        Ok(self
            .store
            .find_api_key(key_id)
            .await?
            .filter(|key| key.organization_id == organization_id))
    }

    /// List keys for an organization, newest first.
    pub async fn list(&self, organization_id: &str) -> Result<Vec<ApiKey>> {
        self.store.list_api_keys(organization_id).await
    }

    /// Revoke a key belonging to an organization.
    ///
    /// Returns false if the key does not exist, belongs to another
    /// organization, or is already revoked.
    pub async fn revoke(&self, organization_id: &str, key_id: &str) -> Result<bool> {
        if self.get(organization_id, key_id).await?.is_none() {
            return Ok(false);
        }

        let revoked = self.store.revoke_api_key(key_id, SystemTime::now()).await?;
        if revoked {
            tracing::info!(
                target: "auth.api_key.revoked",
                organization_id = %organization_id,
                api_key_id = %key_id,
                "API key revoked"
            );
        }
        Ok(revoked)
    }

    /// Revoke every active key for an organization.
    pub async fn revoke_all(&self, organization_id: &str) -> Result<usize> {
        let count = self
            .store
            .revoke_all_api_keys(organization_id, SystemTime::now())
            .await?;
        tracing::warn!(
            target: "auth.api_key.revoke_all",
            organization_id = %organization_id,
            count = count,
            "All API keys revoked for organization"
        );
        Ok(count)
    }

    /// Require that `user_id` may manage API keys for `organization_id`.
    ///
    /// API keys act on behalf of the whole organization, so managing them is
    /// treated as an organization settings change: the user must be a member
    /// whose role passes [`MembershipStore::can_manage_settings`]. Returns 403
    /// otherwise. Call this before [`create`](Self::create),
    /// [`list`](Self::list), [`revoke`](Self::revoke), or
    /// [`revoke_all`](Self::revoke_all) on behalf of a user.
    ///
    /// [`MembershipStore::can_manage_settings`]: crate::organizations::MembershipStore::can_manage_settings
    #[cfg(feature = "organizations")]
    pub async fn authorize_management<M>(
        &self,
        memberships: &M,
        organization_id: &str,
        user_id: &str,
    ) -> Result<()>
    where
        M: crate::organizations::MembershipStore,
    {
        let allowed = memberships
            .get_membership(organization_id, user_id)
            .await?
            .is_some_and(|membership| {
                memberships.can_manage_settings(&memberships.membership_role(&membership))
            });
        if allowed {
            Ok(())
        } else {
            Err(TidewayError::forbidden(
                "You do not have permission to manage API keys for this organization",
            ))
        }
    }

    /// Check whether a credential has this manager's key format.
    #[must_use]
    pub fn is_api_key(&self, raw_key: &str) -> bool {
        self.parse_key_id(raw_key).is_some()
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &ApiKeyConfig {
        &self.config
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    fn parse_key_id<'a>(&self, raw_key: &'a str) -> Option<&'a str> {
        let rest = raw_key
            .strip_prefix(self.config.prefix.as_str())?
            .strip_prefix('_')?;
        let (id, secret) = rest.split_once('_')?;
        let valid_id = id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit());
        (valid_id && !secret.is_empty()).then_some(id)
    }
}

fn generate_secret() -> String {
    use rand::Rng;
    let bytes: [u8; SECRET_LENGTH] = rand::thread_rng().r#gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_key(raw_key: &str) -> String {
    format!("{:x}", Sha256::digest(raw_key.as_bytes()))
}

/// Object-safe API key verification used by the request extractors.
#[async_trait]
pub trait ApiKeyAuthenticator: Send + Sync + 'static {
    /// Authenticate a plaintext key.
    async fn authenticate(&self, raw_key: &str) -> Result<ApiKey>;

    /// Check whether a bearer credential looks like an API key (rather than a JWT).
    fn is_api_key(&self, raw_key: &str) -> bool;
}

#[async_trait]
impl<S: ApiKeyStore + 'static> ApiKeyAuthenticator for ApiKeyManager<S> {
    async fn authenticate(&self, raw_key: &str) -> Result<ApiKey> {
        ApiKeyManager::authenticate(self, raw_key).await
    }

    fn is_api_key(&self, raw_key: &str) -> bool {
        ApiKeyManager::is_api_key(self, raw_key)
    }
}

/// Request extension that enables the API key extractors.
///
/// ```rust,ignore
/// router.layer(Extension(ApiKeyExtension::new(manager)))
/// ```
#[derive(Clone)]
pub struct ApiKeyExtension(pub Arc<dyn ApiKeyAuthenticator>);

impl ApiKeyExtension {
    /// Wrap an authenticator (typically an [`ApiKeyManager`]).
    #[must_use]
    pub fn new(authenticator: impl ApiKeyAuthenticator) -> Self {
        Self(Arc::new(authenticator))
    }
}

/// Where the request carried an API key, if anywhere.
fn api_key_credential<'a>(
    parts: &'a Parts,
    authenticator: &dyn ApiKeyAuthenticator,
) -> Option<&'a str> {
    if let Some(value) = parts.headers.get(API_KEY_HEADER) {
        // An explicit API key header is always treated as an API key, even if
        // malformed, so it fails closed instead of falling through to JWT auth.
        return Some(value.to_str().unwrap_or_default().trim());
    }

    parts
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| authenticator.is_api_key(token))
}

async fn authenticate_parts(
    parts: &mut Parts,
    authenticator: &dyn ApiKeyAuthenticator,
    credential: &str,
) -> Result<ApiKey> {
    let key = authenticator.authenticate(credential).await?;
    parts.extensions.insert(key.clone());
    Ok(key)
}

fn resolve_authenticator(parts: &Parts) -> Result<Arc<dyn ApiKeyAuthenticator>> {
    parts
        .extensions
        .get::<ApiKeyExtension>()
        .map(|ext| Arc::clone(&ext.0))
        .ok_or_else(|| TidewayError::internal("ApiKeyExtension not found in request extensions"))
}

/// Axum extractor that requires a valid API key.
///
/// Accepts `X-API-Key: <key>` or `Authorization: Bearer <key>`.
/// Rejects with 401 if no valid key is present.
pub struct ApiKeyAuth(pub ApiKey);

impl<S> FromRequestParts<S> for ApiKeyAuth
where
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            if let Some(key) = parts.extensions.get::<ApiKey>().cloned() {
                return Ok(ApiKeyAuth(key));
            }

            let authenticator = resolve_authenticator(parts)?;
            let credential = api_key_credential(parts, authenticator.as_ref())
                .map(str::to_owned)
                .ok_or_else(|| TidewayError::unauthorized("Missing API key"))?;

            authenticate_parts(parts, authenticator.as_ref(), &credential)
                .await
                .map(ApiKeyAuth)
        })
    }
}

/// The authenticated caller: either a user (via the [`AuthProvider`]) or an API key.
#[allow(clippy::large_enum_variant)] // `P::User` is generic; boxing would only hurt ergonomics.
pub enum Principal<P: AuthProvider> {
    /// A user authenticated by JWT.
    User(P::User),
    /// An organization API key.
    ApiKey(ApiKey),
}

impl<P: AuthProvider> Clone for Principal<P> {
    fn clone(&self) -> Self {
        match self {
            Self::User(user) => Self::User(user.clone()),
            Self::ApiKey(key) => Self::ApiKey(key.clone()),
        }
    }
}

impl<P: AuthProvider> Principal<P> {
    /// The user, if authenticated as one.
    #[must_use]
    pub fn user(&self) -> Option<&P::User> {
        match self {
            Self::User(user) => Some(user),
            Self::ApiKey(_) => None,
        }
    }

    /// The API key, if authenticated with one.
    #[must_use]
    pub fn api_key(&self) -> Option<&ApiKey> {
        match self {
            Self::User(_) => None,
            Self::ApiKey(key) => Some(key),
        }
    }
}

/// Axum extractor that accepts either a JWT-authenticated user or an API key.
///
/// API keys are detected via the `X-API-Key` header or a bearer token with the
/// configured key prefix; anything else is authenticated with the
/// [`AuthProvider`] exactly like [`AuthUser`]. If no [`ApiKeyExtension`] is
/// installed, only users are accepted.
///
/// ```rust,ignore
/// async fn list_projects(principal: Principal<MyAuthProvider>) -> Result<Json<Vec<Project>>> {
///     let org_id = match &principal {
///         Principal::User(user) => user.current_org_id.clone(),
///         Principal::ApiKey(key) => {
///             key.require_scope("projects:read")?;
///             key.organization_id.clone()
///         }
///     };
///     // ...
/// }
/// ```
impl<P, S> FromRequestParts<S> for Principal<P>
where
    P: AuthProvider,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            if let Some(key) = parts.extensions.get::<ApiKey>().cloned() {
                return Ok(Principal::ApiKey(key));
            }

            if let Ok(authenticator) = resolve_authenticator(parts)
                && let Some(credential) =
                    api_key_credential(parts, authenticator.as_ref()).map(str::to_owned)
            {
                return authenticate_parts(parts, authenticator.as_ref(), &credential)
                    .await
                    .map(Principal::ApiKey);
            }

            let AuthUser(user) = AuthUser::<P>::from_request_parts(parts, state).await?;
            Ok(Principal::User(user))
        })
    }
}

/// In-memory store for testing.
#[cfg(any(test, feature = "test-auth-bypass"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// In-memory API key store for testing.
    #[derive(Default)]
    pub struct InMemoryApiKeyStore {
        keys: RwLock<HashMap<String, ApiKey>>,
    }

    impl InMemoryApiKeyStore {
        /// Create a new in-memory store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl ApiKeyStore for InMemoryApiKeyStore {
        async fn create_api_key(&self, key: &ApiKey) -> Result<()> {
            self.keys
                .write()
                .unwrap()
                .insert(key.id.clone(), key.clone());
            Ok(())
        }

        async fn find_api_key(&self, id: &str) -> Result<Option<ApiKey>> {
            Ok(self.keys.read().unwrap().get(id).cloned())
        }

        async fn list_api_keys(&self, organization_id: &str) -> Result<Vec<ApiKey>> {
            let keys = self.keys.read().unwrap();
            let mut result: Vec<_> = keys
                .values()
                .filter(|key| key.organization_id == organization_id)
                .cloned()
                .collect();
            result.sort_by_key(|key| std::cmp::Reverse(key.created_at));
            Ok(result)
        }

        async fn touch_api_key(&self, id: &str, used_at: SystemTime) -> Result<()> {
            if let Some(key) = self.keys.write().unwrap().get_mut(id) {
                key.last_used_at = Some(used_at);
            }
            Ok(())
        }

        async fn revoke_api_key(&self, id: &str, revoked_at: SystemTime) -> Result<bool> {
            let mut keys = self.keys.write().unwrap();
            match keys.get_mut(id) {
                Some(key) if key.revoked_at.is_none() => {
                    key.revoked_at = Some(revoked_at);
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test::InMemoryApiKeyStore;
    use super::*;

    fn manager() -> ApiKeyManager<InMemoryApiKeyStore> {
        ApiKeyManager::new(InMemoryApiKeyStore::new(), ApiKeyConfig::default())
    }

    #[tokio::test]
    async fn created_key_is_stored_hashed_and_authenticates() {
        let manager = manager();
        let created = manager
            .create(
                NewApiKey::new("org-1", "CI")
                    .scopes(["projects:read"])
                    .created_by("user-1"),
            )
            .await
            .unwrap();

        assert!(created.plaintext.starts_with("tw_"));
        let stored = manager
            .store()
            .find_api_key(&created.api_key.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored.key_hash, created.plaintext);
        assert!(!stored.key_hash.contains(&created.plaintext));
        assert_eq!(stored.key_hash.len(), 64);
        assert_eq!(stored.created_by.as_deref(), Some("user-1"));
        assert!(!format!("{created:?}").contains(&created.plaintext));

        let key = manager.authenticate(&created.plaintext).await.unwrap();
        assert_eq!(key.organization_id, "org-1");
        assert!(key.has_scope("projects:read"));
    }

    #[tokio::test]
    async fn tampered_or_malformed_keys_are_rejected() {
        let manager = manager();
        let created = manager.create(NewApiKey::new("org-1", "CI")).await.unwrap();

        let mut tampered = created.plaintext.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        for bad in [
            tampered.as_str(),
            "",
            "tw_",
            "tw_notanid_secret",
            "eyJhbGciOiJIUzI1NiJ9.e30.sig",
            &created.plaintext.replacen("tw_", "xx_", 1),
        ] {
            assert!(manager.authenticate(bad).await.is_err(), "accepted {bad:?}");
        }
    }

    #[tokio::test]
    async fn revoked_keys_are_rejected_and_revocation_is_org_bound() {
        let manager = manager();
        let created = manager.create(NewApiKey::new("org-1", "CI")).await.unwrap();
        let id = &created.api_key.id;

        assert!(!manager.revoke("org-2", id).await.unwrap());
        assert!(manager.authenticate(&created.plaintext).await.is_ok());

        assert!(manager.revoke("org-1", id).await.unwrap());
        assert!(!manager.revoke("org-1", id).await.unwrap());
        assert!(manager.authenticate(&created.plaintext).await.is_err());
    }

    #[tokio::test]
    async fn revoke_all_only_affects_one_organization() {
        let manager = manager();
        let a1 = manager.create(NewApiKey::new("org-1", "a")).await.unwrap();
        let a2 = manager.create(NewApiKey::new("org-1", "b")).await.unwrap();
        let b = manager.create(NewApiKey::new("org-2", "c")).await.unwrap();

        assert_eq!(manager.revoke_all("org-1").await.unwrap(), 2);
        assert!(manager.authenticate(&a1.plaintext).await.is_err());
        assert!(manager.authenticate(&a2.plaintext).await.is_err());
        assert!(manager.authenticate(&b.plaintext).await.is_ok());
    }

    #[tokio::test]
    async fn expired_keys_are_rejected() {
        let manager = manager();
        let created = manager
            .create(NewApiKey::new("org-1", "CI").expires_in(Duration::ZERO))
            .await
            .unwrap();
        assert!(manager.authenticate(&created.plaintext).await.is_err());
    }

    #[tokio::test]
    async fn last_used_is_tracked_and_throttled() {
        let manager = manager();
        let created = manager.create(NewApiKey::new("org-1", "CI")).await.unwrap();
        assert!(created.api_key.last_used_at.is_none());

        let first = manager.authenticate(&created.plaintext).await.unwrap();
        let first_used = first.last_used_at.expect("last_used_at recorded");
        let stored = manager
            .store()
            .find_api_key(&first.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.last_used_at, Some(first_used));

        // Within the throttle window the stored timestamp is not rewritten.
        let second = manager.authenticate(&created.plaintext).await.unwrap();
        assert_eq!(second.last_used_at, Some(first_used));

        let eager = ApiKeyManager::from_arc(
            Arc::clone(&manager.store),
            ApiKeyConfig::default().last_used_update_interval(Duration::ZERO),
        );
        std::thread::sleep(Duration::from_millis(2));
        let third = eager.authenticate(&created.plaintext).await.unwrap();
        assert!(third.last_used_at.unwrap() > first_used);
    }

    #[tokio::test]
    async fn create_validates_input_and_enforces_limit() {
        let manager = ApiKeyManager::new(
            InMemoryApiKeyStore::new(),
            ApiKeyConfig::default().max_keys_per_organization(1),
        );
        assert!(manager.create(NewApiKey::new("", "CI")).await.is_err());
        assert!(manager.create(NewApiKey::new("org-1", " ")).await.is_err());
        assert!(
            manager
                .create(NewApiKey::new("org-1", "CI").scopes(["bad scope"]))
                .await
                .is_err()
        );

        let first = manager.create(NewApiKey::new("org-1", "CI")).await.unwrap();
        assert!(
            manager
                .create(NewApiKey::new("org-1", "CI 2"))
                .await
                .is_err()
        );
        assert!(manager.create(NewApiKey::new("org-2", "CI")).await.is_ok());

        // Revoking frees a slot.
        manager.revoke("org-1", &first.api_key.id).await.unwrap();
        assert!(
            manager
                .create(NewApiKey::new("org-1", "CI 2"))
                .await
                .is_ok()
        );
    }

    #[cfg(feature = "organizations")]
    #[tokio::test]
    async fn only_members_who_manage_settings_may_manage_keys() {
        use crate::organizations::{
            DefaultOrgRole, InMemoryOrgStore, MembershipStore, TestMembership,
        };

        let orgs = InMemoryOrgStore::new();
        for (user_id, role) in [
            ("owner", DefaultOrgRole::Owner),
            ("admin", DefaultOrgRole::Admin),
            ("member", DefaultOrgRole::Member),
        ] {
            orgs.add_member(&TestMembership {
                org_id: "org-1".into(),
                user_id: user_id.into(),
                role,
                joined_at: 0,
            })
            .await
            .unwrap();
        }

        let manager = manager();
        assert!(
            manager
                .authorize_management(&orgs, "org-1", "owner")
                .await
                .is_ok()
        );
        assert!(
            manager
                .authorize_management(&orgs, "org-1", "admin")
                .await
                .is_ok()
        );
        for (org, user) in [
            ("org-1", "member"),
            ("org-1", "stranger"),
            ("org-2", "owner"),
        ] {
            let error = manager
                .authorize_management(&orgs, org, user)
                .await
                .unwrap_err();
            assert!(matches!(error, TidewayError::Forbidden(_)), "{org}/{user}");
        }
    }

    #[test]
    fn scope_matching() {
        assert!(scope_matches("*", "anything:here"));
        assert!(scope_matches("projects:read", "projects:read"));
        assert!(scope_matches("projects:*", "projects:write"));
        assert!(!scope_matches("projects:*", "projectsx:write"));
        assert!(!scope_matches("projects:*", "projects"));
        assert!(!scope_matches("projects:read", "projects:write"));
    }

    #[test]
    #[should_panic(expected = "prefix")]
    fn invalid_prefix_panics() {
        let _ = ApiKeyManager::new(
            InMemoryApiKeyStore::new(),
            ApiKeyConfig::new().prefix("tw_x"),
        );
    }
}
