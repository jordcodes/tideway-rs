use crate::auth::jwt_issuer::{AccessTokenClaims, TokenType};
use crate::error::{Result, TidewayError};
use futures::StreamExt;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Reusable HTTP client and safety policy for JWKS retrieval.
#[derive(Clone)]
pub struct JwksClient {
    http: Client,
    max_response_bytes: usize,
}

impl JwksClient {
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

    pub fn new() -> Result<Self> {
        let http = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TidewayError::internal(format!("Failed to build JWKS client: {e}")))?;
        Ok(Self {
            http,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    pub fn with_http_client(http: Client) -> Self {
        Self {
            http,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes.max(1);
        self
    }

    pub async fn fetch(&self, url: &str) -> Result<JwkSet> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to fetch JWKS: {e}")))?;

        if !response.status().is_success() {
            return Err(TidewayError::internal(format!(
                "JWKS endpoint returned status: {}",
                response.status()
            )));
        }

        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(TidewayError::internal(
                "JWKS response exceeds configured limit",
            ));
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| TidewayError::internal(format!("Failed to read JWKS: {e}")))?;
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(TidewayError::internal(
                    "JWKS response exceeds configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let raw: RawJwkSet = serde_json::from_slice(&body)
            .map_err(|e| TidewayError::internal(format!("Failed to parse JWKS: {e}")))?;
        let advertised_keys = raw.keys.len();
        let keys = rsa_keys(raw.keys);
        if advertised_keys > 0 && keys.is_empty() {
            return Err(TidewayError::internal(
                "JWKS contains no supported RSA keys",
            ));
        }
        Ok(JwkSet { keys })
    }
}

/// JSON Web Key (JWK) as returned by auth providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub n: String,
    pub e: String,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub alg: Option<String>,
}

/// JWK Set containing multiple keys
///
/// Only RSA keys are retained. Keys of other types (`EC`, `OKP`, `oct`) and malformed
/// RSA keys are skipped so a single unsupported key cannot break the whole set.
#[derive(Debug, Clone, Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct RawJwkSet {
    keys: Vec<serde_json::Value>,
}

/// Keep RSA keys, skipping other key types and malformed RSA keys.
fn rsa_keys(raw: Vec<serde_json::Value>) -> Vec<Jwk> {
    raw.into_iter()
        .filter_map(|value| {
            let kty = value.get("kty").and_then(serde_json::Value::as_str);
            if kty != Some("RSA") {
                tracing::debug!(kty = ?kty, "Skipping unsupported JWK key type");
                return None;
            }
            match serde_json::from_value::<Jwk>(value) {
                Ok(jwk) => Some(jwk),
                Err(error) => {
                    tracing::warn!(error = %error, "Skipping malformed RSA JWK");
                    None
                }
            }
        })
        .collect()
}

impl<'de> Deserialize<'de> for JwkSet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawJwkSet::deserialize(deserializer)?;
        Ok(Self {
            keys: rsa_keys(raw.keys),
        })
    }
}

impl JwkSet {
    /// Fetch JWK Set from a URL
    pub async fn fetch(url: &str) -> Result<Self> {
        JwksClient::new()?.fetch(url).await
    }

    /// Find a JWK by key ID
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys
            .iter()
            .find(|jwk| jwk.kid.as_ref().map(|k| k == kid).unwrap_or(false))
    }

    /// Get the first JWK (useful when there's only one key)
    pub fn first(&self) -> Option<&Jwk> {
        self.keys.first()
    }
}

/// Decoding keys prebuilt from a JWK Set, indexed by key ID, so verification does
/// not rebuild an RSA key on every request.
///
/// Fails when the set has keys but none of them has valid RSA components, so a
/// broken JWKS is rejected instead of silently replacing usable keys.
fn build_decoding_keys(set: &JwkSet) -> Result<HashMap<String, DecodingKey>> {
    let mut decoding_keys = HashMap::new();
    let mut valid_keys = 0;
    for jwk in &set.keys {
        let key = match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
            Ok(key) => key,
            Err(error) => {
                tracing::warn!(kid = ?jwk.kid, error = %error, "Skipping JWK with invalid RSA components");
                continue;
            }
        };
        valid_keys += 1;
        if let Some(kid) = &jwk.kid {
            decoding_keys.entry(kid.clone()).or_insert(key);
        }
    }
    if !set.keys.is_empty() && valid_keys == 0 {
        return Err(TidewayError::internal("JWKS contains no valid RSA keys"));
    }
    Ok(decoding_keys)
}

/// Fetch the JWKS and swap in its decoding keys. On any error the current keys are kept.
async fn refresh_decoding_keys(
    jwks: &RwLock<HashMap<String, DecodingKey>>,
    client: &JwksClient,
    url: &str,
) -> Result<()> {
    let decoding_keys = build_decoding_keys(&client.fetch(url).await?)?;
    *jwks.write().await = decoding_keys;
    Ok(())
}

/// Tracks the periodic JWKS refresh schedule.
struct JwksSchedule {
    last_attempt: Instant,
    last_attempt_failed: bool,
}

/// Generic JWT verifier that can work with any claims type
///
/// # Security Note
///
/// For production use, always configure both issuer and audience validation
/// using [`JwtVerifier::set_issuer`] and [`JwtVerifier::set_audience`]. Without these checks, tokens
/// from any issuer could be accepted if they have a valid signature.
#[derive(Clone)]
pub struct JwtVerifier<C> {
    jwks: Arc<RwLock<HashMap<String, DecodingKey>>>,
    jwks_url: Option<String>,
    jwks_client: Option<JwksClient>,
    jwks_refresh_interval: Option<Duration>,
    jwks_schedule: Arc<Mutex<JwksSchedule>>,
    last_unknown_kid_refresh: Arc<Mutex<Option<Instant>>>,
    unknown_kid_refresh_cooldown: Duration,
    decoding_key: Option<DecodingKey>,
    validation: Validation,
    /// Track whether issuer validation is configured
    issuer_configured: bool,
    /// Track whether audience validation is configured
    audience_configured: bool,
    /// Ensure security warning is only logged once per verifier instance
    /// This prevents log spam in high-traffic applications
    warning_logged: Arc<OnceLock<()>>,
    _claims: std::marker::PhantomData<C>,
}

impl<C: DeserializeOwned + Clone> JwtVerifier<C> {
    /// Minimum recommended key size for HS256 (256 bits).
    pub const MIN_HS256_SECRET_BYTES: usize = 32;

    /// Default interval between scheduled JWKS refreshes.
    pub const DEFAULT_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

    fn with_parts(
        jwks: HashMap<String, DecodingKey>,
        jwks_url: Option<String>,
        jwks_client: Option<JwksClient>,
        decoding_key: Option<DecodingKey>,
        validation: Validation,
    ) -> Self {
        Self {
            jwks: Arc::new(RwLock::new(jwks)),
            jwks_url,
            jwks_client,
            jwks_refresh_interval: Some(Self::DEFAULT_JWKS_REFRESH_INTERVAL),
            jwks_schedule: Arc::new(Mutex::new(JwksSchedule {
                last_attempt: Instant::now(),
                last_attempt_failed: false,
            })),
            last_unknown_kid_refresh: Arc::new(Mutex::new(None)),
            unknown_kid_refresh_cooldown: Duration::from_secs(30),
            decoding_key,
            validation,
            issuer_configured: false,
            audience_configured: false,
            warning_logged: Arc::new(OnceLock::new()),
            _claims: std::marker::PhantomData,
        }
    }

    /// Reuse this verifier's keys and validation rules to decode a different
    /// claims type, e.g. `AccessTokenClaims<ImpersonationClaims>` to read
    /// custom claims from tokens checked by a `JwtVerifier<AccessTokenClaims>`.
    #[must_use]
    pub fn with_claims<D: DeserializeOwned + Clone>(&self) -> JwtVerifier<D> {
        JwtVerifier {
            jwks: self.jwks.clone(),
            jwks_url: self.jwks_url.clone(),
            jwks_client: self.jwks_client.clone(),
            jwks_refresh_interval: self.jwks_refresh_interval,
            jwks_schedule: self.jwks_schedule.clone(),
            last_unknown_kid_refresh: self.last_unknown_kid_refresh.clone(),
            unknown_kid_refresh_cooldown: self.unknown_kid_refresh_cooldown,
            decoding_key: self.decoding_key.clone(),
            validation: self.validation.clone(),
            issuer_configured: self.issuer_configured,
            audience_configured: self.audience_configured,
            warning_logged: self.warning_logged.clone(),
            _claims: std::marker::PhantomData,
        }
    }

    /// Create a verifier using JWKS (fetches keys from URL)
    ///
    /// # Security Warning
    ///
    /// After creating a verifier, you should configure issuer and audience
    /// validation using [`Self::set_issuer`] and [`Self::set_audience`] before use in production.
    pub async fn from_jwks_url(url: impl Into<String>, algorithm: Algorithm) -> Result<Self> {
        Self::from_jwks_url_with_client(url, algorithm, JwksClient::new()?).await
    }

    /// Create a verifier using a caller-provided reusable JWKS client.
    pub async fn from_jwks_url_with_client(
        url: impl Into<String>,
        algorithm: Algorithm,
        client: JwksClient,
    ) -> Result<Self> {
        let url = url.into();
        let jwks = build_decoding_keys(&client.fetch(&url).await?)?;

        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;

        Ok(Self::with_parts(
            jwks,
            Some(url),
            Some(client),
            None,
            validation,
        ))
    }

    /// Create a verifier using a static secret (for HS256)
    ///
    /// # Security Warning
    ///
    /// After creating a verifier, you should configure issuer and audience
    /// validation using [`Self::set_issuer`] and [`Self::set_audience`] before use in production.
    #[deprecated(
        since = "0.7.21",
        note = "use JwtVerifier::from_secret_checked to enforce a safe minimum secret"
    )]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self::from_secret_unchecked(secret)
    }

    fn from_secret_unchecked(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        Self::with_parts(
            HashMap::new(),
            None,
            None,
            Some(DecodingKey::from_secret(secret)),
            validation,
        )
    }

    /// Create an HS256 verifier while enforcing a 256-bit minimum secret.
    pub fn from_secret_checked(secret: &[u8]) -> Result<Self> {
        if secret.len() < Self::MIN_HS256_SECRET_BYTES {
            return Err(TidewayError::internal(
                "HS256 JWT secret must be at least 32 bytes",
            ));
        }
        Ok(Self::from_secret_unchecked(secret))
    }

    /// Create a verifier using a static RSA public key (PEM format)
    ///
    /// # Security Warning
    ///
    /// After creating a verifier, you should configure issuer and audience
    /// validation using [`Self::set_issuer`] and [`Self::set_audience`] before use in production.
    pub fn from_rsa_pem(pem: &[u8]) -> Result<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(pem)
            .map_err(|e| TidewayError::internal(format!("Invalid RSA PEM: {}", e)))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        Ok(Self::with_parts(
            HashMap::new(),
            None,
            None,
            Some(decoding_key),
            validation,
        ))
    }

    /// Set the expected issuer claim
    ///
    /// **Strongly recommended for production use.** Without issuer validation,
    /// tokens from any issuer with a valid signature would be accepted.
    pub fn set_issuer(&mut self, issuer: impl Into<String>) {
        self.validation.set_issuer(&[issuer.into()]);
        self.issuer_configured = true;
    }

    /// Configure the expected issuer using builder syntax.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.set_issuer(issuer);
        self
    }

    /// Accept any of several issuer values (some providers use more than one spelling).
    ///
    /// An empty list leaves issuer validation unconfigured.
    pub fn with_issuers<I, S>(mut self, issuers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let issuers: Vec<String> = issuers.into_iter().map(Into::into).collect();
        if !issuers.is_empty() {
            self.validation.set_issuer(&issuers);
            self.issuer_configured = true;
        }
        self
    }

    /// Set the expected audience claim
    ///
    /// **Strongly recommended for production use.** Without audience validation,
    /// tokens intended for other applications could be accepted.
    pub fn set_audience(&mut self, audience: impl Into<String>) {
        self.validation.set_audience(&[audience.into()]);
        self.audience_configured = true;
    }

    /// Configure the expected audience using builder syntax.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.set_audience(audience);
        self
    }

    /// Set the minimum interval between automatic refreshes caused by unknown key IDs.
    pub fn with_unknown_kid_refresh_cooldown(mut self, cooldown: Duration) -> Self {
        self.unknown_kid_refresh_cooldown = cooldown;
        self
    }

    /// Set how often JWKS keys are re-fetched so rotated and revoked keys are picked up.
    ///
    /// Defaults to [`Self::DEFAULT_JWKS_REFRESH_INTERVAL`]. Once the interval has elapsed,
    /// the next verification starts a background refresh and keeps using the current keys
    /// meanwhile. If the refresh fails, or returns no valid RSA keys, the current keys stay
    /// in use and the refresh is retried after the unknown-key cooldown.
    pub fn with_jwks_refresh_interval(mut self, interval: Duration) -> Self {
        self.jwks_refresh_interval = Some(interval);
        self
    }

    /// Disable scheduled JWKS refreshes.
    ///
    /// Keys are then only re-fetched for unknown key IDs or by calling [`Self::refresh_jwks`],
    /// so keys removed by the provider stay trusted until the process restarts.
    pub fn without_scheduled_jwks_refresh(mut self) -> Self {
        self.jwks_refresh_interval = None;
        self
    }

    /// Refresh the JWKS (useful for key rotation)
    ///
    /// Returns an error and keeps the current keys if the fetch fails or the new set has
    /// no valid RSA keys.
    pub async fn refresh_jwks(&self) -> Result<()> {
        if let (Some(url), Some(client)) = (&self.jwks_url, &self.jwks_client) {
            refresh_decoding_keys(&self.jwks, client, url).await?;
        }
        Ok(())
    }

    /// Start a background JWKS refresh if the scheduled refresh interval has elapsed.
    ///
    /// Only one refresh runs at a time, and requests never wait for it.
    async fn refresh_jwks_if_due(&self) {
        let (Some(interval), Some(url), Some(client)) = (
            self.jwks_refresh_interval,
            &self.jwks_url,
            &self.jwks_client,
        ) else {
            return;
        };
        let Ok(mut schedule) = self.jwks_schedule.clone().try_lock_owned() else {
            return;
        };
        let wait = if schedule.last_attempt_failed {
            self.unknown_kid_refresh_cooldown.min(interval)
        } else {
            interval
        };
        if schedule.last_attempt.elapsed() < wait {
            return;
        }
        schedule.last_attempt = Instant::now();

        let jwks = self.jwks.clone();
        let client = client.clone();
        let url = url.clone();
        let refresh = async move {
            match refresh_decoding_keys(&jwks, &client, &url).await {
                Ok(()) => schedule.last_attempt_failed = false,
                Err(error) => {
                    schedule.last_attempt_failed = true;
                    tracing::warn!(error = %error, "Scheduled JWKS refresh failed; keeping current keys");
                }
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(refresh);
            }
            Err(_) => refresh.await,
        }
    }

    async fn cached_decoding_key(&self, kid: &str) -> Option<DecodingKey> {
        self.jwks.read().await.get(kid).cloned()
    }

    /// Verify and decode a JWT token
    ///
    /// # Security Warning
    ///
    /// If issuer or audience validation is not configured, a warning will be logged once.
    /// For production use, always configure both using [`Self::set_issuer`] and [`Self::set_audience`].
    pub async fn verify(&self, token: &str) -> Result<TokenData<C>> {
        // Warn ONCE if issuer/audience validation is not configured
        // Uses OnceLock to prevent log spam in high-traffic applications
        if !self.issuer_configured || !self.audience_configured {
            self.warning_logged.get_or_init(|| {
                if !self.issuer_configured && !self.audience_configured {
                    tracing::warn!(
                        "JWT verifier has no issuer or audience validation configured. \
                        This is insecure for production use. Call set_issuer() and set_audience() \
                        to validate these claims."
                    );
                } else if !self.issuer_configured {
                    tracing::warn!(
                        "JWT verifier has no issuer validation configured. \
                        Call set_issuer() to validate the token issuer."
                    );
                } else {
                    tracing::warn!(
                        "JWT verifier has no audience validation configured. \
                        Call set_audience() to validate the token audience."
                    );
                }
            });
        }

        // If we have a static decoding key, use it
        if let Some(key) = &self.decoding_key {
            return decode::<C>(token, key, &self.validation)
                .map_err(|e| TidewayError::unauthorized(format!("Invalid token: {}", e)));
        }

        // Otherwise, use JWKS
        let header = decode_header(token)
            .map_err(|e| TidewayError::unauthorized(format!("Invalid token header: {}", e)))?;

        let kid = header
            .kid
            .as_ref()
            .ok_or_else(|| TidewayError::unauthorized("Token missing 'kid' header"))?;

        self.refresh_jwks_if_due().await;

        let mut decoding_key = self.cached_decoding_key(kid).await;
        if decoding_key.is_none() && self.jwks_url.is_some() {
            let mut last_refresh = self.last_unknown_kid_refresh.lock().await;
            decoding_key = self.cached_decoding_key(kid).await;
            let refresh_allowed =
                last_refresh.is_none_or(|last| last.elapsed() >= self.unknown_kid_refresh_cooldown);
            if decoding_key.is_none() && refresh_allowed {
                *last_refresh = Some(Instant::now());
                self.refresh_jwks().await.map_err(|error| {
                    tracing::warn!(error = %error, "JWKS refresh failed for unknown key ID");
                    TidewayError::unauthorized("Token key is not available")
                })?;
                decoding_key = self.cached_decoding_key(kid).await;
            }
        }
        let decoding_key = decoding_key.ok_or_else(|| {
            TidewayError::unauthorized(format!("Key '{}' not found in JWKS", kid))
        })?;

        decode::<C>(token, &decoding_key, &self.validation)
            .map_err(|e| TidewayError::unauthorized(format!("Invalid token: {}", e)))
    }
}

impl<T> JwtVerifier<AccessTokenClaims<T>>
where
    T: DeserializeOwned + Clone + Serialize,
{
    /// Verify and decode an access token.
    ///
    /// This rejects refresh tokens even when they are signed by the same issuer.
    pub async fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<TokenData<AccessTokenClaims<T>>> {
        let token_data = self.verify(token).await?;

        if token_data.claims.token_type != TokenType::Access {
            return Err(TidewayError::unauthorized("Expected access token"));
        }

        Ok(token_data)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::auth::jwt_issuer::{JwtIssuer, JwtIssuerConfig, TokenSubject};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_create_verifier_from_secret() {
        let verifier = JwtVerifier::<TestClaims>::from_secret(b"my_secret");
        assert!(verifier.decoding_key.is_some());
    }

    #[test]
    fn test_checked_verifier_rejects_short_hs256_secret() {
        assert!(JwtVerifier::<TestClaims>::from_secret_checked(b"too-short").is_err());
        assert!(JwtVerifier::<TestClaims>::from_secret_checked(&[b'x'; 32]).is_ok());
    }

    #[tokio::test]
    async fn test_algorithm_confusion_attack_rejected() {
        // Create a verifier expecting HS256
        let secret = b"my_secret_key_for_testing_12345";
        let verifier = JwtVerifier::<TestClaims>::from_secret(secret);

        // Create a valid HS256 token
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .saturating_add(Duration::from_secs(60 * 60))
                .as_secs() as usize,
        };

        let valid_token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        // Valid token should work
        let result = verifier.verify(&valid_token).await;
        assert!(result.is_ok(), "Valid HS256 token should be accepted");

        // Now create a token with a DIFFERENT algorithm (HS384)
        // This simulates an algorithm confusion attack
        let wrong_algo_token = encode(
            &Header::new(Algorithm::HS384),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        // Token with wrong algorithm should be REJECTED
        let result = verifier.verify(&wrong_algo_token).await;
        assert!(
            result.is_err(),
            "Token with wrong algorithm should be rejected (algorithm confusion protection)"
        );

        // Verify the error message mentions the algorithm issue
        if let Err(e) = result {
            let error_msg = e.to_string();
            assert!(
                error_msg.contains("Invalid token"),
                "Error should indicate invalid token: {}",
                error_msg
            );
        }
    }

    #[tokio::test]
    async fn test_none_algorithm_rejected() {
        // Create a verifier expecting HS256
        let verifier = JwtVerifier::<TestClaims>::from_secret(b"secret");

        // Manually craft a token with "alg": "none" - a classic JWT attack
        // Header: {"alg":"none","typ":"JWT"}
        // This is base64url encoded
        let none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        let payload = "eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjo5OTk5OTk5OTk5fQ";
        let none_token = format!("{}{}.", none_header, payload);

        // "none" algorithm token should be REJECTED
        let result = verifier.verify(&none_token).await;
        assert!(
            result.is_err(),
            "Token with 'none' algorithm should be rejected"
        );
    }

    #[tokio::test]
    async fn test_verify_access_token_rejects_refresh_token() {
        let secret = "test_secret_for_access_token_purpose_checks";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(secret, "test-app")).unwrap();
        let tokens = issuer.issue(TokenSubject::new("user-123"), true).unwrap();
        let verifier = JwtVerifier::<AccessTokenClaims>::from_secret(secret.as_bytes());

        let access_result = verifier.verify_access_token(&tokens.access_token).await;
        assert!(access_result.is_ok(), "access tokens should be accepted");

        let refresh_result = verifier.verify_access_token(&tokens.refresh_token).await;
        assert!(
            refresh_result.is_err(),
            "refresh tokens must not authenticate access-token paths"
        );
    }

    #[tokio::test]
    async fn test_verify_access_token_rejects_wrong_audience() {
        let secret = "test_secret_for_audience_validation_123";
        let issuer = JwtIssuer::new(
            JwtIssuerConfig::with_secure_secret(secret, "test-app")
                .unwrap()
                .audience("api-a"),
        )
        .unwrap();
        let tokens = issuer.issue(TokenSubject::new("user-123"), false).unwrap();

        let valid = JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())
            .unwrap()
            .with_issuer("test-app")
            .with_audience("api-a");
        assert!(
            valid
                .verify_access_token(&tokens.access_token)
                .await
                .is_ok()
        );

        let wrong_audience =
            JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())
                .unwrap()
                .with_issuer("test-app")
                .with_audience("api-b");
        assert!(
            wrong_audience
                .verify_access_token(&tokens.access_token)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_with_claims_reads_custom_claims_with_same_validation() {
        use crate::auth::ImpersonationClaims;

        let secret = "test_secret_for_custom_claim_retyping_1";
        let issuer = JwtIssuer::new(
            JwtIssuerConfig::with_secure_secret(secret, "test-app")
                .unwrap()
                .audience("api-a"),
        )
        .unwrap();
        let claims = ImpersonationClaims {
            imp_session: "imp_abc".into(),
            imp_admin: "admin-1".into(),
            imp_blocked: vec!["delete_account".into()],
        };
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let (token, expires_in) = issuer
            .issue_access_token_expiring_at(
                TokenSubject::new("user-123").with_custom(claims.clone()),
                expires_at,
            )
            .unwrap();
        assert!(expires_in <= 600);

        let verifier = JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())
            .unwrap()
            .with_issuer("test-app")
            .with_audience("api-a");
        let data = verifier
            .with_claims::<AccessTokenClaims<ImpersonationClaims>>()
            .verify_access_token(&token)
            .await
            .unwrap();
        assert_eq!(data.claims.custom, Some(claims));
        assert_eq!(data.claims.standard.exp, expires_at);

        let plain = issuer
            .issue_access_token(TokenSubject::new("user-123"))
            .unwrap()
            .0;
        let data = verifier
            .with_claims::<AccessTokenClaims<ImpersonationClaims>>()
            .verify_access_token(&plain)
            .await
            .unwrap();
        assert_eq!(data.claims.custom, None);

        let wrong_audience =
            JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())
                .unwrap()
                .with_issuer("test-app")
                .with_audience("api-b")
                .with_claims::<AccessTokenClaims<ImpersonationClaims>>();
        assert!(wrong_audience.verify_access_token(&token).await.is_err());
    }

    #[tokio::test]
    async fn test_unknown_kid_refresh_cooldown_skips_repeated_network_fetch() {
        let mut verifier = JwtVerifier::<TestClaims>::from_secret(b"unused");
        verifier.decoding_key = None;
        verifier.jwks_url = Some("http://127.0.0.1:1/should-not-be-called".to_string());
        verifier.jwks_client = Some(JwksClient::new().unwrap());
        verifier.validation = Validation::new(Algorithm::RS256);
        *verifier.last_unknown_kid_refresh.lock().await = Some(std::time::Instant::now());

        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InJhbmRvbSJ9.e30.signature";
        let error = verifier.verify(token).await.unwrap_err();
        assert!(error.to_string().contains("not found in JWKS"));
    }

    struct TestRsaKey {
        kid: &'static str,
        encoding_key: EncodingKey,
        jwk: serde_json::Value,
    }

    fn test_rsa_key(kid: &'static str) -> TestRsaKey {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::traits::PublicKeyParts;

        let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        TestRsaKey {
            kid,
            encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            jwk: serde_json::json!({
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
            }),
        }
    }

    fn sign_rs256(key: &TestRsaKey) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.kid.to_string());
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
        };
        encode(&header, &claims, &key.encoding_key).unwrap()
    }

    fn ec_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "kid": "ec-key",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        })
    }

    /// Serves the JSON in `body` and counts requests.
    async fn serve_jwks(
        body: Arc<std::sync::Mutex<serde_json::Value>>,
        hits: Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let body = body.clone();
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    axum::Json(body.lock().unwrap().clone())
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/jwks")
    }

    #[test]
    fn test_jwk_set_skips_non_rsa_keys() {
        let rsa = test_rsa_key("rsa-key");
        let json = serde_json::json!({
            "keys": [
                ec_jwk(),
                { "kty": "OKP", "kid": "ed-key", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
                { "kty": "oct", "kid": "hmac-key", "k": "c2VjcmV0" },
                { "kty": "RSA", "kid": "broken-rsa" },
                rsa.jwk,
            ]
        });

        let set: JwkSet =
            serde_json::from_value(json).expect("non-RSA keys must not break the set");
        assert_eq!(set.keys.len(), 1);
        assert!(set.find_by_kid("rsa-key").is_some());
    }

    #[tokio::test]
    async fn test_jwks_verifier_accepts_rsa_key_alongside_ec_key_with_cached_decoding_key() {
        let rsa = test_rsa_key("rsa-key");
        let body = Arc::new(std::sync::Mutex::new(
            serde_json::json!({ "keys": [ec_jwk(), rsa.jwk.clone()] }),
        ));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = serve_jwks(body, hits.clone()).await;

        let verifier = JwtVerifier::<TestClaims>::from_jwks_url(url, Algorithm::RS256)
            .await
            .expect("JWKS with an EC key should still load");
        assert!(verifier.jwks.read().await.contains_key("rsa-key"));

        let token = sign_rs256(&rsa);
        verifier.verify(&token).await.expect("first verify");
        verifier.verify(&token).await.expect("second verify");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_jwks_refreshes_on_schedule_and_drops_revoked_keys() {
        let old_key = test_rsa_key("old-key");
        let new_key = test_rsa_key("new-key");
        let body = Arc::new(std::sync::Mutex::new(
            serde_json::json!({ "keys": [old_key.jwk.clone()] }),
        ));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = serve_jwks(body.clone(), hits.clone()).await;

        let verifier = JwtVerifier::<TestClaims>::from_jwks_url(url, Algorithm::RS256)
            .await
            .unwrap()
            .with_jwks_refresh_interval(Duration::from_millis(50))
            .with_unknown_kid_refresh_cooldown(Duration::from_secs(3600));
        let old_token = sign_rs256(&old_key);
        verifier
            .verify(&old_token)
            .await
            .expect("old key initially valid");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Provider rotates keys and revokes the old one.
        *body.lock().unwrap() = serde_json::json!({ "keys": [new_key.jwk.clone()] });
        tokio::time::sleep(Duration::from_millis(80)).await;

        // The refresh runs in the background, so the revocation lands shortly after.
        let deadline = Instant::now() + Duration::from_secs(5);
        while verifier.verify(&old_token).await.is_ok() {
            assert!(
                Instant::now() < deadline,
                "revoked key must stop verifying after the scheduled refresh"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        verifier
            .verify(&sign_rs256(&new_key))
            .await
            .expect("rotated key accepted");
    }

    #[tokio::test]
    async fn test_jwks_without_supported_keys_fails_to_load() {
        let body = Arc::new(std::sync::Mutex::new(
            serde_json::json!({ "keys": [ec_jwk()] }),
        ));
        let url = serve_jwks(body, Arc::default()).await;

        let result = JwtVerifier::<TestClaims>::from_jwks_url(url, Algorithm::RS256).await;
        assert!(result.is_err(), "a JWKS with only EC keys must not load");
    }

    #[tokio::test]
    async fn test_empty_jwks_still_loads() {
        let body = Arc::new(std::sync::Mutex::new(serde_json::json!({ "keys": [] })));
        let url = serve_jwks(body, Arc::default()).await;

        JwtVerifier::<TestClaims>::from_jwks_url(url, Algorithm::RS256)
            .await
            .expect("an empty JWKS loaded before and must keep loading");
    }

    #[tokio::test]
    async fn test_refresh_without_usable_keys_keeps_current_keys() {
        let key = test_rsa_key("rsa-key");
        let body = Arc::new(std::sync::Mutex::new(
            serde_json::json!({ "keys": [key.jwk.clone()] }),
        ));
        let url = serve_jwks(body.clone(), Arc::default()).await;
        let verifier = JwtVerifier::<TestClaims>::from_jwks_url(url, Algorithm::RS256)
            .await
            .unwrap();
        let token = sign_rs256(&key);

        *body.lock().unwrap() = serde_json::json!({ "keys": [ec_jwk()] });
        assert!(verifier.refresh_jwks().await.is_err());
        *body.lock().unwrap() = serde_json::json!({
            "keys": [{ "kty": "RSA", "kid": "rsa-key", "n": "!!", "e": "!!" }]
        });
        assert!(verifier.refresh_jwks().await.is_err());

        verifier
            .verify(&token)
            .await
            .expect("failed refreshes must keep the current keys");
    }

    #[tokio::test]
    async fn test_scheduled_jwks_refresh_can_be_disabled() {
        let key = test_rsa_key("rsa-key");
        let body = Arc::new(std::sync::Mutex::new(
            serde_json::json!({ "keys": [key.jwk.clone()] }),
        ));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = serve_jwks(body, hits.clone()).await;
        let verifier = JwtVerifier::<TestClaims>::from_jwks_url(url, Algorithm::RS256)
            .await
            .unwrap()
            .with_jwks_refresh_interval(Duration::ZERO)
            .without_scheduled_jwks_refresh();

        let token = sign_rs256(&key);
        for _ in 0..3 {
            verifier.verify(&token).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
