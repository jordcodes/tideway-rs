use crate::auth::jwt_issuer::{AccessTokenClaims, TokenType};
use crate::error::{Result, TidewayError};
use futures::StreamExt;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::{Arc, OnceLock};
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

        serde_json::from_slice(&body)
            .map_err(|e| TidewayError::internal(format!("Failed to parse JWKS: {e}")))
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
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

/// Generic JWT verifier that can work with any claims type
///
/// # Security Note
///
/// For production use, always configure both issuer and audience validation
/// using [`set_issuer`] and [`set_audience`]. Without these checks, tokens
/// from any issuer could be accepted if they have a valid signature.
#[derive(Clone)]
pub struct JwtVerifier<C> {
    jwks: Arc<RwLock<JwkSet>>,
    jwks_url: Option<String>,
    jwks_client: Option<JwksClient>,
    last_unknown_kid_refresh: Arc<Mutex<Option<std::time::Instant>>>,
    unknown_kid_refresh_cooldown: std::time::Duration,
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

    /// Create a verifier using JWKS (fetches keys from URL)
    ///
    /// # Security Warning
    ///
    /// After creating a verifier, you should configure issuer and audience
    /// validation using [`set_issuer`] and [`set_audience`] before use in production.
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
        let jwks = client.fetch(&url).await?;

        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;

        Ok(Self {
            jwks: Arc::new(RwLock::new(jwks)),
            jwks_url: Some(url),
            jwks_client: Some(client),
            last_unknown_kid_refresh: Arc::new(Mutex::new(None)),
            unknown_kid_refresh_cooldown: std::time::Duration::from_secs(30),
            decoding_key: None,
            validation,
            issuer_configured: false,
            audience_configured: false,
            warning_logged: Arc::new(OnceLock::new()),
            _claims: std::marker::PhantomData,
        })
    }

    /// Create a verifier using a static secret (for HS256)
    ///
    /// # Security Warning
    ///
    /// After creating a verifier, you should configure issuer and audience
    /// validation using [`set_issuer`] and [`set_audience`] before use in production.
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

        Self {
            jwks: Arc::new(RwLock::new(JwkSet { keys: vec![] })),
            jwks_url: None,
            jwks_client: None,
            last_unknown_kid_refresh: Arc::new(Mutex::new(None)),
            unknown_kid_refresh_cooldown: std::time::Duration::from_secs(30),
            decoding_key: Some(DecodingKey::from_secret(secret)),
            validation,
            issuer_configured: false,
            audience_configured: false,
            warning_logged: Arc::new(OnceLock::new()),
            _claims: std::marker::PhantomData,
        }
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
    /// validation using [`set_issuer`] and [`set_audience`] before use in production.
    pub fn from_rsa_pem(pem: &[u8]) -> Result<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(pem)
            .map_err(|e| TidewayError::internal(format!("Invalid RSA PEM: {}", e)))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        Ok(Self {
            jwks: Arc::new(RwLock::new(JwkSet { keys: vec![] })),
            jwks_url: None,
            jwks_client: None,
            last_unknown_kid_refresh: Arc::new(Mutex::new(None)),
            unknown_kid_refresh_cooldown: std::time::Duration::from_secs(30),
            decoding_key: Some(decoding_key),
            validation,
            issuer_configured: false,
            audience_configured: false,
            warning_logged: Arc::new(OnceLock::new()),
            _claims: std::marker::PhantomData,
        })
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
    pub fn with_unknown_kid_refresh_cooldown(mut self, cooldown: std::time::Duration) -> Self {
        self.unknown_kid_refresh_cooldown = cooldown;
        self
    }

    /// Refresh the JWKS (useful for key rotation)
    pub async fn refresh_jwks(&self) -> Result<()> {
        if let (Some(url), Some(client)) = (&self.jwks_url, &self.jwks_client) {
            let new_jwks = client.fetch(url).await?;
            let mut jwks = self.jwks.write().await;
            *jwks = new_jwks;
        }
        Ok(())
    }

    /// Verify and decode a JWT token
    ///
    /// # Security Warning
    ///
    /// If issuer or audience validation is not configured, a warning will be logged once.
    /// For production use, always configure both using [`set_issuer`] and [`set_audience`].
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

        let mut jwk = self.jwks.read().await.find_by_kid(kid).cloned();
        if jwk.is_none() && self.jwks_url.is_some() {
            let mut last_refresh = self.last_unknown_kid_refresh.lock().await;
            jwk = self.jwks.read().await.find_by_kid(kid).cloned();
            let refresh_allowed =
                last_refresh.is_none_or(|last| last.elapsed() >= self.unknown_kid_refresh_cooldown);
            if jwk.is_none() && refresh_allowed {
                *last_refresh = Some(std::time::Instant::now());
                self.refresh_jwks().await.map_err(|error| {
                    tracing::warn!(error = %error, "JWKS refresh failed for unknown key ID");
                    TidewayError::unauthorized("Token key is not available")
                })?;
                jwk = self.jwks.read().await.find_by_kid(kid).cloned();
            }
        }
        let jwk = jwk.ok_or_else(|| {
            TidewayError::unauthorized(format!("Key '{}' not found in JWKS", kid))
        })?;

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| TidewayError::internal(format!("Failed to create decoding key: {}", e)))?;

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
}
