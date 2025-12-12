use crate::error::{Result, TidewayError};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

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
        let client = Client::new();
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to fetch JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(TidewayError::internal(format!(
                "JWKS endpoint returned status: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to parse JWKS: {}", e)))
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
    /// Create a verifier using JWKS (fetches keys from URL)
    ///
    /// # Security Warning
    ///
    /// After creating a verifier, you should configure issuer and audience
    /// validation using [`set_issuer`] and [`set_audience`] before use in production.
    pub async fn from_jwks_url(url: impl Into<String>, algorithm: Algorithm) -> Result<Self> {
        let url = url.into();
        let jwks = JwkSet::fetch(&url).await?;

        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;

        Ok(Self {
            jwks: Arc::new(RwLock::new(jwks)),
            jwks_url: Some(url),
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
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        Self {
            jwks: Arc::new(RwLock::new(JwkSet { keys: vec![] })),
            jwks_url: None,
            decoding_key: Some(DecodingKey::from_secret(secret)),
            validation,
            issuer_configured: false,
            audience_configured: false,
            warning_logged: Arc::new(OnceLock::new()),
            _claims: std::marker::PhantomData,
        }
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

    /// Set the expected audience claim
    ///
    /// **Strongly recommended for production use.** Without audience validation,
    /// tokens intended for other applications could be accepted.
    pub fn set_audience(&mut self, audience: impl Into<String>) {
        self.validation.set_audience(&[audience.into()]);
        self.audience_configured = true;
    }

    /// Refresh the JWKS (useful for key rotation)
    pub async fn refresh_jwks(&self) -> Result<()> {
        if let Some(url) = &self.jwks_url {
            let new_jwks = JwkSet::fetch(url).await?;
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

        let jwks = self.jwks.read().await;
        let jwk = jwks.find_by_kid(kid).ok_or_else(|| {
            TidewayError::unauthorized(format!("Key '{}' not found in JWKS", kid))
        })?;

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| TidewayError::internal(format!("Failed to create decoding key: {}", e)))?;

        decode::<C>(token, &decoding_key, &self.validation)
            .map_err(|e| TidewayError::unauthorized(format!("Invalid token: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

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

    #[tokio::test]
    async fn test_algorithm_confusion_attack_rejected() {
        // Create a verifier expecting HS256
        let secret = b"my_secret_key_for_testing_12345";
        let verifier = JwtVerifier::<TestClaims>::from_secret(secret);

        // Create a valid HS256 token
        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
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
}
