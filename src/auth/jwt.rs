use crate::error::{Result, TidewayError};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;
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
#[derive(Clone)]
pub struct JwtVerifier<C> {
    jwks: Arc<RwLock<JwkSet>>,
    jwks_url: Option<String>,
    decoding_key: Option<DecodingKey>,
    validation: Validation,
    _claims: std::marker::PhantomData<C>,
}

impl<C: DeserializeOwned + Clone> JwtVerifier<C> {
    /// Create a verifier using JWKS (fetches keys from URL)
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
            _claims: std::marker::PhantomData,
        })
    }

    /// Create a verifier using a static secret (for HS256)
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        Self {
            jwks: Arc::new(RwLock::new(JwkSet { keys: vec![] })),
            jwks_url: None,
            decoding_key: Some(DecodingKey::from_secret(secret)),
            validation,
            _claims: std::marker::PhantomData,
        }
    }

    /// Create a verifier using a static RSA public key (PEM format)
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
            _claims: std::marker::PhantomData,
        })
    }

    /// Set the expected issuer claim
    pub fn set_issuer(&mut self, issuer: impl Into<String>) {
        self.validation.set_issuer(&[issuer.into()]);
    }

    /// Set the expected audience claim
    pub fn set_audience(&mut self, audience: impl Into<String>) {
        self.validation.set_audience(&[audience.into()]);
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
    pub async fn verify(&self, token: &str) -> Result<TokenData<C>> {
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
}
