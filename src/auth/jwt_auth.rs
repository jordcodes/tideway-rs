//! Paired JWT issuance and verification configuration.
//!
//! [`JwtAuth`] keeps signing and validation policy together so an application cannot
//! accidentally issue tokens with one issuer or audience and verify them with another.

use std::{sync::Arc, time::Duration};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::de::DeserializeOwned;

use crate::{Result, TidewayError};

use super::{JwtIssuer, JwtIssuerConfig, JwtVerifier};

#[derive(Clone)]
enum VerificationKey {
    Hs256(Vec<u8>),
    Rs256(Vec<u8>),
}

/// Configuration that produces a compatible [`JwtIssuer`] and [`JwtVerifier`].
#[derive(Clone)]
pub struct JwtAuthConfig {
    issuer: JwtIssuerConfig,
    verification_key: VerificationKey,
}

impl JwtAuthConfig {
    /// Configure HS256 issuance and verification from one secret.
    pub fn with_secure_secret(
        secret: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self> {
        let secret = secret.into();
        Ok(Self {
            issuer: JwtIssuerConfig::with_secure_secret(secret.clone(), issuer)?,
            verification_key: VerificationKey::Hs256(secret.into_bytes()),
        })
    }

    /// Configure RS256 with separate private signing and public verification keys.
    pub fn with_rsa_key_pair(
        private_pem: impl AsRef<[u8]>,
        public_pem: impl AsRef<[u8]>,
        issuer: impl Into<String>,
    ) -> Result<Self> {
        let private_pem = private_pem.as_ref().to_vec();
        let public_pem = public_pem.as_ref().to_vec();
        validate_rsa_key_pair(&private_pem, &public_pem)?;
        Ok(Self {
            issuer: JwtIssuerConfig::with_rsa_private_key(private_pem, issuer),
            verification_key: VerificationKey::Rs256(public_pem),
        })
    }

    /// Set the required token audience shared by issuance and verification.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.issuer = self.issuer.audience(audience);
        self
    }

    /// Set the key ID included in issued token headers.
    #[must_use]
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.issuer = self.issuer.key_id(key_id);
        self
    }

    /// Set the access-token lifetime.
    #[must_use]
    pub fn access_token_ttl(mut self, ttl: Duration) -> Self {
        self.issuer = self.issuer.access_token_ttl(ttl);
        self
    }

    /// Set the refresh-token lifetime.
    #[must_use]
    pub fn refresh_token_ttl(mut self, ttl: Duration) -> Self {
        self.issuer = self.issuer.refresh_token_ttl(ttl);
        self
    }

    /// Set the extended refresh-token lifetime used by "remember me".
    #[must_use]
    pub fn remember_me_ttl(mut self, ttl: Duration) -> Self {
        self.issuer = self.issuer.remember_me_ttl(ttl);
        self
    }
}

fn validate_rsa_key_pair(private_pem: &[u8], public_pem: &[u8]) -> Result<()> {
    let encoding_key = EncodingKey::from_rsa_pem(private_pem)
        .map_err(|error| TidewayError::internal(format!("Invalid RSA private PEM: {error}")))?;
    let decoding_key = DecodingKey::from_rsa_pem(public_pem)
        .map_err(|error| TidewayError::internal(format!("Invalid RSA public PEM: {error}")))?;
    let token = encode(
        &Header::new(Algorithm::RS256),
        &serde_json::json!({ "tideway_key_pair_check": true }),
        &encoding_key,
    )
    .map_err(|error| TidewayError::internal(format!("Invalid RSA private key: {error}")))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    decode::<serde_json::Value>(&token, &decoding_key, &validation).map_err(|_| {
        TidewayError::internal("RSA private and public keys do not form a matching pair")
    })?;
    Ok(())
}

/// A JWT issuer paired with reusable verifier construction from the same policy.
#[derive(Clone)]
pub struct JwtAuth {
    issuer: Arc<JwtIssuer>,
    verification_key: VerificationKey,
    issuer_id: String,
    audience: String,
}

impl JwtAuth {
    /// Build a paired JWT configuration.
    ///
    /// An audience is required because accepting a signed token without checking which
    /// service it targets weakens isolation when signing infrastructure is shared.
    pub fn new(config: JwtAuthConfig) -> Result<Self> {
        let issuer_id = config.issuer.issuer.clone();
        let audience = config.issuer.audience.clone().ok_or_else(|| {
            TidewayError::internal("JwtAuthConfig requires an audience before startup")
        })?;
        let issuer = Arc::new(JwtIssuer::new(config.issuer)?);
        Ok(Self {
            issuer,
            verification_key: config.verification_key,
            issuer_id,
            audience,
        })
    }

    /// Return the configured issuer for token flows and application modules.
    pub fn issuer(&self) -> Arc<JwtIssuer> {
        Arc::clone(&self.issuer)
    }

    /// Build a verifier that inherits this pair's algorithm, key, issuer, and audience.
    pub fn verifier<C>(&self) -> Result<JwtVerifier<C>>
    where
        C: DeserializeOwned + Clone,
    {
        let verifier = match &self.verification_key {
            VerificationKey::Hs256(secret) => JwtVerifier::from_secret_checked(secret)?,
            VerificationKey::Rs256(public_pem) => JwtVerifier::from_rsa_pem(public_pem)?,
        };
        Ok(verifier
            .with_issuer(&self.issuer_id)
            .with_audience(&self.audience))
    }

    /// Return the stable issuer identifier.
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Return the stable audience identifier.
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    };

    use super::*;
    use crate::auth::{AccessTokenClaims, TokenSubject};

    const SECRET: &str = "test-only-secret-with-at-least-32-bytes";

    fn rsa_test_keys() -> &'static (Vec<u8>, Vec<u8>, Vec<u8>) {
        static KEYS: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYS.get_or_init(|| {
            let mut rng = rand::thread_rng();
            let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
            let unrelated =
                RsaPrivateKey::new(&mut rng, 2048).expect("generate unrelated test RSA key");
            let private_pem = private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode test private key")
                .as_bytes()
                .to_vec();
            let public_pem = private
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("encode test public key")
                .into_bytes();
            let unrelated_public_pem = unrelated
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("encode unrelated test public key")
                .into_bytes();
            (private_pem, public_pem, unrelated_public_pem)
        })
    }

    #[tokio::test]
    async fn issued_access_token_is_accepted_by_paired_verifier() {
        let jwt = JwtAuth::new(
            JwtAuthConfig::with_secure_secret(SECRET, "stable-api")
                .expect("valid auth config")
                .audience("stable-clients"),
        )
        .expect("valid paired auth");

        let token = jwt
            .issuer()
            .issue(TokenSubject::new("user-123"), false)
            .expect("issue token")
            .access_token;
        let verified = jwt
            .verifier::<AccessTokenClaims>()
            .expect("paired verifier")
            .verify_access_token(&token)
            .await
            .expect("verify token");

        assert_eq!(verified.claims.standard.iss, "stable-api");
        assert_eq!(
            verified.claims.standard.aud.as_deref(),
            Some("stable-clients")
        );
    }

    #[tokio::test]
    async fn issued_rsa_token_is_accepted_by_paired_verifier() {
        let (private_key, public_key, _) = rsa_test_keys();
        let jwt = JwtAuth::new(
            JwtAuthConfig::with_rsa_key_pair(private_key, public_key, "stable-api")
                .expect("matching RSA key pair")
                .audience("stable-clients"),
        )
        .expect("valid paired auth");

        let token = jwt
            .issuer()
            .issue(TokenSubject::new("user-123"), false)
            .expect("issue token")
            .access_token;
        jwt.verifier::<AccessTokenClaims>()
            .expect("paired verifier")
            .verify_access_token(&token)
            .await
            .expect("verify token");
    }

    #[test]
    fn audience_is_required() {
        let config = JwtAuthConfig::with_secure_secret(SECRET, "stable-api").unwrap();
        let error = JwtAuth::new(config).err().expect("missing audience error");
        assert!(error.to_string().contains("requires an audience"));
    }

    #[test]
    fn rsa_pair_rejects_invalid_public_key_at_configuration_time() {
        let (private_key, _, _) = rsa_test_keys();
        let error =
            JwtAuthConfig::with_rsa_key_pair(private_key, b"not a public key", "stable-api")
                .err()
                .expect("invalid public key error");
        assert!(error.to_string().contains("Invalid RSA public PEM"));
    }

    #[test]
    fn rsa_pair_rejects_unrelated_valid_keys_at_configuration_time() {
        let (private_key, _, unrelated_public_key) = rsa_test_keys();
        let error =
            JwtAuthConfig::with_rsa_key_pair(private_key, unrelated_public_key, "stable-api")
                .err()
                .expect("mismatched key error");
        assert!(error.to_string().contains("do not form a matching pair"));
    }
}
