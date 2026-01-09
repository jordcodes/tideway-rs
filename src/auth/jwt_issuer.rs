//! JWT token issuance.
//!
//! Provides JWT token generation for access and refresh tokens with support
//! for custom claims and token rotation.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::auth::{JwtIssuer, JwtIssuerConfig, TokenSubject};
//!
//! let issuer = JwtIssuer::new(
//!     JwtIssuerConfig::with_secret("your-secret-key", "my-app")
//! )?;
//!
//! let subject = TokenSubject::new("user-123")
//!     .with_email("user@example.com")
//!     .with_name("John Doe");
//!
//! let tokens = issuer.issue(subject, false)?;
//! println!("Access token: {}", tokens.access_token);
//! ```

use crate::error::{Result, TidewayError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for JWT token issuance.
#[derive(Clone)]
pub struct JwtIssuerConfig {
    /// Secret key for HS256 or private key for RS256
    secret: SecretKey,
    /// Token issuer (iss claim)
    pub issuer: String,
    /// Token audience (aud claim)
    pub audience: Option<String>,
    /// Key ID for key rotation (kid header)
    pub key_id: Option<String>,
    /// Access token expiry (default: 15 minutes)
    pub access_token_ttl: Duration,
    /// Refresh token expiry (default: 7 days)
    pub refresh_token_ttl: Duration,
    /// Extended refresh token expiry for "remember me" (default: 30 days)
    pub remember_me_ttl: Duration,
    /// Algorithm to use
    algorithm: Algorithm,
}

#[derive(Clone)]
enum SecretKey {
    Symmetric(Vec<u8>),
    Rsa { private_pem: Vec<u8> },
}

impl JwtIssuerConfig {
    /// Create config with HS256 symmetric key.
    pub fn with_secret(secret: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self {
            secret: SecretKey::Symmetric(secret.into().into_bytes()),
            issuer: issuer.into(),
            audience: None,
            key_id: None,
            access_token_ttl: Duration::from_secs(15 * 60), // 15 min
            refresh_token_ttl: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            remember_me_ttl: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            algorithm: Algorithm::HS256,
        }
    }

    /// Create config with RS256 private key (PEM format).
    pub fn with_rsa_private_key(
        private_pem: impl Into<Vec<u8>>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            secret: SecretKey::Rsa {
                private_pem: private_pem.into(),
            },
            issuer: issuer.into(),
            audience: None,
            key_id: None,
            access_token_ttl: Duration::from_secs(15 * 60),
            refresh_token_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            remember_me_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            algorithm: Algorithm::RS256,
        }
    }

    /// Set the token audience.
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = Some(aud.into());
        self
    }

    /// Set the key ID (kid) for key rotation support.
    ///
    /// The key ID is included in the JWT header and helps identify which
    /// key was used to sign the token. This is useful when rotating keys.
    pub fn key_id(mut self, kid: impl Into<String>) -> Self {
        self.key_id = Some(kid.into());
        self
    }

    /// Set access token TTL.
    pub fn access_token_ttl(mut self, ttl: Duration) -> Self {
        self.access_token_ttl = ttl;
        self
    }

    /// Set refresh token TTL.
    pub fn refresh_token_ttl(mut self, ttl: Duration) -> Self {
        self.refresh_token_ttl = ttl;
        self
    }

    /// Set "remember me" refresh token TTL.
    pub fn remember_me_ttl(mut self, ttl: Duration) -> Self {
        self.remember_me_ttl = ttl;
        self
    }
}

/// Standard JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time (unix timestamp)
    pub exp: u64,
    /// Issued at (unix timestamp)
    pub iat: u64,
    /// Not before (unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// JWT ID (unique identifier)
    pub jti: String,
}

/// Token type for distinguishing access vs refresh tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Access token (short-lived, used for API access)
    Access,
    /// Refresh token (long-lived, used to get new access tokens)
    Refresh,
}

/// Claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims<T = ()>
where
    T: Serialize,
{
    /// Standard JWT claims
    #[serde(flatten)]
    pub standard: StandardClaims,
    /// Token type
    pub token_type: TokenType,
    /// User's email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// User's name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Custom claims (app-specific)
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub custom: Option<T>,
}

/// Claims for refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// Standard JWT claims
    #[serde(flatten)]
    pub standard: StandardClaims,
    /// Token type
    pub token_type: TokenType,
    /// Token family ID (for refresh token rotation detection)
    pub family: String,
    /// Generation in this family (increments on each refresh)
    pub generation: u32,
}

/// Issued token pair.
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    /// Access token (short-lived)
    pub access_token: String,
    /// Refresh token (long-lived)
    pub refresh_token: String,
    /// Access token expiry in seconds
    pub expires_in: u64,
    /// Token type (always "Bearer")
    pub token_type: &'static str,
    /// Token family ID (for refresh token rotation tracking)
    #[serde(skip)]
    pub family: String,
}

/// User info needed for token issuance.
pub struct TokenSubject<'a, T = ()>
where
    T: Serialize,
{
    /// User ID (becomes sub claim)
    pub user_id: &'a str,
    /// User email (optional, included in access token)
    pub email: Option<&'a str>,
    /// User name (optional, included in access token)
    pub name: Option<&'a str>,
    /// Custom claims to include
    pub custom: Option<T>,
}

impl<'a> TokenSubject<'a, ()> {
    /// Create a new token subject with a user ID.
    pub fn new(user_id: &'a str) -> Self {
        Self {
            user_id,
            email: None,
            name: None,
            custom: None,
        }
    }
}

impl<'a, T: Serialize> TokenSubject<'a, T> {
    /// Set the user's email.
    pub fn with_email(mut self, email: &'a str) -> Self {
        self.email = Some(email);
        self
    }

    /// Set the user's name.
    pub fn with_name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }

    /// Add custom claims to the token.
    pub fn with_custom<U: Serialize>(self, custom: U) -> TokenSubject<'a, U> {
        TokenSubject {
            user_id: self.user_id,
            email: self.email,
            name: self.name,
            custom: Some(custom),
        }
    }
}

/// Issues and manages JWT tokens.
#[derive(Clone)]
pub struct JwtIssuer {
    config: JwtIssuerConfig,
    encoding_key: EncodingKey,
}

impl JwtIssuer {
    /// Create a new JWT issuer with the given configuration.
    pub fn new(config: JwtIssuerConfig) -> Result<Self> {
        let encoding_key = match &config.secret {
            SecretKey::Symmetric(secret) => EncodingKey::from_secret(secret),
            SecretKey::Rsa { private_pem } => {
                EncodingKey::from_rsa_pem(private_pem).map_err(|e| {
                    TidewayError::Internal(format!("Invalid RSA private key: {}", e))
                })?
            }
        };

        Ok(Self {
            config,
            encoding_key,
        })
    }

    /// Build a JWT header with the configured algorithm and optional key ID.
    fn build_header(&self) -> Header {
        let mut header = Header::new(self.config.algorithm);
        if let Some(ref kid) = self.config.key_id {
            header.kid = Some(kid.clone());
        }
        header
    }

    /// Issue a token pair (access + refresh).
    pub fn issue<T: Serialize>(
        &self,
        subject: TokenSubject<'_, T>,
        remember_me: bool,
    ) -> Result<TokenPair> {
        let now = current_timestamp();
        let jti_access = generate_jti();
        let jti_refresh = generate_jti();
        let family = generate_token_family();

        // Access token
        let access_claims = AccessTokenClaims {
            standard: StandardClaims {
                sub: subject.user_id.to_string(),
                iss: self.config.issuer.clone(),
                aud: self.config.audience.clone(),
                exp: now + self.config.access_token_ttl.as_secs(),
                iat: now,
                nbf: Some(now),
                jti: jti_access,
            },
            token_type: TokenType::Access,
            email: subject.email.map(String::from),
            name: subject.name.map(String::from),
            custom: subject.custom,
        };

        // Refresh token
        let refresh_ttl = if remember_me {
            self.config.remember_me_ttl
        } else {
            self.config.refresh_token_ttl
        };

        let refresh_claims = RefreshTokenClaims {
            standard: StandardClaims {
                sub: subject.user_id.to_string(),
                iss: self.config.issuer.clone(),
                aud: self.config.audience.clone(),
                exp: now + refresh_ttl.as_secs(),
                iat: now,
                nbf: Some(now),
                jti: jti_refresh,
            },
            token_type: TokenType::Refresh,
            family: family.clone(),
            generation: 0,
        };

        let header = self.build_header();

        let access_token = encode(&header, &access_claims, &self.encoding_key)
            .map_err(|e| TidewayError::Internal(format!("Failed to encode access token: {}", e)))?;

        let refresh_token = encode(&header, &refresh_claims, &self.encoding_key)
            .map_err(|e| TidewayError::Internal(format!("Failed to encode refresh token: {}", e)))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.config.access_token_ttl.as_secs(),
            token_type: "Bearer",
            family,
        })
    }

    /// Issue only an access token (for token refresh flow).
    pub fn issue_access_token<T: Serialize>(
        &self,
        subject: TokenSubject<'_, T>,
    ) -> Result<(String, u64)> {
        let now = current_timestamp();
        let jti = generate_jti();

        let claims = AccessTokenClaims {
            standard: StandardClaims {
                sub: subject.user_id.to_string(),
                iss: self.config.issuer.clone(),
                aud: self.config.audience.clone(),
                exp: now + self.config.access_token_ttl.as_secs(),
                iat: now,
                nbf: Some(now),
                jti,
            },
            token_type: TokenType::Access,
            email: subject.email.map(String::from),
            name: subject.name.map(String::from),
            custom: subject.custom,
        };

        let header = self.build_header();

        let token = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| TidewayError::Internal(format!("Failed to encode access token: {}", e)))?;

        Ok((token, self.config.access_token_ttl.as_secs()))
    }

    /// Issue a rotated refresh token (increment generation).
    pub fn rotate_refresh_token(&self, old_claims: &RefreshTokenClaims) -> Result<String> {
        let now = current_timestamp();
        let jti = generate_jti();

        // Calculate remaining TTL from original token
        let remaining = old_claims.standard.exp.saturating_sub(now);
        let new_exp = now + remaining;

        let claims = RefreshTokenClaims {
            standard: StandardClaims {
                sub: old_claims.standard.sub.clone(),
                iss: self.config.issuer.clone(),
                aud: self.config.audience.clone(),
                exp: new_exp,
                iat: now,
                nbf: Some(now),
                jti,
            },
            token_type: TokenType::Refresh,
            family: old_claims.family.clone(),
            generation: old_claims.generation + 1,
        };

        let header = self.build_header();

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| TidewayError::Internal(format!("Failed to encode refresh token: {}", e)))
    }

    /// Get the issuer string.
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Get the audience string.
    pub fn audience(&self) -> Option<&str> {
        self.config.audience.as_deref()
    }

    /// Get the algorithm used for signing.
    pub fn algorithm(&self) -> Algorithm {
        self.config.algorithm
    }

    /// Get the key ID (if set).
    pub fn key_id(&self) -> Option<&str> {
        self.config.key_id.as_deref()
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_jti() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_token_family() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    fn test_issuer() -> JwtIssuer {
        JwtIssuer::new(JwtIssuerConfig::with_secret(
            "test-secret-key-32-bytes-long!!",
            "test-app",
        ))
        .unwrap()
    }

    #[test]
    fn test_issue_token_pair() {
        let issuer = test_issuer();
        let subject = TokenSubject::new("user-123")
            .with_email("test@example.com")
            .with_name("Test User");

        let pair = issuer.issue(subject, false).unwrap();

        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.token_type, "Bearer");
        assert!(pair.expires_in > 0);
    }

    #[test]
    fn test_access_token_claims() {
        let issuer = test_issuer();
        let subject = TokenSubject::new("user-123").with_email("test@example.com");

        let pair = issuer.issue(subject, false).unwrap();

        // Decode and verify claims
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["test-app"]);
        validation.set_required_spec_claims(&["exp", "iat", "sub"]);

        let decoded = decode::<AccessTokenClaims>(
            &pair.access_token,
            &DecodingKey::from_secret(b"test-secret-key-32-bytes-long!!"),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.standard.sub, "user-123");
        assert_eq!(decoded.claims.email, Some("test@example.com".to_string()));
        assert_eq!(decoded.claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_refresh_token_rotation() {
        let issuer = test_issuer();
        let subject = TokenSubject::new("user-123");

        let pair = issuer.issue(subject, false).unwrap();

        // Decode refresh token
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["test-app"]);

        let decoded = decode::<RefreshTokenClaims>(
            &pair.refresh_token,
            &DecodingKey::from_secret(b"test-secret-key-32-bytes-long!!"),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.generation, 0);

        // Rotate
        let rotated = issuer.rotate_refresh_token(&decoded.claims).unwrap();

        let decoded_rotated = decode::<RefreshTokenClaims>(
            &rotated,
            &DecodingKey::from_secret(b"test-secret-key-32-bytes-long!!"),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded_rotated.claims.generation, 1);
        assert_eq!(decoded_rotated.claims.family, decoded.claims.family);
    }

    #[test]
    fn test_custom_claims() {
        #[derive(Serialize, Deserialize)]
        struct CustomClaims {
            org_id: String,
            role: String,
        }

        let issuer = test_issuer();
        let subject = TokenSubject::new("user-123").with_custom(CustomClaims {
            org_id: "org-456".to_string(),
            role: "admin".to_string(),
        });

        let pair = issuer.issue(subject, false).unwrap();

        // Decode with custom claims
        #[derive(Deserialize)]
        struct FullClaims {
            sub: String,
            org_id: String,
            role: String,
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["test-app"]);

        let decoded = decode::<FullClaims>(
            &pair.access_token,
            &DecodingKey::from_secret(b"test-secret-key-32-bytes-long!!"),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.sub, "user-123");
        assert_eq!(decoded.claims.org_id, "org-456");
        assert_eq!(decoded.claims.role, "admin");
    }

    #[test]
    fn test_remember_me_extends_refresh() {
        let issuer = test_issuer();
        let subject = TokenSubject::new("user-123");

        let normal = issuer.issue(subject, false).unwrap();
        let subject = TokenSubject::new("user-123");
        let remembered = issuer.issue(subject, true).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["test-app"]);

        let normal_claims = decode::<RefreshTokenClaims>(
            &normal.refresh_token,
            &DecodingKey::from_secret(b"test-secret-key-32-bytes-long!!"),
            &validation,
        )
        .unwrap();

        let remembered_claims = decode::<RefreshTokenClaims>(
            &remembered.refresh_token,
            &DecodingKey::from_secret(b"test-secret-key-32-bytes-long!!"),
            &validation,
        )
        .unwrap();

        // Remember me should have longer expiry
        assert!(remembered_claims.claims.standard.exp > normal_claims.claims.standard.exp);
    }
}
