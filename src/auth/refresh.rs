//! Token refresh flow with rotation.
//!
//! Handles refreshing access tokens using refresh tokens with automatic
//! rotation and reuse detection.
//!
//! This module emits tracing events for security monitoring:
//! - `auth.token.refresh` - Successful token refresh
//! - `auth.token.reuse_detected` - Token reuse attack detected (critical)
//! - `auth.token.revoked` - Token family revoked (logout)
//! - `auth.token.revoke_all` - All user tokens revoked (security event)
//! - `auth.token.invalid` - Invalid token presented

use crate::auth::jwt_issuer::{JwtIssuer, RefreshTokenClaims, TokenPair, TokenSubject, TokenType};
use crate::auth::storage::RefreshTokenStore;
use crate::error::{Result, TidewayError};
use async_trait::async_trait;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

/// Trait for loading user data during token refresh.
#[async_trait]
pub trait UserLoader: Send + Sync {
    /// The user type.
    type User: Send + Sync;

    /// Load a user by their ID.
    ///
    /// Returns `None` if the user doesn't exist or has been disabled.
    async fn load_user(&self, user_id: &str) -> Result<Option<Self::User>>;

    /// Get the user's email (for token claims).
    fn user_email(&self, user: &Self::User) -> Option<String>;

    /// Get the user's name (for token claims).
    fn user_name(&self, user: &Self::User) -> Option<String>;
}

/// Handles token refresh with rotation and reuse detection.
///
/// # Token Rotation
///
/// Each time a refresh token is used, a new refresh token is issued with an
/// incremented generation number. The old token becomes invalid.
///
/// # Reuse Detection
///
/// If an old-generation token is presented (indicating it was stolen and used
/// by an attacker), the entire token family is revoked, invalidating both
/// the attacker's and legitimate user's tokens.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::{TokenRefreshFlow, JwtIssuer, JwtIssuerConfig};
///
/// let flow = TokenRefreshFlow::new(
///     JwtIssuer::new(JwtIssuerConfig::with_secret("secret", "my-app"))?,
///     my_token_store,
///     my_user_loader,
///     b"secret",
/// );
///
/// let new_tokens = flow.refresh(&old_refresh_token).await?;
/// ```
pub struct TokenRefreshFlow<S, L>
where
    S: RefreshTokenStore,
    L: UserLoader,
{
    issuer: JwtIssuer,
    store: S,
    user_loader: L,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl<S, L> TokenRefreshFlow<S, L>
where
    S: RefreshTokenStore,
    L: UserLoader,
{
    /// Create a new token refresh flow.
    pub fn new(issuer: JwtIssuer, store: S, user_loader: L, secret: &[u8]) -> Self {
        let mut validation = Validation::new(issuer.algorithm());
        validation.set_issuer(&[issuer.issuer()]);
        if let Some(aud) = issuer.audience() {
            validation.set_audience(&[aud]);
        }

        Self {
            decoding_key: DecodingKey::from_secret(secret),
            issuer,
            store,
            user_loader,
            validation,
        }
    }

    /// Create a new token refresh flow with RS256.
    pub fn with_rsa_public_key(
        issuer: JwtIssuer,
        store: S,
        user_loader: L,
        public_key_pem: &[u8],
    ) -> Result<Self> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer.issuer()]);
        if let Some(aud) = issuer.audience() {
            validation.set_audience(&[aud]);
        }

        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem)
            .map_err(|e| TidewayError::Internal(format!("Invalid RSA public key: {}", e)))?;

        Ok(Self {
            issuer,
            store,
            user_loader,
            decoding_key,
            validation,
        })
    }

    /// Refresh tokens using a refresh token.
    ///
    /// Returns a new token pair with a rotated refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenPair> {
        // Decode refresh token
        let claims = decode::<RefreshTokenClaims>(refresh_token, &self.decoding_key, &self.validation)
            .map_err(|e| {
                tracing::warn!(
                    target: "auth.token.invalid",
                    error = %e,
                    "Invalid refresh token presented"
                );
                TidewayError::Unauthorized(format!("Invalid refresh token: {}", e))
            })?
            .claims;

        let user_id = &claims.standard.sub;
        let family = &claims.family;

        // Verify it's a refresh token
        if claims.token_type != TokenType::Refresh {
            tracing::warn!(
                target: "auth.token.invalid",
                user_id = %user_id,
                token_type = ?claims.token_type,
                "Wrong token type used for refresh"
            );
            return Err(TidewayError::Unauthorized("Invalid token type".into()));
        }

        // Check if family is revoked
        if self.store.is_family_revoked(family).await? {
            tracing::warn!(
                target: "auth.token.invalid",
                user_id = %user_id,
                family = %family,
                "Attempted use of revoked token family"
            );
            return Err(TidewayError::Unauthorized("Token has been revoked".into()));
        }

        // Check generation (detect reuse)
        if let Some(stored_gen) = self.store.get_family_generation(family).await? {
            if claims.generation < stored_gen {
                // Token reuse detected! Revoke entire family
                tracing::error!(
                    target: "auth.token.reuse_detected",
                    user_id = %user_id,
                    family = %family,
                    presented_generation = claims.generation,
                    expected_generation = stored_gen,
                    "SECURITY: Refresh token reuse detected - possible token theft"
                );
                self.store.revoke_family(family).await?;
                return Err(TidewayError::Unauthorized("Token reuse detected".into()));
            }
        }

        // Load user (verify still exists/active)
        let user = match self.user_loader.load_user(user_id).await? {
            Some(u) => u,
            None => {
                tracing::warn!(
                    target: "auth.token.invalid",
                    user_id = %user_id,
                    family = %family,
                    "Token refresh failed: user not found or disabled"
                );
                return Err(TidewayError::Unauthorized("User not found".into()));
            }
        };

        // Update stored generation
        let new_generation = claims.generation + 1;
        self.store
            .set_family_generation(family, new_generation)
            .await?;

        // Issue new access token
        let email = self.user_loader.user_email(&user);
        let name = self.user_loader.user_name(&user);

        let mut subject = TokenSubject::new(user_id);
        if let Some(ref e) = email {
            subject = subject.with_email(e);
        }
        if let Some(ref n) = name {
            subject = subject.with_name(n);
        }

        let (access_token, expires_in) = self.issuer.issue_access_token(subject)?;

        // Rotate refresh token (keeps same family)
        let family = claims.family.clone();
        let new_refresh_token = self.issuer.rotate_refresh_token(&claims)?;

        tracing::info!(
            target: "auth.token.refresh",
            user_id = %user_id,
            family = %family,
            generation = new_generation,
            "Token refreshed successfully"
        );

        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh_token,
            expires_in,
            token_type: "Bearer",
            family,
        })
    }

    /// Revoke a specific refresh token (logout).
    pub async fn revoke(&self, refresh_token: &str) -> Result<()> {
        let claims = decode::<RefreshTokenClaims>(refresh_token, &self.decoding_key, &self.validation)
            .map_err(|e| TidewayError::Unauthorized(format!("Invalid refresh token: {}", e)))?
            .claims;

        self.store.revoke_family(&claims.family).await?;

        tracing::info!(
            target: "auth.token.revoked",
            user_id = %claims.standard.sub,
            family = %claims.family,
            "Token family revoked (logout)"
        );

        Ok(())
    }

    /// Revoke all tokens for a user (password change, security event).
    pub async fn revoke_all(&self, user_id: &str) -> Result<()> {
        self.store.revoke_all_for_user(user_id).await?;

        tracing::warn!(
            target: "auth.token.revoke_all",
            user_id = %user_id,
            "All tokens revoked for user (security event)"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt_issuer::JwtIssuerConfig;
    use crate::auth::storage::token::test::InMemoryRefreshTokenStore;

    struct TestUserLoader;

    struct TestUser {
        id: String,
        email: String,
        name: String,
    }

    #[async_trait]
    impl UserLoader for TestUserLoader {
        type User = TestUser;

        async fn load_user(&self, user_id: &str) -> Result<Option<Self::User>> {
            Ok(Some(TestUser {
                id: user_id.to_string(),
                email: "test@example.com".to_string(),
                name: "Test User".to_string(),
            }))
        }

        fn user_email(&self, user: &Self::User) -> Option<String> {
            Some(user.email.clone())
        }

        fn user_name(&self, user: &Self::User) -> Option<String> {
            Some(user.name.clone())
        }
    }

    #[tokio::test]
    async fn test_refresh_flow() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, secret);

        // Issue initial tokens
        let subject = TokenSubject::new("user-123");
        let initial = issuer.issue(subject, false).unwrap();

        // Refresh
        let refreshed = flow.refresh(&initial.refresh_token).await.unwrap();

        assert!(!refreshed.access_token.is_empty());
        assert!(!refreshed.refresh_token.is_empty());
        assert_ne!(refreshed.refresh_token, initial.refresh_token);
    }

    #[tokio::test]
    async fn test_reuse_detection() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, secret);

        // Issue initial tokens
        let subject = TokenSubject::new("user-123");
        let initial = issuer.issue(subject, false).unwrap();

        // First refresh should work
        let _refreshed = flow.refresh(&initial.refresh_token).await.unwrap();

        // Using the old token again should fail (reuse detection)
        let result = flow.refresh(&initial.refresh_token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, secret);

        // Issue tokens and store family
        let subject = TokenSubject::new("user-123");
        let initial = issuer.issue(subject, false).unwrap();

        // First refresh works (also stores the family)
        let refreshed = flow.refresh(&initial.refresh_token).await.unwrap();

        // Revoke the token
        flow.revoke(&refreshed.refresh_token).await.unwrap();

        // Now refresh should fail
        let result = flow.refresh(&refreshed.refresh_token).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        // Associate family with user
        let subject = TokenSubject::new("user-123");
        let initial = issuer.issue(subject, false).unwrap();
        store.associate_family_with_user(&initial.family, "user-123").await.unwrap();

        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, secret);

        // First refresh works
        let refreshed = flow.refresh(&initial.refresh_token).await.unwrap();

        // Revoke all for user
        flow.revoke_all("user-123").await.unwrap();

        // Now refresh should fail
        let result = flow.refresh(&refreshed.refresh_token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        let flow = TokenRefreshFlow::new(issuer, store, user_loader, secret);

        // Invalid token should fail
        let result = flow.refresh("not-a-valid-token").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_access_token_rejected_for_refresh() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, secret);

        // Issue tokens
        let subject = TokenSubject::new("user-123");
        let tokens = issuer.issue(subject, false).unwrap();

        // Using access token for refresh should fail
        let result = flow.refresh(&tokens.access_token).await;
        assert!(result.is_err());
        // Access tokens don't have the refresh claims structure, so decoding fails
    }

    #[tokio::test]
    async fn test_wrong_secret_rejected() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let wrong_secret = b"wrong-secret-key-32-bytes-long!";

        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        // Flow created with wrong secret
        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, wrong_secret);

        // Issue tokens with correct secret
        let subject = TokenSubject::new("user-123");
        let tokens = issuer.issue(subject, false).unwrap();

        // Refresh should fail due to signature mismatch
        let result = flow.refresh(&tokens.refresh_token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_chained_refresh() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let issuer = JwtIssuer::new(JwtIssuerConfig::with_secret(
            String::from_utf8_lossy(secret).to_string(),
            "test-app",
        ))
        .unwrap();

        let store = InMemoryRefreshTokenStore::new();
        let user_loader = TestUserLoader;

        let flow = TokenRefreshFlow::new(issuer.clone(), store, user_loader, secret);

        // Issue initial tokens
        let subject = TokenSubject::new("user-123");
        let initial = issuer.issue(subject, false).unwrap();

        // Chain multiple refreshes
        let refresh1 = flow.refresh(&initial.refresh_token).await.unwrap();
        let refresh2 = flow.refresh(&refresh1.refresh_token).await.unwrap();
        let refresh3 = flow.refresh(&refresh2.refresh_token).await.unwrap();

        // Each should produce a new token
        assert_ne!(initial.refresh_token, refresh1.refresh_token);
        assert_ne!(refresh1.refresh_token, refresh2.refresh_token);
        assert_ne!(refresh2.refresh_token, refresh3.refresh_token);

        // All should have same family
        assert_eq!(initial.family, refresh1.family);
        assert_eq!(refresh1.family, refresh2.family);
        assert_eq!(refresh2.family, refresh3.family);
    }
}
