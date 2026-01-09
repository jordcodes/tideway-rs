//! Refresh token storage trait.

use crate::error::Result;
use async_trait::async_trait;

/// Trait for tracking refresh token families.
///
/// This is used for refresh token rotation and detecting token reuse attacks.
/// When a refresh token is used, the generation is incremented. If an old
/// generation token is presented, it indicates the token was stolen and the
/// entire family should be revoked.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::storage::RefreshTokenStore;
/// use async_trait::async_trait;
///
/// struct RedisTokenStore {
///     client: redis::Client,
/// }
///
/// #[async_trait]
/// impl RefreshTokenStore for RedisTokenStore {
///     async fn is_family_revoked(&self, family: &str) -> Result<bool> {
///         let key = format!("token_family:{}:revoked", family);
///         Ok(self.client.exists(&key).await?)
///     }
///
///     // ... implement other methods
/// }
/// ```
#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    /// Check if a token family has been revoked.
    async fn is_family_revoked(&self, family: &str) -> Result<bool>;

    /// Get the last valid generation for a token family.
    ///
    /// Returns `None` if the family doesn't exist yet.
    async fn get_family_generation(&self, family: &str) -> Result<Option<u32>>;

    /// Set the current generation for a token family.
    async fn set_family_generation(&self, family: &str, generation: u32) -> Result<()>;

    /// Revoke an entire token family.
    ///
    /// This should be called when token reuse is detected to invalidate
    /// all tokens in the family (both the attacker's and legitimate user's).
    async fn revoke_family(&self, family: &str) -> Result<()>;

    /// Revoke all token families for a user.
    ///
    /// This should be called on password change, account compromise, or
    /// explicit logout-all-devices request.
    async fn revoke_all_for_user(&self, user_id: &str) -> Result<()>;

    /// Associate a token family with a user (for revoke_all_for_user).
    async fn associate_family_with_user(&self, family: &str, user_id: &str) -> Result<()>;
}

/// Trait for temporary MFA token storage.
///
/// MFA tokens are short-lived tokens issued after password verification
/// but before MFA verification. They allow the user to complete MFA
/// without re-entering their password.
#[async_trait]
pub trait MfaTokenStore: Send + Sync {
    /// Store an MFA token with the associated user ID.
    ///
    /// The token should expire after a short time (e.g., 5 minutes).
    async fn store(&self, token: &str, user_id: &str, ttl: std::time::Duration) -> Result<()>;

    /// Consume an MFA token, returning the user ID if valid.
    ///
    /// This should delete the token after retrieval (one-time use).
    async fn consume(&self, token: &str) -> Result<Option<String>>;
}

/// Simple in-memory implementation for testing.
#[cfg(any(test, feature = "test-auth-bypass"))]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;
    use std::time::{Duration, Instant};

    /// In-memory refresh token store for testing.
    #[derive(Default)]
    pub struct InMemoryRefreshTokenStore {
        families: RwLock<HashMap<String, FamilyState>>,
        user_families: RwLock<HashMap<String, Vec<String>>>,
    }

    struct FamilyState {
        generation: u32,
        revoked: bool,
    }

    impl InMemoryRefreshTokenStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl RefreshTokenStore for InMemoryRefreshTokenStore {
        async fn is_family_revoked(&self, family: &str) -> Result<bool> {
            let families = self.families.read().unwrap();
            Ok(families.get(family).map(|s| s.revoked).unwrap_or(false))
        }

        async fn get_family_generation(&self, family: &str) -> Result<Option<u32>> {
            let families = self.families.read().unwrap();
            Ok(families.get(family).map(|s| s.generation))
        }

        async fn set_family_generation(&self, family: &str, generation: u32) -> Result<()> {
            let mut families = self.families.write().unwrap();
            families.insert(
                family.to_string(),
                FamilyState {
                    generation,
                    revoked: false,
                },
            );
            Ok(())
        }

        async fn revoke_family(&self, family: &str) -> Result<()> {
            let mut families = self.families.write().unwrap();
            if let Some(state) = families.get_mut(family) {
                state.revoked = true;
            }
            Ok(())
        }

        async fn revoke_all_for_user(&self, user_id: &str) -> Result<()> {
            let user_families = self.user_families.read().unwrap();
            if let Some(families_list) = user_families.get(user_id) {
                let mut families = self.families.write().unwrap();
                for family in families_list {
                    if let Some(state) = families.get_mut(family) {
                        state.revoked = true;
                    }
                }
            }
            Ok(())
        }

        async fn associate_family_with_user(&self, family: &str, user_id: &str) -> Result<()> {
            let mut user_families = self.user_families.write().unwrap();
            user_families
                .entry(user_id.to_string())
                .or_default()
                .push(family.to_string());
            Ok(())
        }
    }

    /// In-memory MFA token store for testing.
    #[derive(Default)]
    pub struct InMemoryMfaTokenStore {
        tokens: RwLock<HashMap<String, (String, Instant)>>,
    }

    impl InMemoryMfaTokenStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl MfaTokenStore for InMemoryMfaTokenStore {
        async fn store(&self, token: &str, user_id: &str, ttl: Duration) -> Result<()> {
            let mut tokens = self.tokens.write().unwrap();
            tokens.insert(token.to_string(), (user_id.to_string(), Instant::now() + ttl));
            Ok(())
        }

        async fn consume(&self, token: &str) -> Result<Option<String>> {
            let mut tokens = self.tokens.write().unwrap();
            if let Some((user_id, expires)) = tokens.remove(token) {
                if Instant::now() < expires {
                    return Ok(Some(user_id));
                }
            }
            Ok(None)
        }
    }
}
