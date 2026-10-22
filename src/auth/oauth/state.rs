//! Storage for in-flight OAuth authorization requests.

use crate::error::Result;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Data remembered between redirecting to the provider and handling its callback.
#[derive(Clone)]
pub struct PendingAuthorization {
    /// Provider the authorization was started for.
    pub provider: String,
    /// PKCE code verifier (secret; sent only to the token endpoint).
    pub pkce_verifier: String,
    /// OIDC nonce expected in the `id_token`.
    pub nonce: String,
    /// Validated same-origin path to send the user to after sign-in.
    pub redirect_to: Option<String>,
    /// When set, the identity is linked to this already signed-in user instead of
    /// signing in or creating an account.
    pub link_user_id: Option<String>,
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthorization")
            .field("provider", &self.provider)
            .field("pkce_verifier", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("redirect_to", &self.redirect_to)
            .field("link_user_id", &self.link_user_id)
            .finish()
    }
}

/// Stores pending authorizations keyed by a hash of the `state` parameter.
///
/// Implementations must make [`Self::consume`] single-use (delete-and-return atomically)
/// and must not return expired entries. Use a shared store such as Redis or a database
/// table when running more than one instance.
#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    /// Save a pending authorization until `expires_at`.
    async fn store(
        &self,
        state_hash: &str,
        pending: PendingAuthorization,
        expires_at: SystemTime,
    ) -> Result<()>;

    /// Remove and return a pending authorization if it exists and has not expired.
    async fn consume(&self, state_hash: &str) -> Result<Option<PendingAuthorization>>;
}

/// In-process [`OAuthStateStore`].
///
/// Suitable for tests and single-instance deployments. State is lost on restart and is
/// not shared between instances, so callbacks routed to another instance will fail.
///
/// Holds at most [`Self::MAX_ENTRIES`] pending authorizations. When full it drops expired
/// entries and then the oldest pending ones, so a flood of anonymous authorize requests cannot
/// block new sign-ins; it can only cut short sign-ins started before the flood.
#[derive(Default)]
pub struct InMemoryOAuthStateStore {
    inner: Mutex<Entries>,
}

#[derive(Default)]
struct Entries {
    by_hash: HashMap<String, (PendingAuthorization, SystemTime)>,
    /// Insertion order for eviction. May hold hashes already consumed; those are skipped.
    order: VecDeque<String>,
}

impl InMemoryOAuthStateStore {
    /// Upper bound on stored entries so unauthenticated authorize requests cannot grow
    /// memory without limit.
    pub const MAX_ENTRIES: usize = 100_000;

    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored (possibly expired) entries.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("oauth state lock poisoned")
            .by_hash
            .len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl OAuthStateStore for InMemoryOAuthStateStore {
    async fn store(
        &self,
        state_hash: &str,
        pending: PendingAuthorization,
        expires_at: SystemTime,
    ) -> Result<()> {
        let mut inner = self.inner.lock().expect("oauth state lock poisoned");
        let Entries { by_hash, order } = &mut *inner;
        if by_hash.len() >= Self::MAX_ENTRIES {
            let now = SystemTime::now();
            by_hash.retain(|_, (_, expires)| *expires > now);
            order.retain(|hash| by_hash.contains_key(hash));
        }
        while by_hash.len() >= Self::MAX_ENTRIES {
            let Some(oldest) = order.pop_front() else {
                break;
            };
            by_hash.remove(&oldest);
        }
        // Consumed hashes stay in `order` until skipped; compact before it grows unbounded.
        if order.len() >= 2 * Self::MAX_ENTRIES {
            order.retain(|hash| by_hash.contains_key(hash));
        }
        by_hash.insert(state_hash.to_string(), (pending, expires_at));
        order.push_back(state_hash.to_string());
        Ok(())
    }

    async fn consume(&self, state_hash: &str) -> Result<Option<PendingAuthorization>> {
        let mut inner = self.inner.lock().expect("oauth state lock poisoned");
        Ok(inner
            .by_hash
            .remove(state_hash)
            .filter(|(_, expires)| *expires > SystemTime::now())
            .map(|(pending, _)| pending))
    }
}

/// Default lifetime of a pending authorization.
pub(crate) const DEFAULT_STATE_TTL: Duration = Duration::from_secs(600);

#[cfg(test)]
mod tests {
    use super::*;

    fn pending() -> PendingAuthorization {
        PendingAuthorization {
            provider: "github".into(),
            pkce_verifier: "pkce-secret-value".into(),
            nonce: "nonce-secret-value".into(),
            redirect_to: None,
            link_user_id: None,
        }
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let store = InMemoryOAuthStateStore::new();
        store
            .store("h", pending(), SystemTime::now() + Duration::from_secs(60))
            .await
            .unwrap();
        assert!(store.consume("h").await.unwrap().is_some());
        assert!(store.consume("h").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_entries_are_not_returned() {
        let store = InMemoryOAuthStateStore::new();
        store
            .store("h", pending(), SystemTime::now() - Duration::from_secs(1))
            .await
            .unwrap();
        assert!(store.consume("h").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn full_store_evicts_oldest_instead_of_rejecting_new_sign_ins() {
        let store = InMemoryOAuthStateStore::new();
        let expires = SystemTime::now() + Duration::from_secs(600);
        for i in 0..InMemoryOAuthStateStore::MAX_ENTRIES {
            store
                .store(&format!("flood-{i}"), pending(), expires)
                .await
                .unwrap();
        }

        // Another user's sign-in still starts and completes.
        store.store("victim", pending(), expires).await.unwrap();
        assert!(store.consume("victim").await.unwrap().is_some());
        assert_eq!(store.len(), InMemoryOAuthStateStore::MAX_ENTRIES - 1);
        // The oldest flood entry made room.
        assert!(store.consume("flood-0").await.unwrap().is_none());
        assert!(store.consume("flood-1").await.unwrap().is_some());
    }

    #[test]
    fn debug_redacts_secrets() {
        let debug = format!("{:?}", pending());
        assert!(!debug.contains("pkce-secret-value"));
        assert!(!debug.contains("nonce-secret-value"));
        assert!(debug.contains("[REDACTED]"));
    }
}
