use crate::error::Result;
use crate::traits::session::{SessionData, SessionStore};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

struct SessionState {
    sessions: HashMap<String, SessionData>,
    last_cleanup: Instant,
}

impl SessionState {
    fn cleanup_expired(&mut self) -> usize {
        let initial_len = self.sessions.len();
        self.sessions.retain(|_, session| !session.is_expired());
        // Release excess bucket storage after traffic spikes without resizing
        // the map on every small change in the number of active sessions.
        if self.sessions.capacity() > self.sessions.len().saturating_mul(4).max(64) {
            self.sessions
                .shrink_to(self.sessions.len().saturating_mul(2));
        }
        self.last_cleanup = Instant::now();
        initial_len - self.sessions.len()
    }
}

/// In-memory session store implementation
///
/// Stores sessions in a HashMap. Suitable for development and testing,
/// but not for production (sessions are lost on restart and not shared
/// across instances).
///
/// Saves sweep expired sessions at most once per minute, including sessions
/// that are never loaded again. Idle stores can be reclaimed explicitly with
/// [`SessionStore::cleanup_expired`]. Each session's `expires_at` controls expiry.
#[derive(Clone)]
pub struct InMemorySessionStore {
    state: Arc<RwLock<SessionState>>,
    #[allow(dead_code)] // Stored for potential future use when creating sessions
    default_ttl: Duration,
}

impl InMemorySessionStore {
    /// Create a new in-memory session store
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState {
                sessions: HashMap::new(),
                last_cleanup: Instant::now(),
            })),
            default_ttl,
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>> {
        let state = self.state.read().await;

        if let Some(session) = state.sessions.get(session_id) {
            if session.is_expired() {
                drop(state);
                let mut state = self.state.write().await;
                // A concurrent save may have renewed it while acquiring the lock.
                if let Some(session) = state.sessions.get(session_id) {
                    if !session.is_expired() {
                        return Ok(Some(session.clone()));
                    }
                    state.sessions.remove(session_id);
                }
                return Ok(None);
            }
            Ok(Some(session.clone()))
        } else {
            Ok(None)
        }
    }

    async fn save(&self, session_id: &str, data: SessionData) -> Result<()> {
        let mut state = self.state.write().await;
        if state.last_cleanup.elapsed() >= CLEANUP_INTERVAL {
            state.cleanup_expired();
        }
        if data.is_expired() {
            state.sessions.remove(session_id);
        } else {
            state.sessions.insert(session_id.to_string(), data);
        }
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<()> {
        let mut state = self.state.write().await;
        state.sessions.remove(session_id);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        Ok(self.state.write().await.cleanup_expired())
    }

    fn is_healthy(&self) -> bool {
        true // In-memory store is always healthy
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600 * 24)) // 24 hours default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_load_save() {
        let store = InMemorySessionStore::new(Duration::from_secs(3600));
        let session_id = "test-session-1";
        let mut session_data = SessionData::new(Duration::from_secs(3600));
        session_data.set("user_id".to_string(), "123".to_string());

        store.save(session_id, session_data.clone()).await.unwrap();

        let loaded = store.load(session_id).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().get("user_id"), Some(&"123".to_string()));
    }

    #[tokio::test]
    async fn test_delete() {
        let store = InMemorySessionStore::new(Duration::from_secs(3600));
        let session_id = "test-session-1";
        let session_data = SessionData::new(Duration::from_secs(3600));

        store.save(session_id, session_data).await.unwrap();
        store.delete(session_id).await.unwrap();

        let loaded = store.load(session_id).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_expired_saves_do_not_accumulate() {
        let store = InMemorySessionStore::default();
        for i in 0..100 {
            let mut data = SessionData::new(Duration::from_secs(3600));
            data.expires_at = std::time::SystemTime::UNIX_EPOCH;
            store.save(&format!("expired-{i}"), data).await.unwrap();
        }
        assert!(store.state.read().await.sessions.is_empty());
    }

    #[tokio::test]
    async fn test_save_cleans_abandoned_sessions_during_churn() {
        let store = InMemorySessionStore::default();
        let writer = store.clone();
        let mut active = SessionData::new(Duration::from_secs(3600));
        active.set("user_id".into(), "123".into());
        store.save("active", active).await.unwrap();

        for batch in 0..20 {
            for i in 0..100 {
                writer
                    .save(
                        &format!("abandoned-{batch}-{i}"),
                        SessionData::new(Duration::from_secs(3600)),
                    )
                    .await
                    .unwrap();
            }
            // Simulate expiry and the sweep deadline without sleeping. These
            // abandoned IDs are deliberately never loaded or explicitly deleted.
            {
                let mut state = store.state.write().await;
                for (id, data) in &mut state.sessions {
                    if id.starts_with("abandoned-") {
                        data.expires_at = std::time::SystemTime::UNIX_EPOCH;
                    }
                }
                state.last_cleanup = Instant::now() - CLEANUP_INTERVAL;
            }
            writer
                .save("next", SessionData::new(Duration::from_secs(3600)))
                .await
                .unwrap();

            let state = store.state.read().await;
            assert_eq!(state.sessions.len(), 2);
            assert!(state.sessions.capacity() <= 64);
            assert_eq!(state.sessions["active"].get("user_id"), Some(&"123".into()));
        }
    }

    #[tokio::test]
    async fn test_expired_save_replaces_existing_session() {
        let store = InMemorySessionStore::default();
        store
            .save("session", SessionData::new(Duration::from_secs(3600)))
            .await
            .unwrap();
        let mut expired = SessionData::new(Duration::from_secs(3600));
        expired.expires_at = std::time::SystemTime::UNIX_EPOCH;
        store.save("session", expired).await.unwrap();
        assert!(store.state.read().await.sessions.is_empty());
    }

    #[tokio::test]
    async fn test_expiration() {
        let store = InMemorySessionStore::new(Duration::from_secs(1));
        let session_id = "test-session-1";
        let session_data = SessionData::new(Duration::from_millis(10));

        store.save(session_id, session_data).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        let loaded = store.load(session_id).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = InMemorySessionStore::new(Duration::from_secs(1));

        // Add expired session
        let expired_id = "expired-1";
        let expired_data = SessionData::new(Duration::from_millis(10));
        store.save(expired_id, expired_data).await.unwrap();

        // Add valid session
        let valid_id = "valid-1";
        let valid_data = SessionData::new(Duration::from_secs(3600));
        store.save(valid_id, valid_data).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        let removed = store.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);

        assert!(store.load(expired_id).await.unwrap().is_none());
        assert!(store.load(valid_id).await.unwrap().is_some());
    }
}
