use crate::error::Result;
use crate::traits::session::{SessionData, SessionStore};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// In-memory session store implementation
///
/// Stores sessions in a HashMap. Suitable for development and testing,
/// but not for production (sessions are lost on restart and not shared
/// across instances).
#[derive(Clone)]
pub struct InMemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
    #[allow(dead_code)] // Stored for potential future use when creating sessions
    default_ttl: Duration,
}

impl InMemorySessionStore {
    /// Create a new in-memory session store
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>> {
        let sessions = self.sessions.read().await;

        if let Some(session) = sessions.get(session_id) {
            if session.is_expired() {
                drop(sessions);
                // Remove expired session
                let mut sessions = self.sessions.write().await;
                sessions.remove(session_id);
                return Ok(None);
            }
            Ok(Some(session.clone()))
        } else {
            Ok(None)
        }
    }

    async fn save(&self, session_id: &str, data: SessionData) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.to_string(), data);
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let initial_len = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        let removed = initial_len - sessions.len();
        Ok(removed)
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
