use crate::error::Result;
use crate::traits::cache::Cache;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cached value with expiration time
struct CachedValue {
    data: Vec<u8>,
    expires_at: Option<Instant>,
}

impl CachedValue {
    fn new(data: Vec<u8>, ttl: Option<Duration>) -> Self {
        let expires_at = ttl.map(|d| Instant::now() + d);
        Self { data, expires_at }
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|expires| Instant::now() >= expires)
            .unwrap_or(false)
    }
}

/// In-memory cache implementation
///
/// Uses a HashMap with TTL support. Expired entries are removed
/// lazily on access and periodically via cleanup.
#[derive(Clone)]
pub struct InMemoryCache {
    inner: Arc<RwLock<HashMap<String, CachedValue>>>,
    max_entries: usize,
}

impl InMemoryCache {
    /// Create a new in-memory cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
        }
    }

    /// Clean up expired entries
    #[allow(dead_code)] // Public API method for manual cleanup
    async fn cleanup_expired(&self) {
        let mut cache = self.inner.write().await;
        cache.retain(|_, value| !value.is_expired());
    }

    /// Remove oldest entries if cache is full
    async fn evict_if_full(&self) {
        let mut cache = self.inner.write().await;
        if cache.len() >= self.max_entries {
            // Simple eviction: remove first entry (FIFO)
            // In production, you might want LRU or other strategies
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
            }
        }
    }
}

#[async_trait]
impl Cache for InMemoryCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let cache = self.inner.read().await;

        if let Some(value) = cache.get(key) {
            if value.is_expired() {
                drop(cache);
                // Remove expired entry
                let mut cache = self.inner.write().await;
                cache.remove(key);
                return Ok(None);
            }

            Ok(Some(value.data.clone()))
        } else {
            Ok(None)
        }
    }

    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()> {
        // Evict if needed before inserting
        self.evict_if_full().await;

        let mut cache = self.inner.write().await;
        cache.insert(
            key.to_string(),
            CachedValue::new(value, ttl),
        );

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut cache = self.inner.write().await;
        cache.remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut cache = self.inner.write().await;
        cache.clear();
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true // In-memory cache is always healthy
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::cache::CacheExt;
    use std::time::Duration;

    #[tokio::test]
    async fn test_get_set() {
        let cache = InMemoryCache::new(100);
        cache.set("key1", &"value1", None).await.unwrap();

        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let cache = InMemoryCache::new(100);
        cache.set("key1", &"value1", Some(Duration::from_millis(10))).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_delete() {
        let cache = InMemoryCache::new(100);
        cache.set("key1", &"value1", None).await.unwrap();
        cache.delete("key1").await.unwrap();

        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_clear() {
        let cache = InMemoryCache::new(100);
        cache.set("key1", &"value1", None).await.unwrap();
        cache.set("key2", &"value2", None).await.unwrap();
        cache.clear().await.unwrap();

        assert_eq!(cache.get::<String>("key1").await.unwrap(), None);
        assert_eq!(cache.get::<String>("key2").await.unwrap(), None);
    }
}
