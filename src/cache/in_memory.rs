use crate::error::Result;
use crate::traits::cache::Cache;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cached value with expiration time and LRU tracking
struct CachedValue {
    data: Vec<u8>,
    expires_at: Option<Instant>,
    /// Last access time for LRU eviction
    last_accessed: Instant,
}

impl CachedValue {
    fn new(data: Vec<u8>, ttl: Option<Duration>) -> Self {
        let now = Instant::now();
        let expires_at = ttl.map(|d| now + d);
        Self {
            data,
            expires_at,
            last_accessed: now,
        }
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|expires| Instant::now() >= expires)
            .unwrap_or(false)
    }

    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }
}

/// In-memory cache implementation with LRU eviction
///
/// Uses a HashMap with TTL support and LRU (Least Recently Used) eviction.
/// When the cache reaches capacity, the least recently accessed entries
/// are evicted first. Expired entries are removed lazily on access.
///
/// # Security
///
/// The cache is bounded by `max_entries` to prevent memory exhaustion attacks.
/// LRU eviction ensures that frequently accessed entries are retained while
/// infrequently accessed entries (potentially from attackers trying to flush
/// the cache) are evicted first.
#[derive(Clone)]
pub struct InMemoryCache {
    inner: Arc<RwLock<HashMap<String, CachedValue>>>,
    max_entries: usize,
}

impl InMemoryCache {
    /// Create a new in-memory cache with the specified maximum number of entries
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
        }
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) {
        let mut cache = self.inner.write().await;
        cache.retain(|_, value| !value.is_expired());
    }
}

#[async_trait]
impl Cache for InMemoryCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // Use write lock to both read and update last_accessed atomically
        let mut cache = self.inner.write().await;

        if let Some(value) = cache.get_mut(key) {
            if value.is_expired() {
                cache.remove(key);
                return Ok(None);
            }
            // Update last_accessed for LRU and return data
            value.touch();
            return Ok(Some(value.data.clone()));
        }
        Ok(None)
    }

    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()> {
        let mut cache = self.inner.write().await;

        // Only evict if at or over capacity
        if cache.len() >= self.max_entries {
            // First, remove any expired entries
            cache.retain(|_, v| !v.is_expired());

            // If still at capacity, evict LRU entries
            if cache.len() >= self.max_entries {
                let to_evict = std::cmp::max(1, self.max_entries / 10);

                let mut entries: Vec<_> = cache
                    .iter()
                    .map(|(k, v)| (k.clone(), v.last_accessed))
                    .collect();
                entries.sort_by_key(|(_, last_accessed)| *last_accessed);

                for (key, _) in entries.into_iter().take(to_evict) {
                    cache.remove(&key);
                }
            }
        }

        cache.insert(key.to_string(), CachedValue::new(value, ttl));
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
        cache
            .set("key1", &"value1", Some(Duration::from_millis(10)))
            .await
            .unwrap();

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

    #[tokio::test]
    async fn test_lru_eviction() {
        // Small cache to test eviction
        let cache = InMemoryCache::new(5);

        // Fill the cache
        for i in 0..5 {
            cache
                .set(&format!("key{}", i), &format!("value{}", i), None)
                .await
                .unwrap();
            // Small delay to ensure different timestamps
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Access key0 and key1 to make them "recently used"
        let _: Option<String> = cache.get("key0").await.unwrap();
        let _: Option<String> = cache.get("key1").await.unwrap();

        // Add a new entry, which should trigger eviction
        cache.set("key5", &"value5", None).await.unwrap();

        // key0 and key1 should still exist (recently accessed)
        assert!(cache.get::<String>("key0").await.unwrap().is_some());
        assert!(cache.get::<String>("key1").await.unwrap().is_some());

        // The new key should exist
        assert!(cache.get::<String>("key5").await.unwrap().is_some());

        // At least one of the older, unaccessed keys should be evicted
        // (key2, key3, or key4)
        let remaining: usize = ["key2", "key3", "key4"]
            .iter()
            .filter(|k| {
                // Use a blocking approach to avoid async in closure
                futures::executor::block_on(cache.get::<String>(k))
                    .unwrap()
                    .is_some()
            })
            .count();

        // With max_entries=5 and 6 inserts, at least 1 should be evicted
        assert!(remaining < 3, "Expected some old keys to be evicted");
    }

    #[tokio::test]
    async fn test_bounded_cache_does_not_grow_unbounded() {
        let cache = InMemoryCache::new(10);

        // Insert 100 entries
        for i in 0..100 {
            cache
                .set(&format!("key{}", i), &format!("value{}", i), None)
                .await
                .unwrap();
        }

        // Check that cache size is bounded
        let size = cache.inner.read().await.len();
        assert!(
            size <= 10,
            "Cache should not exceed max_entries, got {}",
            size
        );
    }

    #[tokio::test]
    async fn test_expired_entries_evicted_first() {
        let cache = InMemoryCache::new(5);

        // Add some entries with short TTL
        cache
            .set("expire1", &"value1", Some(Duration::from_millis(10)))
            .await
            .unwrap();
        cache
            .set("expire2", &"value2", Some(Duration::from_millis(10)))
            .await
            .unwrap();

        // Add entries without TTL
        cache.set("keep1", &"value1", None).await.unwrap();
        cache.set("keep2", &"value2", None).await.unwrap();
        cache.set("keep3", &"value3", None).await.unwrap();

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Add new entry - should evict expired ones first
        cache.set("new1", &"new_value", None).await.unwrap();

        // Entries without TTL should still exist
        assert!(cache.get::<String>("keep1").await.unwrap().is_some());
        assert!(cache.get::<String>("keep2").await.unwrap().is_some());
        assert!(cache.get::<String>("keep3").await.unwrap().is_some());
        assert!(cache.get::<String>("new1").await.unwrap().is_some());
    }
}
