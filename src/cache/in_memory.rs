//! In-memory cache implementation backed by moka
//!
//! Uses the moka crate for a production-grade concurrent cache with:
//! - True concurrent access (lock-free reads)
//! - TinyLFU eviction policy (combines LRU and LFU)
//! - Automatic TTL expiration
//! - Bounded by entry count and optionally by size

use crate::error::Result;
use crate::traits::cache::Cache;
use async_trait::async_trait;
use moka::future::Cache as MokaCache;
use moka::Expiry;
use std::time::{Duration, Instant};

/// Default TTL for cache entries when none is specified (24 hours)
const DEFAULT_TTL: Duration = Duration::from_secs(86400);

/// Cache entry that stores value with optional custom TTL
#[derive(Clone)]
struct CacheEntry {
    value: Vec<u8>,
    /// Custom TTL for this entry, None means use default
    custom_ttl: Option<Duration>,
}

/// Expiry implementation that supports per-entry TTL
struct CacheExpiry {
    default_ttl: Duration,
}

impl Expiry<String, CacheEntry> for CacheExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CacheEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.custom_ttl.unwrap_or(self.default_ttl))
    }

    fn expire_after_read(
        &self,
        _key: &String,
        _value: &CacheEntry,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        // Don't change expiry on read (TTL behavior, not TTI)
        duration_until_expiry
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &CacheEntry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        // Reset TTL on update
        Some(value.custom_ttl.unwrap_or(self.default_ttl))
    }
}

/// In-memory cache implementation backed by moka
///
/// This is a production-grade cache suitable for high-concurrency workloads.
/// It uses the TinyLFU eviction policy which combines LRU (Least Recently Used)
/// and LFU (Least Frequently Used) for optimal cache hit rates.
///
/// # Features
///
/// - **Concurrent access**: Lock-free reads, highly concurrent writes
/// - **TinyLFU eviction**: Better hit rates than pure LRU
/// - **TTL support**: Per-entry expiration times
/// - **Bounded capacity**: Prevents memory exhaustion
///
/// # Example
///
/// ```rust,ignore
/// use tideway::cache::InMemoryCache;
/// use tideway::traits::cache::CacheExt;
///
/// let cache = InMemoryCache::new(10_000); // 10,000 max entries
///
/// // Store a value with default TTL
/// cache.set("user:123", &user_data, None).await?;
///
/// // Store with custom TTL
/// cache.set("session:abc", &session, Some(Duration::from_secs(3600))).await?;
///
/// // Retrieve
/// let user: Option<UserData> = cache.get("user:123").await?;
/// ```
#[derive(Clone)]
pub struct InMemoryCache {
    inner: MokaCache<String, CacheEntry>,
}

impl InMemoryCache {
    /// Create a new in-memory cache with the specified maximum number of entries
    ///
    /// The cache will automatically evict entries when at capacity using the
    /// TinyLFU policy, which prioritizes keeping frequently and recently accessed
    /// entries.
    pub fn new(max_entries: u64) -> Self {
        let expiry = CacheExpiry {
            default_ttl: DEFAULT_TTL,
        };
        let cache = MokaCache::builder()
            .max_capacity(max_entries)
            .expire_after(expiry)
            .build();

        Self { inner: cache }
    }

    /// Create a cache with custom default TTL
    pub fn with_ttl(max_entries: u64, default_ttl: Duration) -> Self {
        let expiry = CacheExpiry { default_ttl };
        let cache = MokaCache::builder()
            .max_capacity(max_entries)
            .expire_after(expiry)
            .build();

        Self { inner: cache }
    }

    /// Create a cache builder for more configuration options
    pub fn builder() -> InMemoryCacheBuilder {
        InMemoryCacheBuilder::new()
    }

    /// Run pending maintenance tasks (eviction, expiration)
    ///
    /// Moka runs maintenance automatically, but this can be called
    /// to force immediate cleanup if needed.
    pub async fn run_pending_tasks(&self) {
        self.inner.run_pending_tasks().await;
    }

    /// Get the current number of entries in the cache
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    /// Get the weighted size of entries in the cache
    pub fn weighted_size(&self) -> u64 {
        self.inner.weighted_size()
    }
}

/// Builder for InMemoryCache with additional configuration options
pub struct InMemoryCacheBuilder {
    max_entries: u64,
    default_ttl: Duration,
}

impl InMemoryCacheBuilder {
    pub fn new() -> Self {
        Self {
            max_entries: 10_000,
            default_ttl: DEFAULT_TTL,
        }
    }

    /// Set maximum number of entries
    pub fn max_entries(mut self, max: u64) -> Self {
        self.max_entries = max;
        self
    }

    /// Set default time-to-live for entries
    pub fn time_to_live(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Build the cache
    pub fn build(self) -> InMemoryCache {
        let expiry = CacheExpiry {
            default_ttl: self.default_ttl,
        };
        let cache = MokaCache::builder()
            .max_capacity(self.max_entries)
            .expire_after(expiry)
            .build();

        InMemoryCache { inner: cache }
    }
}

impl Default for InMemoryCacheBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cache for InMemoryCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.get(key).await.map(|entry| entry.value))
    }

    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()> {
        let entry = CacheEntry {
            value,
            custom_ttl: ttl,
        };
        self.inner.insert(key.to_string(), entry).await;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.remove(key).await;
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.inner.invalidate_all();
        // Run pending tasks to ensure invalidation completes
        self.inner.run_pending_tasks().await;
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true // Moka is always healthy as an in-memory cache
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::cache::CacheExt;

    #[tokio::test]
    async fn test_get_set() {
        let cache = InMemoryCache::new(100);
        cache.set("key1", &"value1", None).await.unwrap();

        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let cache = InMemoryCache::with_ttl(100, Duration::from_millis(50));
        cache
            .set("key1", &"value1", Some(Duration::from_millis(10)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        cache.run_pending_tasks().await;

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
    async fn test_bounded_cache_does_not_grow_unbounded() {
        let cache = InMemoryCache::new(10);

        // Insert 100 entries
        for i in 0..100 {
            cache
                .set(&format!("key{}", i), &format!("value{}", i), None)
                .await
                .unwrap();
        }

        // Run pending tasks to ensure eviction happens
        cache.run_pending_tasks().await;

        // Check that cache size is bounded (moka may slightly exceed during concurrent writes)
        let size = cache.entry_count();
        assert!(
            size <= 15, // Allow some slack for moka's async eviction
            "Cache should be bounded near max_entries, got {}",
            size
        );
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use std::sync::Arc;

        let cache = Arc::new(InMemoryCache::new(1000));

        // Spawn multiple tasks to read and write concurrently
        let mut handles = vec![];

        for i in 0..10 {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..100 {
                    let key = format!("key{}_{}", i, j);
                    cache.set(&key, &format!("value{}_{}", i, j), None).await.unwrap();
                    let _: Option<String> = cache.get(&key).await.unwrap();
                }
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Cache should still be functional
        cache.set("final", &"value", None).await.unwrap();
        let value: Option<String> = cache.get("final").await.unwrap();
        assert_eq!(value, Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_builder_pattern() {
        let cache = InMemoryCache::builder()
            .max_entries(500)
            .time_to_live(Duration::from_secs(60))
            .build();

        cache.set("key", &"value", None).await.unwrap();
        let value: Option<String> = cache.get("key").await.unwrap();
        assert_eq!(value, Some("value".to_string()));
    }
}
