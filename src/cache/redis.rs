use crate::error::{Result, TidewayError};
use crate::traits::cache::Cache;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Key prefix applied to every cache entry unless overridden.
const DEFAULT_KEY_PREFIX: &str = "cache:";

/// Number of keys requested per `SCAN` iteration in `clear()`.
const CLEAR_SCAN_COUNT: usize = 500;

/// Redis cache implementation
///
/// Every key is stored under a prefix (`cache:` by default), and `clear()` only
/// deletes keys with that prefix, so the cache can share a Redis database with
/// job queues, sessions, or other data.
#[derive(Clone)]
pub struct RedisCache {
    connection: crate::redis_connection::SharedRedisConnection,
    default_ttl: Duration,
    key_prefix: Arc<str>,
    /// Cached health status (updated by ping operations)
    health_status: Arc<AtomicBool>,
}

impl RedisCache {
    /// Create a new Redis cache from a connection URL.
    ///
    /// Keys are stored under the `cache:` prefix. The connection manager is
    /// initialized on first use and shared by clones.
    pub fn new(url: &str, default_ttl: Duration) -> Result<Self> {
        let connection = crate::redis_connection::SharedRedisConnection::new(url)?;

        Ok(Self {
            connection,
            default_ttl,
            key_prefix: Arc::from(DEFAULT_KEY_PREFIX),
            health_status: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Store keys under a custom prefix instead of the default `cache:`.
    ///
    /// Use distinct prefixes for caches that share a Redis database. An empty
    /// prefix stores keys unprefixed, and `clear()` then deletes every key in
    /// the database.
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Arc::from(prefix.into());
        self
    }

    /// The prefix applied to every cache key.
    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    fn prefixed_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }

    /// Clone the shared connection manager
    async fn get_connection(&self) -> Result<redis::aio::ConnectionManager> {
        self.connection.get().await
    }

    /// Ping Redis and update health status
    ///
    /// Call this periodically to keep health status accurate.
    /// The synchronous `is_healthy()` returns the cached status.
    pub async fn ping(&self) -> bool {
        match self.get_connection().await {
            Ok(mut conn) => {
                let result: redis::RedisResult<String> =
                    redis::cmd("PING").query_async(&mut conn).await;
                let healthy = result.is_ok();
                self.health_status.store(healthy, Ordering::Release);
                healthy
            }
            Err(e) => {
                tracing::warn!("Redis ping failed: {}", e);
                self.health_status.store(false, Ordering::Release);
                false
            }
        }
    }
}

/// Convert a TTL to a `PSETEX` millisecond argument.
///
/// Redis rejects a zero expire time, so sub-millisecond remainders are rounded
/// up and the result is clamped to at least 1ms.
fn ttl_to_millis(ttl: Duration) -> u64 {
    let millis = ttl.as_nanos().div_ceil(1_000_000).max(1);
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Build a `SCAN MATCH` pattern matching every key that starts with `prefix`.
///
/// Glob metacharacters in the prefix are escaped so they match literally.
fn prefix_match_pattern(prefix: &str) -> String {
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for c in prefix.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('*');
    pattern
}

#[async_trait]
impl Cache for RedisCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection().await?;

        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(self.prefixed_key(key))
            .query_async::<Option<Vec<u8>>>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis GET failed: {}", e)))?;

        Ok(value)
    }

    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let key = self.prefixed_key(key);
        let ttl_millis = ttl.or(Some(self.default_ttl)).map(ttl_to_millis);

        if let Some(ttl_ms) = ttl_millis {
            redis::cmd("PSETEX")
                .arg(&key)
                .arg(ttl_ms)
                .arg(value)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| TidewayError::internal(format!("Redis PSETEX failed: {}", e)))?;
        } else {
            redis::cmd("SET")
                .arg(&key)
                .arg(value)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| TidewayError::internal(format!("Redis SET failed: {}", e)))?;
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;

        redis::cmd("DEL")
            .arg(self.prefixed_key(key))
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis DEL failed: {}", e)))?;

        Ok(())
    }

    /// Delete every key under this cache's prefix.
    ///
    /// Keys outside the prefix are left untouched. Iterates with `SCAN`, so it
    /// does not block Redis, but keys written concurrently may survive.
    async fn clear(&self) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let pattern = prefix_match_pattern(&self.key_prefix);
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(CLEAR_SCAN_COUNT)
                .query_async(&mut conn)
                .await
                .map_err(|e| TidewayError::internal(format!("Redis SCAN failed: {}", e)))?;

            if !keys.is_empty() {
                redis::cmd("DEL")
                    .arg(keys)
                    .query_async::<()>(&mut conn)
                    .await
                    .map_err(|e| TidewayError::internal(format!("Redis DEL failed: {}", e)))?;
            }

            if next_cursor == 0 {
                break;
            }
            cursor = next_cursor;
        }

        Ok(())
    }

    fn is_healthy(&self) -> bool {
        // Return cached health status from last ping() call
        // Call ping() periodically via a background task for accurate status
        self.health_status.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::cache::CacheExt;

    #[test]
    fn ttl_to_millis_never_produces_zero_for_sub_second_ttls() {
        assert_eq!(ttl_to_millis(Duration::from_millis(500)), 500);
        assert_eq!(ttl_to_millis(Duration::from_millis(999)), 999);
        assert_eq!(ttl_to_millis(Duration::from_micros(1)), 1);
        assert_eq!(ttl_to_millis(Duration::ZERO), 1);
    }

    #[test]
    fn ttl_to_millis_rounds_up_partial_milliseconds() {
        assert_eq!(ttl_to_millis(Duration::from_secs(1)), 1_000);
        assert_eq!(ttl_to_millis(Duration::from_micros(1_500)), 2);
        assert_eq!(ttl_to_millis(Duration::from_secs(3600)), 3_600_000);
        assert_eq!(ttl_to_millis(Duration::MAX), u64::MAX);
    }

    #[test]
    fn prefix_match_pattern_escapes_glob_characters() {
        assert_eq!(prefix_match_pattern("cache:"), "cache:*");
        assert_eq!(prefix_match_pattern(""), "*");
        assert_eq!(prefix_match_pattern(r"a*b?[c]\d:"), r"a\*b\?\[c\]\\d:*");
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_redis_cache_clear_keeps_keys_outside_prefix() {
        let cache = RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600))
            .unwrap()
            .with_key_prefix("tideway_test_cache:");
        let mut conn = cache.get_connection().await.unwrap();
        redis::cmd("SET")
            .arg("tideway_test_other")
            .arg("keep")
            .query_async::<()>(&mut conn)
            .await
            .unwrap();

        cache.set("a", &"v", None).await.unwrap();
        cache.clear().await.unwrap();

        let value: Option<String> = cache.get("a").await.unwrap();
        assert_eq!(value, None);
        let other: Option<String> = redis::cmd("GET")
            .arg("tideway_test_other")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(other.as_deref(), Some("keep"));
        redis::cmd("DEL")
            .arg("tideway_test_other")
            .query_async::<()>(&mut conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_redis_cache_sub_second_ttl() {
        let cache = RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600)).unwrap();

        cache
            .set("test_sub_second", &"v", Some(Duration::from_millis(500)))
            .await
            .unwrap();
        let value: Option<String> = cache.get("test_sub_second").await.unwrap();
        assert_eq!(value, Some("v".to_string()));

        tokio::time::sleep(Duration::from_millis(700)).await;
        let value: Option<String> = cache.get("test_sub_second").await.unwrap();
        assert_eq!(value, None);
    }

    // Note: These tests require a running Redis instance
    // They're commented out by default but can be enabled for integration testing

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_redis_cache() {
        let cache = RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600)).unwrap();

        cache.set("test_key", &"test_value", None).await.unwrap();
        let value: Option<String> = cache.get("test_key").await.unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        cache.delete("test_key").await.unwrap();
        let value: Option<String> = cache.get("test_key").await.unwrap();
        assert_eq!(value, None);
    }
}
