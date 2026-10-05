use crate::error::{Result, TidewayError};
use crate::traits::cache::Cache;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Default namespace for cache keys stored in Redis.
pub const DEFAULT_KEY_PREFIX: &str = "cache:";

/// Number of keys requested per `SCAN` call when clearing the cache.
const CLEAR_SCAN_COUNT: usize = 500;

/// Redis cache implementation
///
/// Every key is stored under a namespace prefix (`cache:` by default), so `clear()` only removes
/// this cache's entries and leaves other data in the same database, such as `RedisJobQueue` jobs,
/// untouched.
#[derive(Clone)]
pub struct RedisCache {
    connection: crate::redis_connection::SharedRedisConnection,
    default_ttl: Duration,
    key_prefix: String,
    /// Cached health status (updated by ping operations)
    health_status: Arc<AtomicBool>,
}

impl RedisCache {
    /// Create a new Redis cache from a connection URL.
    ///
    /// Keys are namespaced with [`DEFAULT_KEY_PREFIX`]; use [`RedisCache::with_prefix`] to change it.
    /// The connection manager is initialized on first use and shared by clones.
    pub fn new(url: &str, default_ttl: Duration) -> Result<Self> {
        let connection = crate::redis_connection::SharedRedisConnection::new(url)?;

        Ok(Self {
            connection,
            default_ttl,
            key_prefix: DEFAULT_KEY_PREFIX.to_string(),
            health_status: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Set the namespace prefix applied to every cache key.
    ///
    /// `clear()` deletes every key that starts with this prefix, so it must not be shared with
    /// other data in the same Redis database. An empty prefix is rejected by `clear()`.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    fn prefixed(&self, key: &str) -> String {
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

#[async_trait]
impl Cache for RedisCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection().await?;

        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(self.prefixed(key))
            .query_async::<Option<Vec<u8>>>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis GET failed: {}", e)))?;

        Ok(value)
    }

    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let ttl_seconds = ttl.or(Some(self.default_ttl)).map(|d| d.as_secs() as usize);

        if let Some(ttl_secs) = ttl_seconds {
            redis::cmd("SETEX")
                .arg(self.prefixed(key))
                .arg(ttl_secs)
                .arg(value)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| TidewayError::internal(format!("Redis SETEX failed: {}", e)))?;
        } else {
            redis::cmd("SET")
                .arg(self.prefixed(key))
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
            .arg(self.prefixed(key))
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis DEL failed: {}", e)))?;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut conn = self.get_connection().await?;

        // Only remove keys in this cache's namespace; FLUSHDB would also wipe jobs and any other
        // data sharing the database.
        if self.key_prefix.is_empty() {
            return Err(TidewayError::internal(
                "Refusing to clear Redis cache without a key prefix",
            ));
        }
        let pattern = format!("{}*", escape_glob(&self.key_prefix));
        let mut cursor: u64 = 0;
        loop {
            let (next, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
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

            if next == 0 {
                break;
            }
            cursor = next;
        }

        Ok(())
    }

    fn is_healthy(&self) -> bool {
        // Return cached health status from last ping() call
        // Call ping() periodically via a background task for accurate status
        self.health_status.load(Ordering::Acquire)
    }
}

/// Escape Redis glob metacharacters so the prefix is matched literally.
fn escape_glob(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::cache::CacheExt;

    #[test]
    fn escape_glob_escapes_metacharacters() {
        assert_eq!(escape_glob("cache:"), "cache:");
        assert_eq!(escape_glob(r"a*b?c[d]e\f"), r"a\*b\?c\[d\]e\\f");
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

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_redis_cache_clear_keeps_other_keys() {
        let cache = RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600))
            .unwrap()
            .with_prefix("tideway-test-cache:");
        let mut conn = cache.get_connection().await.unwrap();
        redis::cmd("SET")
            .arg("tideway-test-jobs:pending")
            .arg("job")
            .query_async::<()>(&mut conn)
            .await
            .unwrap();
        cache.set("test_key", &"test_value", None).await.unwrap();

        cache.clear().await.unwrap();

        let value: Option<String> = cache.get("test_key").await.unwrap();
        assert_eq!(value, None);
        let job: Option<String> = redis::cmd("GETDEL")
            .arg("tideway-test-jobs:pending")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(job.as_deref(), Some("job"));
    }
}
