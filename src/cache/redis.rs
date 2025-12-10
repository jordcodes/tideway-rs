use crate::error::{Result, TidewayError};
use crate::traits::cache::Cache;
use async_trait::async_trait;
use std::time::Duration;

/// Redis cache implementation
#[derive(Clone)]
pub struct RedisCache {
    client: redis::Client,
    default_ttl: Duration,
}

impl RedisCache {
    /// Create a new Redis cache from a connection URL
    pub fn new(url: &str, default_ttl: Duration) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| TidewayError::internal(format!("Failed to create Redis client: {}", e)))?;

        Ok(Self {
            client,
            default_ttl,
        })
    }

    /// Get a connection from the Redis client
    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to get Redis connection: {}", e)))
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection().await?;

        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(key)
            .query_async::<Option<Vec<u8>>>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis GET failed: {}", e)))?;

        Ok(value)
    }

    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let ttl_seconds = ttl
            .or(Some(self.default_ttl))
            .map(|d| d.as_secs() as usize);

        if let Some(ttl_secs) = ttl_seconds {
            redis::cmd("SETEX")
                .arg(key)
                .arg(ttl_secs)
                .arg(value)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| TidewayError::internal(format!("Redis SETEX failed: {}", e)))?;
        } else {
            redis::cmd("SET")
                .arg(key)
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
            .arg(key)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis DEL failed: {}", e)))?;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut conn = self.get_connection().await?;

        redis::cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Redis FLUSHDB failed: {}", e)))?;

        Ok(())
    }

    fn is_healthy(&self) -> bool {
        // Try to get a connection synchronously (best effort)
        // In practice, you might want to ping Redis periodically
        self.client.get_connection().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::cache::CacheExt;

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
