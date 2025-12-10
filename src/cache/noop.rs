use crate::error::Result;
use crate::traits::cache::Cache;
use async_trait::async_trait;
use std::time::Duration;

/// No-op cache implementation for testing
///
/// This cache does nothing - all operations succeed but don't store anything.
/// Useful for testing or when caching is disabled.
#[derive(Clone, Default)]
pub struct NoOpCache;

#[async_trait]
impl Cache for NoOpCache {
    async fn get_bytes(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn set_bytes(&self, _key: &str, _value: Vec<u8>, _ttl: Option<Duration>) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::cache::CacheExt;

    #[tokio::test]
    async fn test_noop_cache() {
        let cache = NoOpCache;

        cache.set("key", &"value", None).await.unwrap();
        let value: Option<String> = cache.get("key").await.unwrap();
        assert_eq!(value, None);

        cache.delete("key").await.unwrap();
        cache.clear().await.unwrap();
    }
}
