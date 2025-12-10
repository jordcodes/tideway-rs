//! Cache trait for key-value storage
//!
//! This trait abstracts caching backends, allowing users to swap between
//! in-memory, Redis, or custom implementations.

use crate::error::Result;
use async_trait::async_trait;
use std::time::Duration;

/// Cache trait for key-value storage with optional TTL
///
/// Note: This trait uses type-erased serialization to be object-safe.
/// Use the helper methods `get` and `set` which handle serialization internally.
#[async_trait]
#[allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds
pub trait Cache: Send + Sync {
    /// Get a value from the cache as JSON bytes
    ///
    /// Returns `Ok(None)` if the key doesn't exist or has expired.
    /// Returns `Ok(Some(bytes))` if the value exists.
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set a value in the cache with optional TTL
    ///
    /// The value should be serialized JSON bytes.
    /// If `ttl` is `None`, the value should persist indefinitely (or use default TTL).
    /// If `ttl` is `Some(duration)`, the value should expire after that duration.
    async fn set_bytes(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()>;

    /// Delete a value from the cache
    async fn delete(&self, key: &str) -> Result<()>;

    /// Clear all values from the cache
    async fn clear(&self) -> Result<()>;

    /// Check if the cache backend is healthy
    fn is_healthy(&self) -> bool;
}

/// Helper trait for type-safe cache operations
///
/// This provides the generic `get` and `set` methods that users expect.
/// Implementations use the object-safe `get_bytes` and `set_bytes` internally.
pub trait CacheExt: Cache {
    /// Get a value from the cache
    async fn get<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        if let Some(bytes) = self.get_bytes(key).await? {
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| crate::error::TidewayError::internal(format!("Failed to deserialize: {}", e)))
        } else {
            Ok(None)
        }
    }

    /// Set a value in the cache
    async fn set<T>(&self, key: &str, value: &T, ttl: Option<Duration>) -> Result<()>
    where
        T: serde::Serialize + Send + Sync,
    {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| crate::error::TidewayError::internal(format!("Failed to serialize: {}", e)))?;
        self.set_bytes(key, bytes, ttl).await
    }

    /// Get a value as a string (convenience method)
    async fn get_str(&self, key: &str) -> Result<Option<String>> {
        self.get(key).await
    }

    /// Set a string value (convenience method)
    async fn set_str(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<()> {
        self.set(key, &value.to_string(), ttl).await
    }
}

// Blanket implementation - all Cache implementations get CacheExt for free
impl<T: Cache> CacheExt for T {}
