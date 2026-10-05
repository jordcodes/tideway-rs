# Caching

Tideway provides a trait-based caching abstraction with multiple backend implementations.

## Cache Trait

The `Cache` trait provides a simple key-value interface:

```rust
use tideway::Cache;
use std::sync::Arc;
use std::time::Duration;

async fn example(cache: Arc<dyn Cache>) -> tideway::Result<()> {
    // Set a value with TTL
    cache.set("user:123", &user_data, Some(Duration::from_secs(3600))).await?;

    // Get a value
    let user: Option<User> = cache.get("user:123").await?;

    // Delete a value
    cache.delete("user:123").await?;

    Ok(())
}
```

## Implementations

### In-Memory Cache

Default implementation using a HashMap:

```rust
use tideway::cache::InMemoryCache;
use std::sync::Arc;

let cache = Arc::new(InMemoryCache::new(10000)); // Max 10k entries
```

### Redis Cache

Requires the `cache-redis` feature:

```rust
use tideway::cache::RedisCache;
use std::sync::Arc;
use std::time::Duration;

let cache = Arc::new(
    RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600))?
);
```

Keys are stored under the `cache:` prefix (`cache.set("user:123", ...)` writes
`cache:user:123`), and `clear()` deletes only keys with that prefix, so the cache can share a
Redis database with the job queue or other data. Give caches that share a database distinct
prefixes:

```rust
let sessions = RedisCache::new(url, ttl)?.with_key_prefix("myapp:sessions:");
```

An empty prefix stores keys unprefixed, and `clear()` then deletes every key in the database.

TTLs are sent with millisecond precision; anything below 1ms is rounded up to 1ms.

### No-Op Cache

For testing or when caching is disabled:

```rust
use tideway::cache::NoOpCache;

let cache = Arc::new(NoOpCache);
```

## Configuration

```rust
use tideway::cache::CacheConfig;

let config = CacheConfig::from_env();
```

## Environment Variables

- `TIDEWAY_CACHE_BACKEND` - Backend type: `in_memory`, `redis`, or `noop`
- `TIDEWAY_CACHE_REDIS_URL` - Redis connection URL (for Redis backend)
- `TIDEWAY_CACHE_DEFAULT_TTL_SECONDS` - Default TTL (default: 3600)
- `TIDEWAY_CACHE_MAX_ENTRIES` - Max entries for in-memory cache (default: 10000)

## Custom Implementation

```rust
use tideway::Cache;
use async_trait::async_trait;

struct MyCustomCache {
    // Your cache implementation
}

#[async_trait]
impl Cache for MyCustomCache {
    async fn get<T>(&self, key: &str) -> tideway::Result<Option<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        // Your implementation
    }

    // ... implement other methods
}
```
