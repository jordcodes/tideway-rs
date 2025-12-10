//! Example: Using Redis caching
//!
//! This example demonstrates how to use Redis as a cache backend.
//! Requires the `cache-redis` feature.
//!
//! Run with: cargo run --example redis_cache --features cache-redis

#[cfg(feature = "cache-redis")]
use tideway::cache::RedisCache;
#[cfg(feature = "cache-redis")]
use tideway::{Cache, CacheExt};
#[cfg(feature = "cache-redis")]
use std::sync::Arc;
#[cfg(feature = "cache-redis")]
use std::time::Duration;

#[cfg(not(feature = "cache-redis"))]
fn main() {
    println!("This example requires the 'cache-redis' feature");
    println!("Run with: cargo run --example redis_cache --features cache-redis");
}

#[cfg(feature = "cache-redis")]
#[tokio::main]
async fn main() -> tideway::Result<()> {
    tideway::init_tracing();

    // Create Redis cache
    let cache = RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600))?;

    // Store some data
    let user_data = User {
        id: 123,
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };

    cache.set("user:123", &user_data, Some(Duration::from_secs(1800))).await?;
    println!("Stored user data in cache");

    // Retrieve data
    if let Some(user) = cache.get::<User>("user:123").await? {
        println!("Retrieved user: {} ({})", user.name, user.email);
    }

    // Use convenience methods for strings
    cache.set_str("greeting", "Hello, World!", Some(Duration::from_secs(60))).await?;
    if let Some(greeting) = cache.get_str("greeting").await? {
        println!("Greeting: {}", greeting);
    }

    // Delete a key
    cache.delete("greeting").await?;
    println!("Deleted greeting from cache");

    // Use in AppContext (wrap in Arc for the context)
    let cache_arc: Arc<dyn tideway::Cache> = Arc::new(
        RedisCache::new("redis://127.0.0.1/", Duration::from_secs(3600))?
    );
    let _context = tideway::AppContext::builder()
        .with_cache(cache_arc)
        .build();

    println!("Redis cache example completed!");
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct User {
    id: u64,
    name: String,
    email: String,
}
