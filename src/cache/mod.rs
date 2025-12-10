//! Caching abstractions with multiple backend implementations.
//!
//! Provides in-memory caching by default, with optional Redis support
//! via the `cache-redis` feature.

mod config;
mod in_memory;
mod noop;

#[cfg(feature = "cache-redis")]
mod redis;

pub use config::CacheConfig;
pub use in_memory::InMemoryCache;
pub use noop::NoOpCache;

#[cfg(feature = "cache-redis")]
pub use redis::RedisCache;
