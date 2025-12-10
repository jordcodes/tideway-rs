use serde::{Deserialize, Serialize};
use crate::utils::get_env_with_prefix;

/// Cache backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    /// In-memory cache (default)
    InMemory,
    /// Redis cache (requires cache-redis feature)
    #[cfg(feature = "cache-redis")]
    Redis,
    /// No-op cache (for testing)
    NoOp,
}

impl Default for CacheBackend {
    fn default() -> Self {
        Self::InMemory
    }
}

/// Cache configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Cache backend type
    #[serde(default)]
    pub backend: CacheBackend,

    /// Redis connection URL (only used for Redis backend)
    #[serde(default)]
    pub redis_url: Option<String>,

    /// Default TTL for cached values (in seconds)
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: u64,

    /// Maximum number of entries for in-memory cache
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::default(),
            redis_url: None,
            default_ttl_seconds: default_ttl_seconds(),
            max_entries: default_max_entries(),
        }
    }
}

impl CacheConfig {
    /// Load cache configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(backend) = get_env_with_prefix("CACHE_BACKEND") {
            config.backend = match backend.to_lowercase().as_str() {
                "redis" => {
                    #[cfg(feature = "cache-redis")]
                    {
                        CacheBackend::Redis
                    }
                    #[cfg(not(feature = "cache-redis"))]
                    {
                        tracing::warn!("Redis cache requested but cache-redis feature not enabled, using in-memory");
                        CacheBackend::InMemory
                    }
                }
                "noop" => CacheBackend::NoOp,
                _ => CacheBackend::InMemory,
            };
        }

        if let Some(url) = get_env_with_prefix("CACHE_REDIS_URL") {
            config.redis_url = Some(url);
        }

        if let Some(ttl) = get_env_with_prefix("CACHE_DEFAULT_TTL_SECONDS") {
            if let Ok(seconds) = ttl.parse() {
                config.default_ttl_seconds = seconds;
            }
        }

        if let Some(max) = get_env_with_prefix("CACHE_MAX_ENTRIES") {
            if let Ok(entries) = max.parse() {
                config.max_entries = entries;
            }
        }

        config
    }
}

fn default_ttl_seconds() -> u64 {
    3600 // 1 hour
}

fn default_max_entries() -> usize {
    10000
}
