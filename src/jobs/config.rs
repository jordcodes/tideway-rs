//! Configuration for background job system

use crate::utils::get_env_with_prefix;
use serde::{Deserialize, Serialize};

/// Job queue backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobBackend {
    /// In-memory queue (for development/testing)
    InMemory,
    /// Redis-backed queue (for production)
    #[cfg(feature = "jobs-redis")]
    Redis,
}

impl Default for JobBackend {
    fn default() -> Self {
        Self::InMemory
    }
}

/// Configuration for background jobs
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JobsConfig {
    /// Enable background job processing
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Job queue backend type
    #[serde(default)]
    pub backend: JobBackend,

    /// Redis connection URL (only used for Redis backend)
    #[serde(default)]
    pub redis_url: Option<String>,

    /// Number of worker threads to spawn
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,

    /// Maximum number of retries for failed jobs
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Base retry backoff in seconds (exponential backoff: base * 2^retry_count)
    #[serde(default = "default_retry_backoff_seconds")]
    pub retry_backoff_seconds: u64,
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            backend: JobBackend::default(),
            redis_url: None,
            worker_count: default_worker_count(),
            max_retries: default_max_retries(),
            retry_backoff_seconds: default_retry_backoff_seconds(),
        }
    }
}

impl JobsConfig {
    /// Load jobs configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Some(enabled) = get_env_with_prefix("JOBS_ENABLED") {
            config.enabled = enabled.parse().unwrap_or(false);
        }

        if let Some(backend) = get_env_with_prefix("JOBS_BACKEND") {
            config.backend = match backend.to_lowercase().as_str() {
                #[cfg(feature = "jobs-redis")]
                "redis" => JobBackend::Redis,
                _ => JobBackend::InMemory,
            };
        }

        if let Some(url) = get_env_with_prefix("JOBS_REDIS_URL") {
            config.redis_url = Some(url);
        }

        if let Some(count) = get_env_with_prefix("JOBS_WORKER_COUNT") {
            if let Ok(c) = count.parse() {
                config.worker_count = c;
            }
        }

        if let Some(retries) = get_env_with_prefix("JOBS_MAX_RETRIES") {
            if let Ok(r) = retries.parse() {
                config.max_retries = r;
            }
        }

        if let Some(backoff) = get_env_with_prefix("JOBS_RETRY_BACKOFF_SECONDS") {
            if let Ok(b) = backoff.parse() {
                config.retry_backoff_seconds = b;
            }
        }

        config
    }
}

fn default_enabled() -> bool {
    false
}

fn default_worker_count() -> usize {
    4
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_backoff_seconds() -> u64 {
    60
}

