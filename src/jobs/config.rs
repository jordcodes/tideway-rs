//! Configuration for background job system

use crate::utils::get_env_with_prefix;
use serde::{Deserialize, Serialize};

/// Job queue backend type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobBackend {
    /// In-memory queue (for development/testing)
    #[default]
    InMemory,
    /// Redis-backed queue (for production)
    #[cfg(feature = "jobs-redis")]
    Redis,
}

/// Configuration for background jobs
#[derive(Clone, Deserialize, Serialize)]
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

    /// Maximum seconds to wait for running jobs during shutdown before aborting them.
    ///
    /// Keep this below the platform's kill deadline (Kubernetes defaults
    /// `terminationGracePeriodSeconds` to 30).
    #[serde(default = "default_shutdown_timeout_seconds")]
    pub shutdown_timeout_seconds: u64,
}

/// Redacts `redis_url`, which can carry a password.
impl std::fmt::Debug for JobsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobsConfig")
            .field("enabled", &self.enabled)
            .field("backend", &self.backend)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "[REDACTED]"))
            .field("worker_count", &self.worker_count)
            .field("max_retries", &self.max_retries)
            .field("retry_backoff_seconds", &self.retry_backoff_seconds)
            .field("shutdown_timeout_seconds", &self.shutdown_timeout_seconds)
            .finish()
    }
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
            shutdown_timeout_seconds: default_shutdown_timeout_seconds(),
        }
    }
}

impl JobsConfig {
    /// Load jobs configuration from environment variables
    pub fn from_env() -> Self {
        Self::default().with_env()
    }

    /// Apply environment overrides, preserving settings for absent variables.
    pub(crate) fn with_env(self) -> Self {
        let mut config = self;

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

        if let Some(count) = get_env_with_prefix("JOBS_WORKER_COUNT")
            && let Ok(c) = count.parse()
        {
            config.worker_count = c;
        }

        if let Some(retries) = get_env_with_prefix("JOBS_MAX_RETRIES")
            && let Ok(r) = retries.parse()
        {
            config.max_retries = r;
        }

        if let Some(backoff) = get_env_with_prefix("JOBS_RETRY_BACKOFF_SECONDS")
            && let Ok(b) = backoff.parse()
        {
            config.retry_backoff_seconds = b;
        }

        if let Some(timeout) = get_env_with_prefix("JOBS_SHUTDOWN_TIMEOUT_SECONDS")
            && let Ok(t) = timeout.parse()
        {
            config.shutdown_timeout_seconds = t;
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

fn default_shutdown_timeout_seconds() -> u64 {
    25
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacts_redis_url() {
        let config = JobsConfig {
            redis_url: Some("redis://:s3cret@cache.internal:6379".to_string()),
            ..Default::default()
        };

        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("s3cret"));
        assert!(debug_output.contains("[REDACTED]"));
    }
}
