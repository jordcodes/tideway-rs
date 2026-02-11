//! Redis-backed job queue implementation
//!
//! This implementation uses Redis lists and sorted sets for distributed
//! job processing. Multiple workers can compete for jobs from the same queue.

use crate::error::{Result, TidewayError};
use crate::traits::job::{Job, JobData, JobQueue};
use async_trait::async_trait;
#[cfg(feature = "jobs")]
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

const PENDING_JOBS_KEY: &str = "jobs:pending";
const SCHEDULED_JOBS_KEY: &str = "jobs:scheduled";
const WORKERS_KEY: &str = "jobs:workers";
const PROCESSING_KEY_PREFIX: &str = "jobs:processing:";
const WORKER_HEARTBEAT_KEY_PREFIX: &str = "jobs:worker:heartbeat:";
const WORKER_HEARTBEAT_TTL_SECONDS: u64 = 30;

/// Atomically move all due scheduled jobs into the pending queue.
///
/// KEYS[1] = scheduled zset key
/// KEYS[2] = pending list key
/// ARGV[1] = unix timestamp cutoff
const MOVE_DUE_JOBS_LUA: &str = r#"
local scheduled_key = KEYS[1]
local pending_key = KEYS[2]
local cutoff = tonumber(ARGV[1])
local jobs = redis.call('ZRANGEBYSCORE', scheduled_key, '-inf', cutoff)

for _, job in ipairs(jobs) do
  redis.call('ZREM', scheduled_key, job)
  redis.call('LPUSH', pending_key, job)
end

return #jobs
"#;

/// Reclaim jobs from stale workers whose heartbeat has expired.
///
/// KEYS[1] = workers set key
/// KEYS[2] = pending list key
/// ARGV[1] = heartbeat key prefix
/// ARGV[2] = processing list key prefix
const RECLAIM_STALE_WORKERS_LUA: &str = r#"
local workers_key = KEYS[1]
local pending_key = KEYS[2]
local heartbeat_prefix = ARGV[1]
local processing_prefix = ARGV[2]
local reclaimed = 0

local workers = redis.call('SMEMBERS', workers_key)
for _, worker in ipairs(workers) do
  local heartbeat_key = heartbeat_prefix .. worker
  if redis.call('EXISTS', heartbeat_key) == 0 then
    local processing_key = processing_prefix .. worker
    while true do
      local job = redis.call('RPOPLPUSH', processing_key, pending_key)
      if not job then
        break
      end
      reclaimed = reclaimed + 1
    end
    redis.call('SREM', workers_key, worker)
  end
end

return reclaimed
"#;

fn processing_key(worker_id: &str) -> String {
    format!("{PROCESSING_KEY_PREFIX}{worker_id}")
}

fn worker_heartbeat_key(worker_id: &str) -> String {
    format!("{WORKER_HEARTBEAT_KEY_PREFIX}{worker_id}")
}

/// Redis-backed job queue implementation
///
/// Uses Redis data structures:
/// - `jobs:pending` - List of jobs ready to be processed
/// - `jobs:processing:{worker_id}` - List of jobs being processed by a worker
/// - `jobs:scheduled` - Sorted set of scheduled jobs (score = timestamp)
/// - `jobs:failed` - List of permanently failed jobs
/// - `jobs:completed` - List of completed jobs (optional, for history)
///
/// # Shutdown Behavior
///
/// The scheduler task runs in the background and will automatically stop when
/// `shutdown()` is called. Always call `shutdown()` before dropping the queue
/// to ensure clean resource cleanup.
#[derive(Clone)]
pub struct RedisJobQueue {
    client: redis::Client,
    worker_id: String,
    max_retries: u32,
    retry_backoff_seconds: u64,
    /// Cached health status (updated by ping operations)
    health_status: Arc<AtomicBool>,
    /// Shutdown flag for background scheduler task
    shutdown: Arc<AtomicBool>,
    /// Handle to the scheduler task for cleanup
    scheduler_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl RedisJobQueue {
    /// Create a new Redis job queue
    ///
    /// # Arguments
    ///
    /// * `url` - Redis connection URL (e.g., "redis://127.0.0.1:6379")
    /// * `worker_id` - Optional worker identifier (auto-generated if None)
    /// * `max_retries` - Maximum retry attempts for failed jobs
    /// * `retry_backoff_seconds` - Base backoff duration (exponentially increased)
    ///
    /// # Important
    ///
    /// Call `shutdown()` when done to cleanly stop background tasks.
    pub fn new(
        url: &str,
        worker_id: Option<String>,
        max_retries: u32,
        retry_backoff_seconds: u64,
    ) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| TidewayError::internal(format!("Failed to create Redis client: {}", e)))?;

        let worker_id = worker_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let shutdown = Arc::new(AtomicBool::new(false));

        let queue = Self {
            client,
            worker_id,
            max_retries,
            retry_backoff_seconds,
            health_status: Arc::new(AtomicBool::new(true)),
            shutdown,
            scheduler_handle: Arc::new(tokio::sync::Mutex::new(None)),
        };

        // Start background task to move scheduled jobs to pending
        queue.start_scheduler_task();

        Ok(queue)
    }

    /// Gracefully shutdown the job queue
    ///
    /// Signals the background scheduler task to stop and waits for it to finish.
    /// This should be called before dropping the queue to ensure clean cleanup.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let queue = RedisJobQueue::new("redis://localhost", None, 3, 5)?;
    /// // ... use the queue ...
    /// queue.shutdown().await;
    /// ```
    pub async fn shutdown(&self) {
        // Signal shutdown
        self.shutdown.store(true, Ordering::Release);

        // Wait for scheduler task to finish
        let mut handle_guard = self.scheduler_handle.lock().await;
        if let Some(handle) = handle_guard.take() {
            // Give the task a reasonable time to finish, then abort if needed
            match tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await {
                Ok(_) => tracing::debug!("Redis job queue scheduler stopped cleanly"),
                Err(_) => tracing::warn!("Redis job queue scheduler did not stop within timeout"),
            }
        }
    }

    /// Ping Redis and update health status
    ///
    /// Call this periodically (e.g., every 30 seconds) to keep health status accurate.
    /// The synchronous `is_healthy()` trait method returns the cached status from the
    /// last ping.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Background health check task
    /// tokio::spawn(async move {
    ///     let mut interval = tokio::time::interval(Duration::from_secs(30));
    ///     loop {
    ///         interval.tick().await;
    ///         queue.ping().await;
    ///     }
    /// });
    /// ```
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
                tracing::warn!("Redis job queue ping failed: {}", e);
                self.health_status.store(false, Ordering::Release);
                false
            }
        }
    }

    /// Get a Redis connection
    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to get Redis connection: {}", e)))
    }

    /// Start background task to move scheduled jobs to pending
    ///
    /// This task polls the scheduled jobs set and moves due jobs to the pending list.
    /// It respects the shutdown flag and will exit cleanly when signaled.
    fn start_scheduler_task(&self) {
        let client = self.client.clone();
        let worker_id = self.worker_id.clone();
        let shutdown = self.shutdown.clone();
        let scheduler_handle = self.scheduler_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

            loop {
                // Check shutdown flag before waiting
                if shutdown.load(Ordering::Acquire) {
                    tracing::debug!("Redis job queue scheduler shutting down");
                    break;
                }

                interval.tick().await;

                // Check again after waking up
                if shutdown.load(Ordering::Acquire) {
                    break;
                }

                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    let heartbeat_key = worker_heartbeat_key(&worker_id);
                    let heartbeat_update: redis::RedisResult<()> = redis::pipe()
                        .cmd("SADD")
                        .arg(WORKERS_KEY)
                        .arg(&worker_id)
                        .ignore()
                        .cmd("SETEX")
                        .arg(&heartbeat_key)
                        .arg(WORKER_HEARTBEAT_TTL_SECONDS)
                        .arg("1")
                        .ignore()
                        .query_async(&mut conn)
                        .await;
                    if let Err(error) = heartbeat_update {
                        tracing::warn!(
                            error = %error,
                            worker_id = %worker_id,
                            "Failed to update Redis job worker heartbeat"
                        );
                        continue;
                    }

                    let reclaimed: redis::RedisResult<i64> =
                        redis::Script::new(RECLAIM_STALE_WORKERS_LUA)
                            .key(WORKERS_KEY)
                            .key(PENDING_JOBS_KEY)
                            .arg(WORKER_HEARTBEAT_KEY_PREFIX)
                            .arg(PROCESSING_KEY_PREFIX)
                            .invoke_async(&mut conn)
                            .await;
                    match reclaimed {
                        Ok(count) if count > 0 => {
                            tracing::warn!(
                                reclaimed_jobs = count,
                                worker_id = %worker_id,
                                "Reclaimed orphaned jobs from stale workers"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                error = %error,
                                worker_id = %worker_id,
                                "Failed to reclaim jobs from stale workers"
                            );
                        }
                    }

                    let now = Utc::now().timestamp();
                    let moved: redis::RedisResult<i64> = redis::Script::new(MOVE_DUE_JOBS_LUA)
                        .key(SCHEDULED_JOBS_KEY)
                        .key(PENDING_JOBS_KEY)
                        .arg(now)
                        .invoke_async(&mut conn)
                        .await;

                    if let Err(error) = moved {
                        tracing::warn!(
                            error = %error,
                            "Failed to move due scheduled jobs to pending queue"
                        );
                    }
                }
            }
        });

        // Store the handle for later cleanup
        // Note: We use try_lock here since start_scheduler_task is called from new()
        // which is not async. In practice, this will always succeed since we just created
        // the mutex.
        if let Ok(mut guard) = scheduler_handle.try_lock() {
            *guard = Some(handle);
        } else {
            // If we can't store the handle, abort it to prevent orphaned tasks
            handle.abort();
            tracing::error!("Failed to store scheduler handle - this should not happen");
        }
    }
}

#[async_trait]
impl JobQueue for RedisJobQueue {
    async fn enqueue(&self, job: &dyn Job) -> Result<String> {
        let job_id = Uuid::new_v4().to_string();
        let payload = job.serialize()?;

        let job_data = JobData::new(
            job_id.clone(),
            job.job_type().to_string(),
            payload,
            self.max_retries,
        );

        let job_json = serde_json::to_string(&job_data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize job: {}", e)))?;

        let mut conn = self.get_connection().await?;
        redis::cmd("LPUSH")
            .arg(PENDING_JOBS_KEY)
            .arg(&job_json)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to enqueue job: {}", e)))?;

        Ok(job_id)
    }

    async fn dequeue(&self) -> Result<Option<JobData>> {
        let mut conn = self.get_connection().await?;
        let processing_key = processing_key(&self.worker_id);

        // Use BRPOPLPUSH for atomic move from pending to processing
        // This blocks for up to 5 seconds waiting for a job
        let result: Option<String> = redis::cmd("BRPOPLPUSH")
            .arg(PENDING_JOBS_KEY)
            .arg(&processing_key)
            .arg(5) // timeout in seconds
            .query_async(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to dequeue job: {}", e)))?;

        if let Some(job_json) = result {
            let job_data: JobData = serde_json::from_str(&job_json)
                .map_err(|e| TidewayError::internal(format!("Failed to deserialize job: {}", e)))?;
            Ok(Some(job_data))
        } else {
            Ok(None)
        }
    }

    async fn complete(&self, job_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let processing_key = processing_key(&self.worker_id);

        // Find and remove the job from processing list
        let jobs: Vec<String> = redis::cmd("LRANGE")
            .arg(&processing_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                TidewayError::internal(format!("Failed to list processing jobs: {}", e))
            })?;

        for job_json in jobs {
            if let Ok(job_data) = serde_json::from_str::<JobData>(&job_json) {
                if job_data.job_id == job_id {
                    // Remove from processing
                    redis::cmd("LREM")
                        .arg(&processing_key)
                        .arg(1)
                        .arg(&job_json)
                        .query_async::<()>(&mut conn)
                        .await
                        .map_err(|e| {
                            TidewayError::internal(format!(
                                "Failed to remove job from processing: {}",
                                e
                            ))
                        })?;

                    // Optionally add to completed list (for history)
                    // redis::cmd("LPUSH").arg("jobs:completed").arg(&job_json).query_async(&mut conn).await?;

                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn fail(&self, job_id: &str, _error: String) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let processing_key = processing_key(&self.worker_id);

        // Find the job in processing list
        let jobs: Vec<String> = redis::cmd("LRANGE")
            .arg(&processing_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                TidewayError::internal(format!("Failed to list processing jobs: {}", e))
            })?;

        for job_json in jobs {
            if let Ok(mut job_data) = serde_json::from_str::<JobData>(&job_json) {
                if job_data.job_id == job_id {
                    // Remove from processing
                    redis::cmd("LREM")
                        .arg(&processing_key)
                        .arg(1)
                        .arg(&job_json)
                        .query_async::<()>(&mut conn)
                        .await
                        .map_err(|e| {
                            TidewayError::internal(format!(
                                "Failed to remove job from processing: {}",
                                e
                            ))
                        })?;

                    if job_data.should_retry() {
                        // Schedule retry with exponential backoff
                        let backoff_seconds =
                            self.retry_backoff_seconds * (2_u64.pow(job_data.retry_count));
                        let retry_at = Utc::now() + Duration::seconds(backoff_seconds as i64);

                        job_data.increment_retry();

                        let retry_json = serde_json::to_string(&job_data).map_err(|e| {
                            TidewayError::internal(format!(
                                "Failed to serialize job for retry: {}",
                                e
                            ))
                        })?;

                        // Add to scheduled set
                        redis::cmd("ZADD")
                            .arg(SCHEDULED_JOBS_KEY)
                            .arg(retry_at.timestamp())
                            .arg(&retry_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| {
                                TidewayError::internal(format!("Failed to schedule retry: {}", e))
                            })?;
                    } else {
                        // Max retries exceeded, move to failed
                        redis::cmd("LPUSH")
                            .arg("jobs:failed")
                            .arg(&job_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| {
                                TidewayError::internal(format!(
                                    "Failed to add to failed list: {}",
                                    e
                                ))
                            })?;
                    }

                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn retry(&self, job_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let processing_key = processing_key(&self.worker_id);

        // Find the job in processing list
        let jobs: Vec<String> = redis::cmd("LRANGE")
            .arg(&processing_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                TidewayError::internal(format!("Failed to list processing jobs: {}", e))
            })?;

        for job_json in jobs {
            if let Ok(mut job_data) = serde_json::from_str::<JobData>(&job_json) {
                if job_data.job_id == job_id {
                    // Remove from processing
                    redis::cmd("LREM")
                        .arg(&processing_key)
                        .arg(1)
                        .arg(&job_json)
                        .query_async::<()>(&mut conn)
                        .await
                        .map_err(|e| {
                            TidewayError::internal(format!(
                                "Failed to remove job from processing: {}",
                                e
                            ))
                        })?;

                    if job_data.should_retry() {
                        job_data.increment_retry();
                        let retry_json = serde_json::to_string(&job_data).map_err(|e| {
                            TidewayError::internal(format!(
                                "Failed to serialize job for retry: {}",
                                e
                            ))
                        })?;

                        // Re-enqueue to pending
                        redis::cmd("LPUSH")
                            .arg(PENDING_JOBS_KEY)
                            .arg(&retry_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| {
                                TidewayError::internal(format!("Failed to retry job: {}", e))
                            })?;
                    } else {
                        // Max retries exceeded
                        redis::cmd("LPUSH")
                            .arg("jobs:failed")
                            .arg(&job_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| {
                                TidewayError::internal(format!(
                                    "Failed to add to failed list: {}",
                                    e
                                ))
                            })?;
                    }

                    return Ok(());
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "jobs")]
    async fn schedule(&self, job: &dyn Job, run_at: DateTime<Utc>) -> Result<String> {
        let job_id = Uuid::new_v4().to_string();
        let payload = job.serialize()?;

        let job_data = JobData::scheduled(
            job_id.clone(),
            job.job_type().to_string(),
            payload,
            self.max_retries,
            run_at,
        );

        let job_json = serde_json::to_string(&job_data)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize job: {}", e)))?;

        let mut conn = self.get_connection().await?;
        redis::cmd("ZADD")
            .arg(SCHEDULED_JOBS_KEY)
            .arg(run_at.timestamp())
            .arg(&job_json)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to schedule job: {}", e)))?;

        Ok(job_id)
    }

    fn is_healthy(&self) -> bool {
        // Return cached health status from last ping() call
        // Call ping() periodically via a background task for accurate status
        self.health_status.load(Ordering::Acquire)
    }
}
