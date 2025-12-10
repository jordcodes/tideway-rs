//! Redis-backed job queue implementation
//!
//! This implementation uses Redis lists and sorted sets for distributed
//! job processing. Multiple workers can compete for jobs from the same queue.

use crate::error::{Result, TidewayError};
use crate::traits::job::{Job, JobData, JobQueue};
use async_trait::async_trait;
#[cfg(feature = "jobs")]
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// Redis-backed job queue implementation
///
/// Uses Redis data structures:
/// - `jobs:pending` - List of jobs ready to be processed
/// - `jobs:processing:{worker_id}` - List of jobs being processed by a worker
/// - `jobs:scheduled` - Sorted set of scheduled jobs (score = timestamp)
/// - `jobs:failed` - List of permanently failed jobs
/// - `jobs:completed` - List of completed jobs (optional, for history)
#[derive(Clone)]
pub struct RedisJobQueue {
    client: redis::Client,
    worker_id: String,
    max_retries: u32,
    retry_backoff_seconds: u64,
    health: std::sync::Arc<std::sync::Mutex<bool>>,
}

impl RedisJobQueue {
    /// Create a new Redis job queue
    pub fn new(url: &str, worker_id: Option<String>, max_retries: u32, retry_backoff_seconds: u64) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| TidewayError::internal(format!("Failed to create Redis client: {}", e)))?;

        let worker_id = worker_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let queue = Self {
            client,
            worker_id,
            max_retries,
            retry_backoff_seconds,
            health: std::sync::Arc::new(std::sync::Mutex::new(true)),
        };

        // Start background task to move scheduled jobs to pending
        queue.start_scheduler_task();

        Ok(queue)
    }

    /// Get a Redis connection
    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to get Redis connection: {}", e)))
    }

    /// Start background task to move scheduled jobs to pending
    fn start_scheduler_task(&self) {
        let client = self.client.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            loop {
                interval.tick().await;

                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    let now = Utc::now().timestamp();

                    // Get all scheduled jobs with score <= now
                    let scheduled_key = "jobs:scheduled";
                    let results: redis::RedisResult<Vec<(String, f64)>> = redis::cmd("ZRANGEBYSCORE")
                        .arg(scheduled_key)
                        .arg("-inf")
                        .arg(now)
                        .arg("WITHSCORES")
                        .query_async(&mut conn)
                        .await;

                    if let Ok(jobs) = results {
                        for (job_json, _score) in jobs {
                            // Remove from scheduled set
                            let _: redis::RedisResult<()> = redis::cmd("ZREM")
                                .arg(scheduled_key)
                                .arg(&job_json)
                                .query_async(&mut conn)
                                .await;

                            // Add to pending list
                            let _: redis::RedisResult<()> = redis::cmd("LPUSH")
                                .arg("jobs:pending")
                                .arg(&job_json)
                                .query_async(&mut conn)
                                .await;
                        }
                    }
                }
            }
        });
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
            .arg("jobs:pending")
            .arg(&job_json)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to enqueue job: {}", e)))?;

        Ok(job_id)
    }

    async fn dequeue(&self) -> Result<Option<JobData>> {
        let mut conn = self.get_connection().await?;
        let processing_key = format!("jobs:processing:{}", self.worker_id);

        // Use BRPOPLPUSH for atomic move from pending to processing
        // This blocks for up to 5 seconds waiting for a job
        let result: Option<String> = redis::cmd("BRPOPLPUSH")
            .arg("jobs:pending")
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
        let processing_key = format!("jobs:processing:{}", self.worker_id);

        // Find and remove the job from processing list
        let jobs: Vec<String> = redis::cmd("LRANGE")
            .arg(&processing_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to list processing jobs: {}", e)))?;

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
                        .map_err(|e| TidewayError::internal(format!("Failed to remove job from processing: {}", e)))?;

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
        let processing_key = format!("jobs:processing:{}", self.worker_id);

        // Find the job in processing list
        let jobs: Vec<String> = redis::cmd("LRANGE")
            .arg(&processing_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to list processing jobs: {}", e)))?;

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
                        .map_err(|e| TidewayError::internal(format!("Failed to remove job from processing: {}", e)))?;

                    if job_data.should_retry() {
                        // Schedule retry with exponential backoff
                        let backoff_seconds = self.retry_backoff_seconds * (2_u64.pow(job_data.retry_count));
                        let retry_at = Utc::now() + Duration::seconds(backoff_seconds as i64);

                        job_data.increment_retry();

                        let retry_json = serde_json::to_string(&job_data)
                            .map_err(|e| TidewayError::internal(format!("Failed to serialize job for retry: {}", e)))?;

                        // Add to scheduled set
                        redis::cmd("ZADD")
                            .arg("jobs:scheduled")
                            .arg(retry_at.timestamp())
                            .arg(&retry_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| TidewayError::internal(format!("Failed to schedule retry: {}", e)))?;
                    } else {
                        // Max retries exceeded, move to failed
                        redis::cmd("LPUSH")
                            .arg("jobs:failed")
                            .arg(&job_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| TidewayError::internal(format!("Failed to add to failed list: {}", e)))?;
                    }

                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn retry(&self, job_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let processing_key = format!("jobs:processing:{}", self.worker_id);

        // Find the job in processing list
        let jobs: Vec<String> = redis::cmd("LRANGE")
            .arg(&processing_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to list processing jobs: {}", e)))?;

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
                        .map_err(|e| TidewayError::internal(format!("Failed to remove job from processing: {}", e)))?;

                    if job_data.should_retry() {
                        job_data.increment_retry();
                        let retry_json = serde_json::to_string(&job_data)
                            .map_err(|e| TidewayError::internal(format!("Failed to serialize job for retry: {}", e)))?;

                        // Re-enqueue to pending
                        redis::cmd("LPUSH")
                            .arg("jobs:pending")
                            .arg(&retry_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| TidewayError::internal(format!("Failed to retry job: {}", e)))?;
                    } else {
                        // Max retries exceeded
                        redis::cmd("LPUSH")
                            .arg("jobs:failed")
                            .arg(&job_json)
                            .query_async::<()>(&mut conn)
                            .await
                            .map_err(|e| TidewayError::internal(format!("Failed to add to failed list: {}", e)))?;
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
            .arg("jobs:scheduled")
            .arg(run_at.timestamp())
            .arg(&job_json)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to schedule job: {}", e)))?;

        Ok(job_id)
    }

    fn is_healthy(&self) -> bool {
        *self.health.lock().unwrap_or_else(|e| e.into_inner())
    }
}
