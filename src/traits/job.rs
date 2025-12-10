//! Background job system traits
//!
//! This module defines traits for background job processing, allowing
//! users to enqueue and process async tasks independently of HTTP requests.

use crate::app::AppContext;
use crate::error::Result;
use async_trait::async_trait;
#[cfg(feature = "jobs")]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// A background job that can be executed asynchronously
///
/// Jobs implement this trait to define their execution logic.
/// The job must be serializable so it can be stored in queues.
#[async_trait]
#[allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds
pub trait Job: Send + Sync + Debug {
    /// Unique identifier for this job type (e.g., "send_email", "generate_report")
    fn job_type(&self) -> &str;

    /// Serialize the job payload to JSON
    fn serialize(&self) -> Result<serde_json::Value>;

    /// Execute the job with the given application context
    ///
    /// The context provides access to database, cache, sessions, etc.
    async fn execute(&self, ctx: &AppContext) -> Result<()>;
}

/// Job data structure for queue storage
///
/// This represents a job that has been enqueued, including
/// metadata like retry count and scheduling information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobData {
    /// Unique job identifier
    pub job_id: String,
    /// Job type identifier (matches `Job::job_type()`)
    pub job_type: String,
    /// Serialized job payload (JSON)
    pub payload: serde_json::Value,
    /// Current retry attempt count
    pub retry_count: u32,
    /// Maximum number of retries allowed
    pub max_retries: u32,
    /// When this job should be executed (None = immediate)
    #[cfg(feature = "jobs")]
    pub scheduled_at: Option<DateTime<Utc>>,
    /// Timestamp when job was created
    #[cfg(feature = "jobs")]
    pub created_at: DateTime<Utc>,
}

impl JobData {
    /// Create a new JobData instance
    #[cfg(feature = "jobs")]
    pub fn new(job_id: String, job_type: String, payload: serde_json::Value, max_retries: u32) -> Self {
        Self {
            job_id,
            job_type,
            payload,
            retry_count: 0,
            max_retries,
            scheduled_at: None,
            created_at: Utc::now(),
        }
    }

    /// Create a scheduled JobData instance
    #[cfg(feature = "jobs")]
    pub fn scheduled(
        job_id: String,
        job_type: String,
        payload: serde_json::Value,
        max_retries: u32,
        run_at: DateTime<Utc>,
    ) -> Self {
        Self {
            job_id,
            job_type,
            payload,
            retry_count: 0,
            max_retries,
            scheduled_at: Some(run_at),
            created_at: Utc::now(),
        }
    }

    /// Check if this job should be retried
    pub fn should_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    /// Increment retry count and return new count
    pub fn increment_retry(&mut self) -> u32 {
        self.retry_count += 1;
        self.retry_count
    }
}

/// Job queue trait for enqueueing and processing background jobs
///
/// Implementations provide different backends (in-memory, Redis, etc.)
/// but share the same interface for job management.
#[async_trait]
#[allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds
pub trait JobQueue: Send + Sync {
    /// Enqueue a job for immediate execution
    ///
    /// Returns the job ID that can be used to track the job.
    async fn enqueue(&self, job: &dyn Job) -> Result<String>;

    /// Dequeue the next available job
    ///
    /// Returns `None` if no jobs are available.
    /// The job should be moved to a "processing" state.
    async fn dequeue(&self) -> Result<Option<JobData>>;

    /// Mark a job as completed
    ///
    /// This removes the job from processing and may archive it.
    async fn complete(&self, job_id: &str) -> Result<()>;

    /// Mark a job as failed
    ///
    /// Stores the error message and determines if retry is needed.
    async fn fail(&self, job_id: &str, error: String) -> Result<()>;

    /// Retry a failed job
    ///
    /// Re-enqueues the job with incremented retry count.
    async fn retry(&self, job_id: &str) -> Result<()>;

    /// Schedule a job for future execution
    ///
    /// The job will be moved to the ready queue when `run_at` time arrives.
    #[cfg(feature = "jobs")]
    async fn schedule(&self, job: &dyn Job, run_at: DateTime<Utc>) -> Result<String>;

    /// Check if the queue is healthy and operational
    fn is_healthy(&self) -> bool;
}
