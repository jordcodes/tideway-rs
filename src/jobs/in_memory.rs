//! In-memory job queue implementation
//!
//! This implementation uses in-memory data structures and is suitable for
//! development, testing, and single-instance deployments.

use crate::error::Result;
use crate::traits::job::{Job, JobData, JobQueue};
use async_trait::async_trait;
#[cfg(feature = "jobs")]
use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Default maximum size for completed/failed job history
const DEFAULT_MAX_HISTORY_SIZE: usize = 10_000;

/// In-memory job queue implementation
///
/// This queue stores jobs in memory and is suitable for:
/// - Development and testing
/// - Single-instance deployments
/// - Jobs that don't need persistence across restarts
///
/// # Resource Limits
///
/// The completed and failed job lists are bounded to prevent unbounded memory growth.
/// By default, each list retains the most recent 10,000 jobs. Older entries are
/// automatically discarded when the limit is reached.
///
/// # Shutdown
///
/// Call `shutdown()` before dropping to cleanly stop background tasks.
#[derive(Clone)]
pub struct InMemoryJobQueue {
    pending: Arc<Mutex<VecDeque<JobData>>>,
    processing: Arc<Mutex<HashMap<String, JobData>>>,
    /// Bounded history of completed jobs (oldest removed when full)
    completed: Arc<Mutex<VecDeque<JobData>>>,
    /// Bounded history of failed jobs (oldest removed when full)
    failed: Arc<Mutex<VecDeque<JobData>>>,
    scheduled: Arc<Mutex<BTreeMap<DateTime<Utc>, Vec<JobData>>>>,
    max_retries: u32,
    retry_backoff_seconds: u64,
    /// Maximum size of completed/failed history lists
    max_history_size: usize,
    /// Cached health status
    health_status: Arc<AtomicBool>,
    /// Shutdown flag for background scheduler
    shutdown: Arc<AtomicBool>,
    /// Handle to scheduler task
    scheduler_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl InMemoryJobQueue {
    /// Create a new in-memory job queue
    pub fn new(max_retries: u32, retry_backoff_seconds: u64) -> Self {
        Self::with_history_limit(max_retries, retry_backoff_seconds, DEFAULT_MAX_HISTORY_SIZE)
    }

    /// Create a new in-memory job queue with custom history limit
    ///
    /// # Arguments
    ///
    /// * `max_retries` - Maximum retry attempts for failed jobs
    /// * `retry_backoff_seconds` - Base backoff duration (exponentially increased)
    /// * `max_history_size` - Maximum number of completed/failed jobs to retain
    pub fn with_history_limit(max_retries: u32, retry_backoff_seconds: u64, max_history_size: usize) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));

        let queue = Self {
            pending: Arc::new(Mutex::new(VecDeque::new())),
            processing: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(VecDeque::new())),
            failed: Arc::new(Mutex::new(VecDeque::new())),
            scheduled: Arc::new(Mutex::new(BTreeMap::new())),
            max_retries,
            retry_backoff_seconds,
            max_history_size,
            health_status: Arc::new(AtomicBool::new(true)),
            shutdown,
            scheduler_handle: Arc::new(Mutex::new(None)),
        };

        // Start background task to move scheduled jobs to pending
        queue.start_scheduler_task();

        queue
    }

    /// Gracefully shutdown the job queue
    ///
    /// Signals the background scheduler task to stop and waits for completion.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);

        let mut handle_guard = self.scheduler_handle.lock().await;
        if let Some(handle) = handle_guard.take() {
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                handle
            ).await {
                Ok(_) => tracing::debug!("In-memory job queue scheduler stopped cleanly"),
                Err(_) => tracing::warn!("In-memory job queue scheduler did not stop within timeout"),
            }
        }
    }

    /// Add job to bounded history, removing oldest if at capacity
    fn push_to_bounded_history(history: &mut VecDeque<JobData>, job: JobData, max_size: usize) {
        if history.len() >= max_size {
            history.pop_front(); // Remove oldest
        }
        history.push_back(job);
    }

    /// Start background task that moves scheduled jobs to pending queue
    fn start_scheduler_task(&self) {
        let scheduled = self.scheduled.clone();
        let pending = self.pending.clone();
        let shutdown = self.shutdown.clone();
        let scheduler_handle = self.scheduler_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

            loop {
                // Check shutdown before waiting
                if shutdown.load(Ordering::Acquire) {
                    tracing::debug!("In-memory job queue scheduler shutting down");
                    break;
                }

                interval.tick().await;

                // Check again after waking
                if shutdown.load(Ordering::Acquire) {
                    break;
                }

                let now = Utc::now();

                let mut scheduled_guard = scheduled.lock().await;
                let mut pending_guard = pending.lock().await;

                // Move all jobs scheduled for now or earlier to pending
                let keys_to_remove: Vec<DateTime<Utc>> = scheduled_guard
                    .iter()
                    .take_while(|(time, _)| **time <= now)
                    .map(|(time, _)| *time)
                    .collect();

                for key in keys_to_remove {
                    if let Some(jobs) = scheduled_guard.remove(&key) {
                        for job in jobs {
                            pending_guard.push_back(job);
                        }
                    }
                }
            }
        });

        // Store handle for cleanup - use try_lock since we're in sync context
        if let Ok(mut guard) = scheduler_handle.try_lock() {
            *guard = Some(handle);
        } else {
            handle.abort();
            tracing::error!("Failed to store scheduler handle");
        }
    }
}

#[async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn enqueue(&self, job: &dyn Job) -> Result<String> {
        let job_id = Uuid::new_v4().to_string();
        let payload = job.serialize()?;

        let job_data = JobData::new(
            job_id.clone(),
            job.job_type().to_string(),
            payload,
            self.max_retries,
        );

        let mut pending = self.pending.lock().await;
        pending.push_back(job_data);

        Ok(job_id)
    }

    async fn dequeue(&self) -> Result<Option<JobData>> {
        let mut pending = self.pending.lock().await;

        if let Some(job_data) = pending.pop_front() {
            let mut processing = self.processing.lock().await;
            processing.insert(job_data.job_id.clone(), job_data.clone());
            Ok(Some(job_data))
        } else {
            Ok(None)
        }
    }

    async fn complete(&self, job_id: &str) -> Result<()> {
        let mut processing = self.processing.lock().await;
        if let Some(job_data) = processing.remove(job_id) {
            let mut completed = self.completed.lock().await;
            Self::push_to_bounded_history(&mut completed, job_data, self.max_history_size);
        }
        Ok(())
    }

    async fn fail(&self, job_id: &str, _error: String) -> Result<()> {
        let mut processing = self.processing.lock().await;

        if let Some(mut job_data) = processing.remove(job_id) {
            if job_data.should_retry() {
                // Schedule retry with exponential backoff
                let backoff_seconds = self.retry_backoff_seconds * (2_u64.pow(job_data.retry_count));
                let retry_at = Utc::now() + Duration::seconds(backoff_seconds as i64);

                job_data.increment_retry();

                let mut scheduled = self.scheduled.lock().await;
                scheduled.entry(retry_at).or_insert_with(Vec::new).push(job_data);
            } else {
                // Max retries exceeded, move to failed (bounded)
                let mut failed = self.failed.lock().await;
                Self::push_to_bounded_history(&mut failed, job_data, self.max_history_size);
            }
        }

        Ok(())
    }

    async fn retry(&self, job_id: &str) -> Result<()> {
        let mut processing = self.processing.lock().await;

        if let Some(mut job_data) = processing.remove(job_id) {
            if job_data.should_retry() {
                job_data.increment_retry();
                let mut pending = self.pending.lock().await;
                pending.push_back(job_data);
            } else {
                let mut failed = self.failed.lock().await;
                Self::push_to_bounded_history(&mut failed, job_data, self.max_history_size);
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

        let mut scheduled = self.scheduled.lock().await;
        scheduled.entry(run_at).or_insert_with(Vec::new).push(job_data);

        Ok(job_id)
    }

    fn is_healthy(&self) -> bool {
        // Return cached health status (always true for in-memory queue)
        self.health_status.load(Ordering::Acquire)
    }
}

impl Default for InMemoryJobQueue {
    fn default() -> Self {
        Self::new(3, 60)
    }
}
