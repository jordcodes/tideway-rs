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
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// In-memory job queue implementation
///
/// This queue stores jobs in memory and is suitable for:
/// - Development and testing
/// - Single-instance deployments
/// - Jobs that don't need persistence across restarts
#[derive(Clone)]
pub struct InMemoryJobQueue {
    pending: Arc<Mutex<VecDeque<JobData>>>,
    processing: Arc<Mutex<HashMap<String, JobData>>>,
    completed: Arc<Mutex<Vec<JobData>>>,
    failed: Arc<Mutex<Vec<JobData>>>,
    scheduled: Arc<Mutex<BTreeMap<DateTime<Utc>, Vec<JobData>>>>,
    max_retries: u32,
    retry_backoff_seconds: u64,
    health: Arc<Mutex<bool>>,
}

impl InMemoryJobQueue {
    /// Create a new in-memory job queue
    pub fn new(max_retries: u32, retry_backoff_seconds: u64) -> Self {
        let queue = Self {
            pending: Arc::new(Mutex::new(VecDeque::new())),
            processing: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(Vec::new())),
            failed: Arc::new(Mutex::new(Vec::new())),
            scheduled: Arc::new(Mutex::new(BTreeMap::new())),
            max_retries,
            retry_backoff_seconds,
            health: Arc::new(Mutex::new(true)),
        };

        // Start background task to move scheduled jobs to pending
        queue.start_scheduler_task();

        queue
    }

    /// Start background task that moves scheduled jobs to pending queue
    fn start_scheduler_task(&self) {
        let scheduled = self.scheduled.clone();
        let pending = self.pending.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
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
            completed.push(job_data);
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
                // Max retries exceeded, move to failed
                let mut failed = self.failed.lock().await;
                failed.push(job_data);
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
                failed.push(job_data);
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
        *self.health.blocking_lock()
    }
}

impl Default for InMemoryJobQueue {
    fn default() -> Self {
        Self::new(3, 60)
    }
}
