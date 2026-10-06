//! Recurring (cron) job scheduler
//!
//! The scheduler enqueues ordinary [`Job`] values onto a [`JobQueue`] on a cron
//! schedule. Workers and the [`JobRegistry`](crate::jobs::JobRegistry) execute
//! them exactly like any other job, so recurring work needs no separate definition.
//!
//! Every instance of an application can run the same scheduler. Before enqueueing
//! an occurrence, each instance tries to claim a lock keyed by the schedule name and
//! the occurrence time through a [`SchedulerLock`]. Only the instance that wins the
//! claim enqueues the job; with [`RedisSchedulerLock`] this is a Redis `SET NX`, so
//! multiple instances never enqueue the same occurrence twice.

use crate::error::{Result, TidewayError};
use crate::traits::job::{Job, JobQueue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cron::Schedule;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// Key prefix used for per-occurrence scheduler locks.
pub const SCHEDULER_LOCK_KEY_PREFIX: &str = "jobs:scheduler:lock:";

/// Default lifetime of a claimed occurrence lock.
///
/// Locks are unique per occurrence, so this only needs to exceed the worst clock
/// skew between instances.
pub const DEFAULT_SCHEDULER_LOCK_TTL: Duration = Duration::from_secs(60 * 60);

/// Distributed lock used to elect a single instance per scheduled occurrence.
#[async_trait]
pub trait SchedulerLock: Send + Sync {
    /// Atomically claim `key` for `ttl`.
    ///
    /// Returns `true` if this caller claimed the key and `false` if another caller
    /// already holds it.
    async fn try_acquire(&self, key: &str, ttl: Duration) -> Result<bool>;
}

/// Process-local [`SchedulerLock`].
///
/// Suitable for single-instance deployments, development and tests. Schedulers
/// only exclude each other when they share the same lock instance; use
/// [`RedisSchedulerLock`] when running more than one process.
#[derive(Clone, Default)]
pub struct InMemorySchedulerLock {
    locks: Arc<Mutex<HashMap<String, std::time::Instant>>>,
}

impl InMemorySchedulerLock {
    /// Create an empty lock store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SchedulerLock for InMemorySchedulerLock {
    async fn try_acquire(&self, key: &str, ttl: Duration) -> Result<bool> {
        let now = std::time::Instant::now();
        let mut locks = self
            .locks
            .lock()
            .map_err(|_| TidewayError::internal("Scheduler lock store poisoned"))?;
        locks.retain(|_, expires_at| *expires_at > now);
        if locks.contains_key(key) {
            return Ok(false);
        }
        locks.insert(key.to_string(), now + ttl);
        Ok(true)
    }
}

/// Redis-backed [`SchedulerLock`] using `SET key value NX PX ttl`.
#[cfg(feature = "jobs-redis")]
#[derive(Clone)]
pub struct RedisSchedulerLock {
    connection: crate::redis_connection::SharedRedisConnection,
}

#[cfg(feature = "jobs-redis")]
impl RedisSchedulerLock {
    /// Create a lock backed by the Redis server at `url`.
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            connection: crate::redis_connection::SharedRedisConnection::new(url)?,
        })
    }

    pub(crate) fn from_connection(
        connection: crate::redis_connection::SharedRedisConnection,
    ) -> Self {
        Self { connection }
    }
}

#[cfg(feature = "jobs-redis")]
#[async_trait]
impl SchedulerLock for RedisSchedulerLock {
    async fn try_acquire(&self, key: &str, ttl: Duration) -> Result<bool> {
        let mut conn = self.connection.get().await?;
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1);
        let reply: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg("1")
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                TidewayError::internal(format!("Failed to acquire scheduler lock: {}", e))
            })?;
        Ok(reply.is_some())
    }
}

struct ScheduledEntry {
    name: String,
    schedule: Schedule,
    job: Arc<dyn Job>,
    next: Option<DateTime<Utc>>,
}

/// Enqueues jobs on cron schedules.
///
/// Cron expressions are evaluated in UTC. Standard five-field expressions
/// (`minute hour day-of-month month day-of-week`) are accepted, as are six- or
/// seven-field expressions with leading seconds and trailing year.
///
/// Occurrences missed while no instance was running are not backfilled.
///
/// # Example
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use tideway::jobs::{InMemoryJobQueue, InMemorySchedulerLock, JobScheduler};
/// # use tideway::{AppContext, Job, Result};
/// # #[derive(Debug)]
/// # struct CleanupExpiredTokens;
/// # #[async_trait::async_trait]
/// # impl Job for CleanupExpiredTokens {
/// #     fn job_type(&self) -> &str { "cleanup_expired_tokens" }
/// #     fn serialize(&self) -> Result<serde_json::Value> { Ok(serde_json::Value::Null) }
/// #     async fn execute(&self, _ctx: &AppContext) -> Result<()> { Ok(()) }
/// # }
///
/// # async fn example() -> Result<()> {
/// let queue = Arc::new(InMemoryJobQueue::new(3, 60));
/// let scheduler = JobScheduler::new(Arc::new(InMemorySchedulerLock::new()))
///     .add("cleanup_expired_tokens", "0 3 * * *", CleanupExpiredTokens)?;
/// let handle = scheduler.start(queue);
/// // ...
/// handle.shutdown().await;
/// # Ok(())
/// # }
/// ```
pub struct JobScheduler {
    entries: Vec<ScheduledEntry>,
    lock: Arc<dyn SchedulerLock>,
    lock_ttl: Duration,
}

impl JobScheduler {
    /// Create an empty scheduler that elects occurrences through `lock`.
    pub fn new(lock: Arc<dyn SchedulerLock>) -> Self {
        Self {
            entries: Vec::new(),
            lock,
            lock_ttl: DEFAULT_SCHEDULER_LOCK_TTL,
        }
    }

    /// Override how long a claimed occurrence lock is held.
    pub fn with_lock_ttl(mut self, ttl: Duration) -> Self {
        self.lock_ttl = ttl;
        self
    }

    /// Enqueue `job` on the cron schedule `cron`.
    ///
    /// `name` identifies the schedule across instances and must be unique within
    /// the scheduler. The job is serialized and enqueued afresh for every occurrence.
    pub fn add<J>(self, name: &str, cron: &str, job: J) -> Result<Self>
    where
        J: Job + 'static,
    {
        self.add_arc(name, cron, Arc::new(job))
    }

    /// Like [`add`](Self::add), for a job that is already shared.
    pub fn add_arc(mut self, name: &str, cron: &str, job: Arc<dyn Job>) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(TidewayError::bad_request("Schedule name must not be empty"));
        }
        if self.entries.iter().any(|entry| entry.name == name) {
            return Err(TidewayError::bad_request(format!(
                "Duplicate schedule name: {name}"
            )));
        }
        let schedule = parse_cron(cron)?;
        self.entries.push(ScheduledEntry {
            name: name.to_string(),
            schedule,
            job,
            next: None,
        });
        Ok(self)
    }

    /// Names of the registered schedules.
    pub fn names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }

    /// Whether any schedules are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Spawn the scheduler loop, enqueueing due jobs onto `queue`.
    pub fn start(mut self, queue: Arc<dyn JobQueue>) -> SchedulerHandle {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            tracing::info!(schedules = ?self.names(), "Job scheduler started");
            self.prime(Utc::now());
            loop {
                let Some(next) = self.next_occurrence() else {
                    tracing::warn!("No upcoming scheduled occurrences; job scheduler stopping");
                    break;
                };
                let wait = (next - Utc::now()).to_std().unwrap_or(Duration::ZERO);
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(wait) => {}
                }
                self.run_due(queue.as_ref(), Utc::now()).await;
            }
            tracing::info!("Job scheduler stopped");
        });
        SchedulerHandle {
            shutdown_tx,
            handle,
        }
    }

    /// Compute each schedule's first occurrence after `now`.
    fn prime(&mut self, now: DateTime<Utc>) {
        for entry in &mut self.entries {
            entry.next = entry.schedule.after(&now).next();
        }
    }

    fn next_occurrence(&self) -> Option<DateTime<Utc>> {
        self.entries.iter().filter_map(|entry| entry.next).min()
    }

    /// Enqueue every occurrence due at `now` that this instance wins the lock for.
    ///
    /// Returns the names of the schedules this instance enqueued.
    async fn run_due(&mut self, queue: &dyn JobQueue, now: DateTime<Utc>) -> Vec<String> {
        let mut enqueued = Vec::new();
        for entry in &mut self.entries {
            let Some(due) = entry.next.filter(|due| *due <= now) else {
                continue;
            };
            // Skip anything missed while busy rather than firing a burst of catch-up runs.
            entry.next = entry.schedule.after(&now).next();

            let key = format!(
                "{SCHEDULER_LOCK_KEY_PREFIX}{}:{}",
                entry.name,
                due.timestamp()
            );
            match self.lock.try_acquire(&key, self.lock_ttl).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::debug!(schedule = %entry.name, %due, "Occurrence claimed by another instance");
                    continue;
                }
                Err(error) => {
                    // Never enqueue without the lock; a duplicate run is worse than a skipped one.
                    tracing::error!(schedule = %entry.name, %due, %error, "Failed to acquire scheduler lock; skipping occurrence");
                    continue;
                }
            }

            match queue.enqueue(entry.job.as_ref()).await {
                Ok(job_id) => {
                    tracing::info!(schedule = %entry.name, %due, job_id = %job_id, "Enqueued scheduled job");
                    enqueued.push(entry.name.clone());
                }
                Err(error) => {
                    tracing::error!(schedule = %entry.name, %due, %error, "Failed to enqueue scheduled job");
                }
            }
        }
        enqueued
    }
}

/// Handle to a running [`JobScheduler`].
pub struct SchedulerHandle {
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl SchedulerHandle {
    /// Stop the scheduler and wait for its loop to exit.
    ///
    /// Jobs already enqueued are unaffected and still run on the workers.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.handle.await;
    }
}

/// Parse a cron expression, accepting the standard five-field form.
fn parse_cron(expression: &str) -> Result<Schedule> {
    let fields = expression.split_whitespace().count();
    let normalized = if fields == 5 {
        format!("0 {}", expression.trim())
    } else {
        expression.trim().to_string()
    };
    Schedule::from_str(&normalized).map_err(|e| {
        TidewayError::bad_request(format!("Invalid cron expression '{expression}': {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppContext;
    use crate::jobs::InMemoryJobQueue;
    use chrono::TimeZone;

    #[derive(Debug)]
    struct NightlyJob;

    #[async_trait]
    impl Job for NightlyJob {
        fn job_type(&self) -> &str {
            "nightly"
        }

        fn serialize(&self) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "kind": "nightly" }))
        }

        async fn execute(&self, _ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    struct FailingLock;

    #[async_trait]
    impl SchedulerLock for FailingLock {
        async fn try_acquire(&self, _key: &str, _ttl: Duration) -> Result<bool> {
            Err(TidewayError::internal("redis down"))
        }
    }

    fn at(h: u32, m: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, h, m, s).unwrap()
    }

    async fn drain(queue: &InMemoryJobQueue) -> Vec<String> {
        let mut types = Vec::new();
        while let Some(job) = queue.dequeue().await.unwrap() {
            types.push(job.job_type);
        }
        types
    }

    #[test]
    fn parses_five_and_six_field_expressions() {
        let five = parse_cron("0 3 * * *").unwrap();
        assert_eq!(five.after(&at(0, 0, 0)).next(), Some(at(3, 0, 0)));

        let six = parse_cron("*/10 * * * * *").unwrap();
        assert_eq!(six.after(&at(0, 0, 0)).next(), Some(at(0, 0, 10)));

        assert!(parse_cron("not a cron").is_err());
        assert!(parse_cron("61 * * * *").is_err());
    }

    #[test]
    fn rejects_duplicate_and_empty_names() {
        let lock = Arc::new(InMemorySchedulerLock::new());
        let scheduler = JobScheduler::new(lock.clone())
            .add("nightly", "0 3 * * *", NightlyJob)
            .unwrap();
        assert!(scheduler.add("nightly", "0 4 * * *", NightlyJob).is_err());
        assert!(
            JobScheduler::new(lock)
                .add(" ", "0 3 * * *", NightlyJob)
                .is_err()
        );
    }

    #[tokio::test]
    async fn enqueues_registered_job_on_each_cron_occurrence() {
        let queue = InMemoryJobQueue::new(3, 60);
        let mut scheduler = JobScheduler::new(Arc::new(InMemorySchedulerLock::new()))
            .add("nightly", "0 3 * * *", NightlyJob)
            .unwrap();
        scheduler.prime(at(0, 0, 0));

        assert!(scheduler.run_due(&queue, at(2, 59, 59)).await.is_empty());
        assert_eq!(
            scheduler.run_due(&queue, at(3, 0, 0)).await,
            vec!["nightly"]
        );
        // Same occurrence is not fired twice by the same instance.
        assert!(scheduler.run_due(&queue, at(3, 0, 1)).await.is_empty());
        assert_eq!(drain(&queue).await, vec!["nightly"]);

        // The next day's occurrence fires again (recurring, not one-shot).
        let next_day = Utc.with_ymd_and_hms(2026, 1, 2, 3, 0, 0).unwrap();
        assert_eq!(scheduler.next_occurrence(), Some(next_day));
        assert_eq!(scheduler.run_due(&queue, next_day).await, vec!["nightly"]);
        assert_eq!(drain(&queue).await, vec!["nightly"]);
    }

    #[tokio::test]
    async fn shared_lock_allows_only_one_instance_per_occurrence() {
        let queue = InMemoryJobQueue::new(3, 60);
        let lock: Arc<dyn SchedulerLock> = Arc::new(InMemorySchedulerLock::new());
        let mut instances: Vec<JobScheduler> = (0..3)
            .map(|_| {
                let mut scheduler = JobScheduler::new(lock.clone())
                    .add("nightly", "0 3 * * *", NightlyJob)
                    .unwrap();
                scheduler.prime(at(0, 0, 0));
                scheduler
            })
            .collect();

        let mut winners = 0;
        for (i, scheduler) in instances.iter_mut().enumerate() {
            // Instances observe the occurrence at slightly different wall-clock times.
            winners += scheduler.run_due(&queue, at(3, 0, i as u32)).await.len();
        }
        assert_eq!(winners, 1);
        assert_eq!(drain(&queue).await, vec!["nightly"]);
    }

    #[tokio::test]
    async fn lock_failure_skips_occurrence_instead_of_running_unguarded() {
        let queue = InMemoryJobQueue::new(3, 60);
        let mut scheduler = JobScheduler::new(Arc::new(FailingLock))
            .add("nightly", "0 3 * * *", NightlyJob)
            .unwrap();
        scheduler.prime(at(0, 0, 0));

        assert!(scheduler.run_due(&queue, at(3, 0, 0)).await.is_empty());
        assert!(drain(&queue).await.is_empty());
    }

    #[tokio::test]
    async fn in_memory_lock_expires_after_ttl() {
        let lock = InMemorySchedulerLock::new();
        assert!(
            lock.try_acquire("k", Duration::from_millis(20))
                .await
                .unwrap()
        );
        assert!(
            !lock
                .try_acquire("k", Duration::from_millis(20))
                .await
                .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            lock.try_acquire("k", Duration::from_millis(20))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn running_instances_enqueue_each_tick_once() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let lock: Arc<dyn SchedulerLock> = Arc::new(InMemorySchedulerLock::new());
        let handles: Vec<_> = (0..2)
            .map(|_| {
                JobScheduler::new(lock.clone())
                    .add("every_second", "* * * * * *", NightlyJob)
                    .unwrap()
                    .start(queue.clone())
            })
            .collect();

        tokio::time::sleep(Duration::from_millis(2_500)).await;
        for handle in handles {
            handle.shutdown().await;
        }

        let fired = drain(&queue).await.len();
        // Two or three ticks elapse in 2.5s; two instances must not double that.
        assert!((2..=3).contains(&fired), "fired {fired} times");
    }
}
