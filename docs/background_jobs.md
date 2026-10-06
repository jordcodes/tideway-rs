# Background Jobs

Tideway provides a trait-based background job system for processing async tasks independently of HTTP requests. Jobs can be enqueued immediately or scheduled for future execution, with automatic retry logic and support for distributed workers.

## Overview

The background job system consists of:

- **Job Trait**: Define jobs that implement `Job` trait
- **Job Queue**: Backend for storing and retrieving jobs (in-memory or Redis)
- **Job Registry**: Maps job types to handler functions
- **Workers**: Poll the queue and execute jobs
- **Scheduling**: Schedule jobs for future execution
- **Recurring jobs**: Enqueue jobs on cron schedules with a cross-instance lock

## Defining Jobs

Jobs must implement the `Job` trait:

```rust
use tideway::{Job, Result, AppContext};
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize)]
struct SendEmailJob {
    to: String,
    subject: String,
    body: String,
}

#[async_trait]
impl Job for SendEmailJob {
    fn job_type(&self) -> &str {
        "send_email"
    }

    fn serialize(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize job: {}", e)))
    }

    async fn execute(&self, ctx: &AppContext) -> Result<()> {
        // Send email logic here
        println!("Sending email to {}: {}", self.to, self.subject);
        Ok(())
    }
}
```

## Registering Job Handlers

Before jobs can be executed, register handlers in the `JobRegistry`:

```rust
use tideway::{JobRegistry, JobData, AppContext};
use std::sync::Arc;
use futures::future::BoxFuture;

let registry = Arc::new(JobRegistry::new());

registry.register("send_email", |data: JobData, ctx: Arc<AppContext>| {
    Box::pin(async move {
        let job: SendEmailJob = serde_json::from_value(data.payload)?;
        job.execute(&ctx).await
    })
});
```

## Enqueueing Jobs

Enqueue jobs for immediate processing:

```rust
use tideway::{AppContext, InMemoryJobQueue};
use std::sync::Arc;

let queue = Arc::new(InMemoryJobQueue::new(3, 60)); // max_retries, backoff_seconds
let ctx = AppContext::builder()
    .with_job_queue(queue.clone())
    .build();

let job = SendEmailJob {
    to: "user@example.com".to_string(),
    subject: "Hello".to_string(),
    body: "World".to_string(),
};

let job_id = queue.enqueue(&job).await?;
```

## Starting Workers

Start a worker pool to process jobs:

```rust
use tideway::{App, ConfigBuilder, InMemoryJobQueue, JobRegistry};
use std::sync::Arc;

let config = ConfigBuilder::new()
    .from_env()
    .build();

let queue = Arc::new(InMemoryJobQueue::new(3, 60));
let registry = Arc::new(JobRegistry::new());

// Register handlers
registry.register("send_email", |data, ctx| {
    Box::pin(async move {
        let job: SendEmailJob = serde_json::from_value(data.payload)?;
        job.execute(&ctx).await
    })
}).await;

let ctx = AppContext::builder()
    .with_job_queue(queue.clone())
    .build();

let app = App::with_config(config)
    .with_context(ctx)
    .start_workers(registry); // Start worker pool

app.serve().await?;
```

## Scheduling Jobs

Schedule jobs for future execution:

```rust
use chrono::{Utc, Duration};

let run_at = Utc::now() + Duration::hours(24);
let job_id = queue.schedule(&job, run_at).await?;
```

## Recurring Jobs (Cron)

`JobScheduler` enqueues an existing `Job` on a cron schedule. The job goes onto the normal queue
and is executed by workers through the `JobRegistry`, so recurring work needs no separate
definition: register the handler once, then add the job to the scheduler.

```rust
use std::sync::Arc;
use tideway::jobs::{InMemorySchedulerLock, JobScheduler};

let scheduler = JobScheduler::new(Arc::new(InMemorySchedulerLock::new()))
    // minute hour day-of-month month day-of-week (UTC)
    .add("trial_ending_reminders", "0 9 * * *", TrialEndingRemindersJob)?
    .add("sync_usage_to_stripe", "15 * * * *", SyncUsageJob)?
    .add("cleanup_expired_tokens", "30 3 * * *", CleanupExpiredTokensJob)?;

let app = App::with_config(config)
    .with_context(ctx)
    .start_workers(registry)
    .start_scheduler(scheduler);
```

- Expressions are evaluated in UTC. Five-field expressions are standard cron; six- or
  seven-field expressions add a leading seconds field and an optional trailing year.
- Schedule names must be unique. They identify an occurrence across instances.
- The job value is serialized and enqueued again for every occurrence.
- Occurrences missed while no instance was running are not backfilled.
- `App::start_scheduler` does nothing unless jobs are enabled and the context has a job queue. On
  the shutdown signal it stops enqueueing before workers drain.
- To manage the scheduler yourself, call `scheduler.start(queue)` and later
  `handle.shutdown().await`.

### Running multiple instances

Each instance can run the same scheduler. Before an occurrence is enqueued, the instance claims a
lock keyed by the schedule name and the occurrence time (`jobs:scheduler:lock:{name}:{unix_ts}`).
Only the instance that gets the lock enqueues the job. With Redis this is `SET key 1 NX PX ttl`:

```rust
let queue = Arc::new(RedisJobQueue::new(&redis_url, None, 3, 60)?);
let scheduler = JobScheduler::new(Arc::new(queue.scheduler_lock()))
    .add("cleanup_expired_tokens", "30 3 * * *", CleanupExpiredTokensJob)?;
// or: JobScheduler::new(Arc::new(RedisSchedulerLock::new(&redis_url)?))
```

`InMemorySchedulerLock` only excludes schedulers in the same process, so use it for
single-instance deployments and tests. Locks last for an hour by default
(`with_lock_ttl` changes this). That covers clock skew between instances. If the lock cannot
be acquired, for example because Redis is unreachable, the occurrence is skipped rather than
enqueued without the lock. Implement `SchedulerLock` to use another coordination backend.

## Redis Queue (Production)

For production deployments with multiple workers, use Redis:

```rust
use tideway::{RedisJobQueue, AppContext};
use std::sync::Arc;

let queue = Arc::new(
    RedisJobQueue::new(
        "redis://localhost:6379",
        None, // worker_id (auto-generated if None)
        3,    // max_retries
        60,   // retry_backoff_seconds
    )?
);

let ctx = AppContext::builder()
    .with_job_queue(queue.clone())
    .build();
```

## Configuration

Configure jobs via environment variables:

```bash
TIDEWAY_JOBS_ENABLED=true
TIDEWAY_JOBS_BACKEND=redis
TIDEWAY_JOBS_REDIS_URL=redis://localhost:6379
TIDEWAY_JOBS_WORKER_COUNT=4
TIDEWAY_JOBS_MAX_RETRIES=3
TIDEWAY_JOBS_RETRY_BACKOFF_SECONDS=60
TIDEWAY_JOBS_SHUTDOWN_TIMEOUT_SECONDS=25
```

Or programmatically:

```rust
use tideway::{ConfigBuilder, JobsConfig, JobBackend};

let config = ConfigBuilder::new()
    .with_jobs_config(
        JobsConfig {
            enabled: true,
            backend: JobBackend::Redis,
            redis_url: Some("redis://localhost:6379".to_string()),
            worker_count: 4,
            max_retries: 3,
            retry_backoff_seconds: 60,
            shutdown_timeout_seconds: 25,
        }
    )
    .build();
```

## Retry Logic

Failed jobs are automatically retried with exponential backoff:

- First retry: after `retry_backoff_seconds`
- Second retry: after `retry_backoff_seconds * 2`
- Third retry: after `retry_backoff_seconds * 4`
- And so on...

After `max_retries` attempts, jobs are moved to the failed queue.

## Railway Deployment

Railway provides Redis as an addon. To use it:

1. Add Redis addon to your Railway project
2. Set environment variables:
   ```bash
   TIDEWAY_JOBS_ENABLED=true
   TIDEWAY_JOBS_BACKEND=redis
   TIDEWAY_JOBS_REDIS_URL=${{REDIS_URL}}  # Railway sets this automatically
   TIDEWAY_JOBS_WORKER_COUNT=4
   ```

3. Multiple Railway instances will automatically share the job queue via Redis, enabling distributed processing.

## Graceful Shutdown

Workers automatically handle graceful shutdown:

- On shutdown signal (Ctrl+C or SIGTERM), workers finish processing their current job
- Workers finish any dequeue already in progress, including execution and acknowledgement of a claimed job, then stop taking new work
- Workers exit cleanly

The `App::serve()` method handles worker shutdown automatically. On the shutdown signal it stops accepting HTTP connections immediately and drains in-flight requests while workers finish their current jobs in parallel. Workers get at most `shutdown_timeout_seconds` (default 25, env `TIDEWAY_JOBS_SHUTDOWN_TIMEOUT_SECONDS`); jobs still running after that are aborted and left for the queue's retry/recovery handling, so keep handlers idempotent. Under Kubernetes, keep this timeout below `terminationGracePeriodSeconds` (default 30) so the process exits before SIGKILL.

When managing a worker pool directly, await `pool.shutdown_with_timeout(timeout)` (or `pool.shutdown()` to wait without a limit) before shutting down the queue so its retry scheduler and Redis heartbeat remain active while jobs finish.

Handler panics are treated as job failures and follow the same retry limits and backoff as returned errors, including with Redis. The worker continues processing jobs. This requires unwinding panics (the default Rust panic strategy); process aborts cannot be caught.

## Best Practices

1. **Idempotency**: Design jobs to be idempotent - they should be safe to retry
2. **Error Handling**: Return `Err` for transient failures, handle permanent failures in job logic
3. **Monitoring**: Log job execution and failures for monitoring
4. **Worker Count**: Set `worker_count` based on your workload (default: 4)
5. **Retry Limits**: Set appropriate `max_retries` based on job type

## Future Enhancements

Future versions may include:
- Job priorities (high/medium/low queues)
- Job result persistence
- Job progress tracking
- Dead letter queue for permanently failed jobs
- Cloud provider backends (AWS SQS, Google Cloud Tasks)
