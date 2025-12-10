# Background Jobs

Tideway provides a trait-based background job system for processing async tasks independently of HTTP requests. Jobs can be enqueued immediately or scheduled for future execution, with automatic retry logic and support for distributed workers.

## Overview

The background job system consists of:

- **Job Trait**: Define jobs that implement `Job` trait
- **Job Queue**: Backend for storing and retrieving jobs (in-memory or Redis)
- **Job Registry**: Maps job types to handler functions
- **Workers**: Poll the queue and execute jobs
- **Scheduling**: Schedule jobs for future execution

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
- No new jobs are dequeued
- Workers exit cleanly

The `App::serve()` method handles worker shutdown automatically.

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
- Cron-style scheduling with cron expressions
