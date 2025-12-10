//! Background Jobs Example
//!
//! Demonstrates how to define, register, and process background jobs
//! using Tideway's job system.

#[cfg(feature = "jobs")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use async_trait::async_trait;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tideway::{
        App, AppContext, ConfigBuilder, InMemoryJobQueue, Job, JobQueue, JobRegistry, Result, TidewayError,
    };

    // Initialize logging
    tideway::init_tracing();

    // Define a sample job
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

        async fn execute(&self, _ctx: &tideway::AppContext) -> Result<()> {
            tracing::info!(
                to = %self.to,
                subject = %self.subject,
                "Processing email job"
            );
            // Simulate email sending
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            tracing::info!("Email sent successfully");
            Ok(())
        }
    }

    // Create job queue and registry
    let queue = Arc::new(InMemoryJobQueue::new(3, 60));
    let registry = Arc::new(JobRegistry::new());

    // Register job handler
    registry
        .register("send_email", |data, ctx| {
            Box::pin(async move {
                let job: SendEmailJob = serde_json::from_value(data.payload).map_err(|e| {
                    TidewayError::internal(format!("Failed to deserialize job: {}", e))
                })?;
                job.execute(&ctx).await
            })
        })
        .await;

    // Create app context with job queue
    let ctx = AppContext::builder().with_job_queue(queue.clone()).build();

    // Create config
    let config = ConfigBuilder::new().with_log_level("info").build()?;

    // Create app with context and start workers
    let app = App::with_config(config)
        .with_context(ctx)
        .start_workers(registry);

    // Enqueue some jobs
    let job1 = SendEmailJob {
        to: "user1@example.com".to_string(),
        subject: "Welcome!".to_string(),
        body: "Thanks for signing up.".to_string(),
    };

    let job2 = SendEmailJob {
        to: "user2@example.com".to_string(),
        subject: "Reminder".to_string(),
        body: "Don't forget about our meeting.".to_string(),
    };

    let job_id1 = queue.enqueue(&job1).await?;
    let job_id2 = queue.enqueue(&job2).await?;

    tracing::info!(job_id = %job_id1, "Enqueued job 1");
    tracing::info!(job_id = %job_id2, "Enqueued job 2");

    println!("Background jobs example started!");
    println!("Two email jobs have been enqueued.");
    println!("Workers will process them in the background.");
    println!("Press Ctrl+C to stop...");

    // Start server (workers are already running)
    app.serve().await?;

    Ok(())
}

#[cfg(not(feature = "jobs"))]
fn main() {
    println!("This example requires the 'jobs' feature to be enabled.");
    println!("Run with: cargo run --example background_jobs --features jobs");
}
