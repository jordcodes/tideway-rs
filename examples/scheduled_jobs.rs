//! Scheduled Jobs Example
//!
//! Demonstrates how to schedule jobs for future execution.

#[cfg(feature = "jobs")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tideway::{
        App, AppContext, ConfigBuilder, InMemoryJobQueue, Job, JobQueue, JobRegistry, Result, TidewayError,
    };
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    // Initialize logging
    tideway::init_tracing();

    // Define a sample job
    #[derive(Debug, Serialize, Deserialize)]
    struct GenerateReportJob {
        report_type: String,
        date_range: String,
    }

    #[async_trait]
    impl Job for GenerateReportJob {
        fn job_type(&self) -> &str {
            "generate_report"
        }

        fn serialize(&self) -> Result<serde_json::Value> {
            serde_json::to_value(self)
                .map_err(|e| TidewayError::internal(format!("Failed to serialize job: {}", e)))
        }

        async fn execute(&self, _ctx: &tideway::AppContext) -> Result<()> {
            tracing::info!(
                report_type = %self.report_type,
                date_range = %self.date_range,
                "Generating report"
            );
            // Simulate report generation
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            tracing::info!("Report generated successfully");
            Ok(())
        }
    }

    // Create job queue and registry
    let queue = Arc::new(InMemoryJobQueue::new(3, 60));
    let registry = Arc::new(JobRegistry::new());

    // Register job handler
    registry.register("generate_report", |data, ctx| {
        Box::pin(async move {
            let job: GenerateReportJob = serde_json::from_value(data.payload)
                .map_err(|e| TidewayError::internal(format!("Failed to deserialize job: {}", e)))?;
            job.execute(&ctx).await
        })
    }).await;

    // Create app context with job queue
    let ctx = AppContext::builder()
        .with_job_queue(queue.clone())
        .build();

    // Create config
    let config = ConfigBuilder::new()
        .with_log_level("info")
        .build()?;

    // Create app with context and start workers
    let app = App::with_config(config)
        .with_context(ctx)
        .start_workers(registry);

    // Schedule jobs for future execution
    let job1 = GenerateReportJob {
        report_type: "daily".to_string(),
        date_range: "2024-01-01".to_string(),
    };

    let job2 = GenerateReportJob {
        report_type: "weekly".to_string(),
        date_range: "2024-01-01 to 2024-01-07".to_string(),
    };

    // Schedule job1 to run in 5 seconds
    let run_at_1 = Utc::now() + Duration::seconds(5);
    let job_id1 = queue.schedule(&job1, run_at_1).await?;

    // Schedule job2 to run in 10 seconds
    let run_at_2 = Utc::now() + Duration::seconds(10);
    let job_id2 = queue.schedule(&job2, run_at_2).await?;

    tracing::info!(
        job_id = %job_id1,
        scheduled_at = %run_at_1,
        "Scheduled job 1"
    );
    tracing::info!(
        job_id = %job_id2,
        scheduled_at = %run_at_2,
        "Scheduled job 2"
    );

    println!("Scheduled jobs example started!");
    println!("Two report jobs have been scheduled:");
    println!("  - Job 1: Will run in 5 seconds");
    println!("  - Job 2: Will run in 10 seconds");
    println!("Workers will process them when scheduled.");
    println!("Press Ctrl+C to stop...");

    // Start server (workers are already running)
    app.serve().await?;

    Ok(())
}

#[cfg(not(feature = "jobs"))]
fn main() {
    println!("This example requires the 'jobs' feature to be enabled.");
    println!("Run with: cargo run --example scheduled_jobs --features jobs");
}
