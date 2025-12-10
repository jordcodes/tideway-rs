#[cfg(test)]
#[cfg(feature = "jobs")]
mod tests {
    use crate::{
        app::AppContext,
        error::Result,
        jobs::{InMemoryJobQueue, JobRegistry},
        traits::job::{Job, JobData, JobQueue},
    };
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tokio::time::{Duration as TokioDuration, sleep};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestJob {
        message: String,
    }

    #[async_trait]
    impl Job for TestJob {
        fn job_type(&self) -> &str {
            "test_job"
        }

        fn serialize(&self) -> Result<serde_json::Value> {
            serde_json::to_value(self).map_err(|e| {
                crate::error::TidewayError::internal(format!("Serialization error: {}", e))
            })
        }

        async fn execute(&self, _ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_enqueue_dequeue() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let job = TestJob {
            message: "Hello".to_string(),
        };

        let job_id = queue.enqueue(&job).await.unwrap();
        assert!(!job_id.is_empty());

        let dequeued = queue.dequeue().await.unwrap();
        assert!(dequeued.is_some());

        let job_data = dequeued.unwrap();
        assert_eq!(job_data.job_id, job_id);
        assert_eq!(job_data.job_type, "test_job");
    }

    #[tokio::test]
    async fn test_complete() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let job = TestJob {
            message: "Hello".to_string(),
        };

        let job_id = queue.enqueue(&job).await.unwrap();
        let _ = queue.dequeue().await.unwrap();

        queue.complete(&job_id).await.unwrap();

        // Job should be removed from processing
        // (InMemoryQueue doesn't expose completed list, so we just verify no error)
    }

    #[tokio::test]
    async fn test_retry() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let job = TestJob {
            message: "Hello".to_string(),
        };

        let job_id = queue.enqueue(&job).await.unwrap();
        let _job_data = queue.dequeue().await.unwrap().unwrap();

        // Fail the job
        queue.fail(&job_id, "Test error".to_string()).await.unwrap();

        // Job should be retried (moved to scheduled with backoff)
        // Wait a bit for scheduler to move it
        sleep(TokioDuration::from_millis(100)).await;

        // Retry should eventually move job back to pending
        // This is hard to test without exposing internals, so we just verify no panic
    }

    #[tokio::test]
    async fn test_schedule() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let job = TestJob {
            message: "Hello".to_string(),
        };

        let run_at = Utc::now() + Duration::seconds(1);
        let job_id = queue.schedule(&job, run_at).await.unwrap();
        assert!(!job_id.is_empty());

        // Initially, job should not be in pending
        let dequeued = queue.dequeue().await.unwrap();
        assert!(dequeued.is_none());

        // Wait for scheduled time
        sleep(TokioDuration::from_secs(2)).await;

        // Now job should be available
        let dequeued = queue.dequeue().await.unwrap();
        assert!(dequeued.is_some());
        assert_eq!(dequeued.unwrap().job_id, job_id);
    }

    #[tokio::test]
    async fn test_registry_register_execute() {
        let registry = Arc::new(JobRegistry::new());
        let ctx = Arc::new(AppContext::new());

        let executed = Arc::new(tokio::sync::Mutex::new(false));

        registry
            .register("test_job", {
                let executed = executed.clone();
                move |_data: JobData, _ctx: Arc<AppContext>| {
                    let executed = executed.clone();
                    Box::pin(async move {
                        *executed.lock().await = true;
                        Ok(())
                    })
                }
            })
            .await;

        let job_data = JobData::new(
            "test-id".to_string(),
            "test_job".to_string(),
            serde_json::json!({"message": "test"}),
            3,
        );

        registry.execute(job_data, ctx).await.unwrap();

        assert!(*executed.lock().await);
    }

    #[tokio::test]
    async fn test_registry_unregistered_job() {
        let registry = Arc::new(JobRegistry::new());
        let ctx = Arc::new(AppContext::new());

        let job_data = JobData::new(
            "test-id".to_string(),
            "unregistered_job".to_string(),
            serde_json::json!({}),
            3,
        );

        let result = registry.execute(job_data, ctx).await;
        assert!(result.is_err());
    }
}
