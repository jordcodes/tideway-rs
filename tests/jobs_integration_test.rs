#[cfg(feature = "jobs")]
mod tests {
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tideway::{
        AppContext,
        jobs::{InMemoryJobQueue, JobRegistry, WorkerPool},
        traits::job::{Job, JobQueue},
    };
    use tokio::time::{Duration as TokioDuration, sleep};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestJob {
        message: String,
        should_fail: bool,
    }

    #[async_trait]
    impl Job for TestJob {
        fn job_type(&self) -> &str {
            "test_job"
        }

        fn serialize(&self) -> tideway::Result<serde_json::Value> {
            serde_json::to_value(self)
                .map_err(|e| tideway::TidewayError::internal(format!("Serialization error: {}", e)))
        }

        async fn execute(&self, _ctx: &tideway::AppContext) -> tideway::Result<()> {
            if self.should_fail {
                Err(tideway::TidewayError::internal("Job execution failed"))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_job_lifecycle_complete() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let job = TestJob {
            message: "Hello".to_string(),
            should_fail: false,
        };

        // Enqueue job
        let job_id = queue.enqueue(&job).await.unwrap();
        assert!(!job_id.is_empty());

        // Dequeue job
        let dequeued = queue.dequeue().await.unwrap();
        assert!(dequeued.is_some());
        let job_data = dequeued.unwrap();
        assert_eq!(job_data.job_id, job_id);
        assert_eq!(job_data.job_type, "test_job");

        // Complete job
        queue.complete(&job_id).await.unwrap();

        // Verify job is not in processing anymore
        let dequeued_again = queue.dequeue().await.unwrap();
        assert!(dequeued_again.is_none());
    }

    #[tokio::test]
    async fn test_job_retry_on_failure() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 1)); // 1 second backoff
        let job = TestJob {
            message: "Will fail".to_string(),
            should_fail: true,
        };

        let job_id = queue.enqueue(&job).await.unwrap();
        let _job_data = queue.dequeue().await.unwrap().unwrap();

        // Fail the job
        queue
            .fail(&job_id, "Test failure".to_string())
            .await
            .unwrap();

        // Job should be scheduled for retry
        // Wait for scheduler to move it back to pending
        sleep(TokioDuration::from_millis(1100)).await;

        // Job should be available again (retried)
        let retried = queue.dequeue().await.unwrap();
        assert!(retried.is_some());
        let retried_data = retried.unwrap();
        assert_eq!(retried_data.job_id, job_id);
        assert_eq!(retried_data.retry_count, 1);
    }

    #[tokio::test]
    async fn test_job_max_retries_exceeded() {
        let queue = Arc::new(InMemoryJobQueue::new(2, 1)); // Max 2 retries, 1 second backoff
        let job = TestJob {
            message: "Will fail".to_string(),
            should_fail: true,
        };

        let job_id = queue.enqueue(&job).await.unwrap();

        // Fail job multiple times to exceed max retries
        for _ in 0..3 {
            if let Some(_job_data) = queue.dequeue().await.unwrap() {
                queue
                    .fail(&job_id, "Test failure".to_string())
                    .await
                    .unwrap();
                sleep(TokioDuration::from_millis(1100)).await;
            }
        }

        // After max retries, job should not be available anymore
        let final_dequeue = queue.dequeue().await.unwrap();
        assert!(final_dequeue.is_none());
    }

    #[tokio::test]
    async fn test_scheduled_job_execution() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let job = TestJob {
            message: "Scheduled".to_string(),
            should_fail: false,
        };

        // Schedule job for 1 second in the future
        let run_at = Utc::now() + Duration::seconds(1);
        let job_id = queue.schedule(&job, run_at).await.unwrap();

        // Initially, job should not be available
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
    async fn test_job_worker_pool() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let registry = Arc::new(JobRegistry::new());
        let context = Arc::new(AppContext::new());

        // Register job handler
        registry
            .register("test_job", {
                move |data: tideway::JobData, ctx: std::sync::Arc<tideway::AppContext>| {
                    Box::pin(async move {
                        // Deserialize and execute
                        let job: TestJob = serde_json::from_value(data.payload).map_err(|e| {
                            tideway::TidewayError::internal(format!("Deserialize error: {}", e))
                        })?;
                        job.execute(&ctx).await
                    })
                }
            })
            .await;

        // Create worker pool (workers start automatically)
        let pool = WorkerPool::new(queue.clone(), registry.clone(), context.clone(), 2);

        // Enqueue a job
        let job = TestJob {
            message: "Worker test".to_string(),
            should_fail: false,
        };
        let _job_id = queue.enqueue(&job).await.unwrap();

        // Give workers time to process
        sleep(TokioDuration::from_millis(500)).await;

        // Job should be processed (completed)
        // Verify by checking it's not in processing anymore
        let dequeued = queue.dequeue().await.unwrap();
        assert!(dequeued.is_none());

        // Shutdown workers
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_registry_access_during_execution() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let registry = Arc::new(JobRegistry::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(2);
        let (finished_tx, mut finished_rx) = tokio::sync::mpsc::channel(2);

        registry
            .register("test_job", {
                let release = release.clone();
                move |data, _ctx| {
                    let release = release.clone();
                    let started_tx = started_tx.clone();
                    let finished_tx = finished_tx.clone();
                    Box::pin(async move {
                        started_tx.send(data.job_id.clone()).await.unwrap();
                        release.acquire().await.unwrap().forget();
                        finished_tx.send(data.job_id).await.unwrap();
                        Ok(())
                    })
                }
            })
            .await;

        let pool = WorkerPool::new(
            queue.clone(),
            registry.clone(),
            Arc::new(AppContext::new()),
            2,
        );
        let job = TestJob {
            message: "Concurrent worker test".to_string(),
            should_fail: false,
        };

        let result = tokio::time::timeout(TokioDuration::from_secs(3), async {
            let first_id = queue.enqueue(&job).await.unwrap();
            assert_eq!(started_rx.recv().await.unwrap(), first_id);

            // The first handler cannot finish until we release its permit below.
            // Registration must not wait for that handler to finish.
            registry
                .register("another_job", |_data, _ctx| Box::pin(async { Ok(()) }))
                .await;
            assert!(registry.is_registered("another_job").await);
            assert_eq!(registry.registered_types().await.len(), 2);

            let second_id = queue.enqueue(&job).await.unwrap();
            assert_eq!(started_rx.recv().await.unwrap(), second_id);
            assert!(finished_rx.try_recv().is_err());

            // Both workers have entered their handlers before either can finish.
            release.add_permits(2);
            let mut finished = vec![
                finished_rx.recv().await.unwrap(),
                finished_rx.recv().await.unwrap(),
            ];
            finished.sort();
            let mut expected = vec![first_id, second_id];
            expected.sort();
            assert_eq!(finished, expected);
        })
        .await;

        pool.shutdown().await;
        result.expect("registry access and concurrent jobs must not wait for running handlers");
    }

    #[tokio::test]
    async fn shutdown_finishes_current_job_without_starting_another() {
        let queue = Arc::new(InMemoryJobQueue::new(0, 0));
        let registry = Arc::new(JobRegistry::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(2);
        let (finished_tx, mut finished_rx) = tokio::sync::mpsc::channel(2);
        registry
            .register("test_job", {
                let release = release.clone();
                move |data, _| {
                    let release = release.clone();
                    let started_tx = started_tx.clone();
                    let finished_tx = finished_tx.clone();
                    Box::pin(async move {
                        started_tx.send(data.job_id.clone()).await.unwrap();
                        release.acquire().await.unwrap().forget();
                        finished_tx.send(data.job_id).await.unwrap();
                        Ok(())
                    })
                }
            })
            .await;
        let job = TestJob {
            message: "shutdown".into(),
            should_fail: false,
        };
        let first = queue.enqueue(&job).await.unwrap();
        let second = queue.enqueue(&job).await.unwrap();
        let pool = WorkerPool::new(queue.clone(), registry, Arc::new(AppContext::new()), 1);
        assert_eq!(started_rx.recv().await.unwrap(), first);
        let mut shutdown = Box::pin(pool.shutdown());
        assert!(
            tokio::time::timeout(TokioDuration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown must wait for the running handler"
        );
        release.add_permits(1);
        tokio::time::timeout(TokioDuration::from_secs(2), shutdown)
            .await
            .unwrap();
        assert_eq!(finished_rx.recv().await.unwrap(), first);
        assert_eq!(queue.dequeue().await.unwrap().unwrap().job_id, second);
        queue.shutdown().await;
    }

    // Exercise both a panic while constructing the future and a panic after yielding.
    async fn check_panic_retry(queue: Arc<dyn JobQueue>, synchronous: bool) {
        let registry = Arc::new(JobRegistry::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        registry
            .register("test_job", move |data, _| {
                let tx = tx.clone();
                if synchronous && data.retry_count == 0 {
                    panic!("handler construction panic");
                }
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    if data.retry_count == 0 {
                        panic!("handler execution panic");
                    }
                    tx.send((data.job_id, data.retry_count)).await.unwrap();
                    Ok(())
                })
            })
            .await;
        let job = TestJob {
            message: "panic".into(),
            should_fail: false,
        };
        let id = queue.enqueue(&job).await.unwrap();
        let pool = WorkerPool::new(queue.clone(), registry, Arc::new(AppContext::new()), 1);
        let result = tokio::time::timeout(TokioDuration::from_secs(8), rx.recv()).await;
        pool.shutdown().await;
        assert_eq!(
            result.expect("panicked job must be retried by the same worker"),
            Some((id, 1))
        );
    }

    #[tokio::test]
    async fn worker_survives_async_panic_and_retries() {
        let queue = Arc::new(InMemoryJobQueue::new(1, 0));
        check_panic_retry(queue.clone(), false).await;
        queue.shutdown().await;
    }

    #[tokio::test]
    async fn worker_survives_handler_construction_panic_and_retries() {
        let queue = Arc::new(InMemoryJobQueue::new(1, 0));
        check_panic_retry(queue.clone(), true).await;
        queue.shutdown().await;
    }

    #[cfg(feature = "jobs-redis")]
    #[tokio::test]
    #[ignore = "requires an isolated Redis database at TIDEWAY_TEST_REDIS_URL"]
    async fn redis_worker_retries_panics_and_errors() {
        let url = std::env::var("TIDEWAY_TEST_REDIS_URL").expect("isolated Redis URL required");
        let queue = Arc::new(tideway::jobs::RedisJobQueue::new(&url, None, 1, 0).unwrap());
        check_panic_retry(queue.clone(), false).await;
        check_panic_retry(queue.clone(), true).await;

        let registry = Arc::new(JobRegistry::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        registry
            .register("test_job", move |data, _| {
                let tx = tx.clone();
                Box::pin(async move {
                    if data.retry_count == 0 {
                        return Err(tideway::TidewayError::internal("retry me"));
                    }
                    tx.send(data.retry_count).await.unwrap();
                    Ok(())
                })
            })
            .await;
        queue
            .enqueue(&TestJob {
                message: "error".into(),
                should_fail: true,
            })
            .await
            .unwrap();
        let pool = WorkerPool::new(queue.clone(), registry, Arc::new(AppContext::new()), 1);
        let result = tokio::time::timeout(TokioDuration::from_secs(8), rx.recv()).await;
        pool.shutdown().await;
        queue.shutdown().await;
        assert_eq!(result.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn test_job_registry_execution() {
        let registry = Arc::new(JobRegistry::new());
        let context = Arc::new(AppContext::new());

        let executed = Arc::new(tokio::sync::Mutex::new(false));

        registry
            .register("test_job", {
                let executed = executed.clone();
                move |_data: tideway::JobData, _ctx: std::sync::Arc<tideway::AppContext>| {
                    let executed = executed.clone();
                    Box::pin(async move {
                        *executed.lock().await = true;
                        Ok(())
                    })
                }
            })
            .await;

        let job_data = tideway::JobData::new(
            "test-id".to_string(),
            "test_job".to_string(),
            serde_json::json!({"message": "test"}),
            3,
        );

        registry.execute(job_data, context).await.unwrap();

        assert!(*executed.lock().await);
    }

    #[tokio::test]
    async fn test_job_registry_unregistered_job_error() {
        let registry = Arc::new(JobRegistry::new());
        let context = Arc::new(AppContext::new());

        let job_data = tideway::JobData::new(
            "test-id".to_string(),
            "unregistered_job".to_string(),
            serde_json::json!({}),
            3,
        );

        let result = registry.execute(job_data, context).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unregistered"));
    }
}
