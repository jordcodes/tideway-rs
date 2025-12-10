//! Job worker system for processing background jobs
//!
//! Workers poll the job queue and execute jobs using registered handlers.

use crate::app::AppContext;
use crate::error::Result;
use crate::jobs::registry::JobRegistry;
use crate::traits::job::JobQueue;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// A single worker that processes jobs from a queue
pub struct JobWorker {
    queue: Arc<dyn JobQueue>,
    registry: Arc<JobRegistry>,
    ctx: Arc<AppContext>,
    worker_id: String,
    shutdown_tx: mpsc::Sender<()>,
}

impl JobWorker {
    /// Create a new job worker
    pub fn new(
        queue: Arc<dyn JobQueue>,
        registry: Arc<JobRegistry>,
        ctx: Arc<AppContext>,
        worker_id: String,
    ) -> (Self, mpsc::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        (
            Self {
                queue,
                registry,
                ctx,
                worker_id,
                shutdown_tx,
            },
            shutdown_rx,
        )
    }

    /// Start the worker and begin processing jobs
    ///
    /// This runs until shutdown is requested via the shutdown channel.
    pub async fn start(self, mut shutdown_rx: mpsc::Receiver<()>) {
        tracing::info!(worker_id = %self.worker_id, "Job worker started");

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!(worker_id = %self.worker_id, "Shutdown signal received, finishing current job...");
                    break;
                }
                result = self.process_next_job() => {
                    match result {
                        Ok(Some(_)) => {
                            // Job processed successfully, continue immediately
                        }
                        Ok(None) => {
                            // No job available, wait a bit before polling again
                            tokio::select! {
                                _ = shutdown_rx.recv() => break,
                                _ = sleep(Duration::from_millis(100)) => {},
                            }
                        }
                        Err(e) => {
                            tracing::error!(worker_id = %self.worker_id, error = %e, "Error processing job");
                            // Wait before retrying
                            tokio::select! {
                                _ = shutdown_rx.recv() => break,
                                _ = sleep(Duration::from_secs(1)) => {},
                            }
                        }
                    }
                }
            }
        }

        tracing::info!(worker_id = %self.worker_id, "Job worker stopped");
    }

    /// Process the next available job from the queue
    async fn process_next_job(&self) -> Result<Option<String>> {
        // Dequeue a job
        let job_data = match self.queue.dequeue().await? {
            Some(data) => data,
            None => return Ok(None),
        };

        let job_id = job_data.job_id.clone();
        tracing::debug!(
            worker_id = %self.worker_id,
            job_id = %job_id,
            job_type = %job_data.job_type,
            "Processing job"
        );

        // Execute the job
        match self.registry.execute(job_data, self.ctx.clone()).await {
            Ok(()) => {
                // Job completed successfully
                self.queue.complete(&job_id).await?;
                tracing::info!(
                    worker_id = %self.worker_id,
                    job_id = %job_id,
                    "Job completed successfully"
                );
                Ok(Some(job_id))
            }
            Err(e) => {
                // Job failed, let the queue handle retry logic
                let error_msg = format!("{}", e);
                self.queue.fail(&job_id, error_msg).await?;
                tracing::warn!(
                    worker_id = %self.worker_id,
                    job_id = %job_id,
                    error = %e,
                    "Job failed"
                );
                Ok(Some(job_id))
            }
        }
    }

    /// Request shutdown of this worker
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}

/// Pool of workers that process jobs concurrently
pub struct WorkerPool {
    workers: Vec<tokio::task::JoinHandle<()>>,
    shutdown_txs: Vec<mpsc::Sender<()>>,
}

impl WorkerPool {
    /// Create a new worker pool
    pub fn new(
        queue: Arc<dyn JobQueue>,
        registry: Arc<JobRegistry>,
        ctx: Arc<AppContext>,
        worker_count: usize,
    ) -> Self {
        let mut workers = Vec::new();
        let mut shutdown_txs = Vec::new();

        for i in 0..worker_count {
            let worker_id = format!("worker-{}", i);
            let (worker, shutdown_rx) = JobWorker::new(
                queue.clone(),
                registry.clone(),
                ctx.clone(),
                worker_id.clone(),
            );
            let shutdown_tx = worker.shutdown_tx.clone();

            let handle = tokio::spawn(async move {
                worker.start(shutdown_rx).await;
            });

            workers.push(handle);
            shutdown_txs.push(shutdown_tx);
        }

        Self {
            workers,
            shutdown_txs,
        }
    }

    /// Shutdown all workers gracefully
    ///
    /// Sends shutdown signals to all workers and waits for them to finish
    /// processing their current jobs.
    pub async fn shutdown(self) {
        tracing::info!("Shutting down worker pool...");

        // Send shutdown signals to all workers
        for shutdown_tx in self.shutdown_txs {
            let _ = shutdown_tx.send(()).await;
        }

        // Wait for all workers to finish
        for worker in self.workers {
            let _ = worker.await;
        }

        tracing::info!("Worker pool shut down");
    }
}
