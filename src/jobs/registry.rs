//! Job registry for mapping job types to handler functions
//!
//! The registry maintains a mapping from job type strings to handler functions
//! that can deserialize and execute jobs.

use crate::app::AppContext;
use crate::error::{Result, TidewayError};
use crate::traits::job::JobData;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for job handler functions
///
/// Handlers receive the `JobData` (with serialized payload) and `AppContext`,
/// and are responsible for deserializing the payload and executing the job.
type JobHandler = Arc<dyn Fn(JobData, Arc<AppContext>) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Registry for mapping job types to their handlers
///
/// Before jobs can be executed, they must be registered with their handler functions.
/// The registry is thread-safe and can be shared across workers.
#[derive(Clone)]
pub struct JobRegistry {
    handlers: Arc<tokio::sync::RwLock<HashMap<String, JobHandler>>>,
}

impl JobRegistry {
    /// Create a new empty job registry
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Register a job type with its handler function
    ///
    /// The handler receives the `JobData` (with serialized payload) and `AppContext`.
    /// It should deserialize the payload into the concrete job type and execute it.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// registry.register("send_email", |data, ctx| {
    ///     Box::pin(async move {
    ///         let job: SendEmailJob = serde_json::from_value(data.payload)?;
    ///         job.execute(&ctx).await
    ///     })
    /// }).await;
    /// ```
    pub async fn register<F>(&self, job_type: &str, handler: F)
    where
        F: Fn(JobData, Arc<AppContext>) -> BoxFuture<'static, Result<()>> + Send + Sync + 'static,
    {
        let handler: JobHandler = Arc::new(handler);
        let mut handlers = self.handlers.write().await;
        handlers.insert(job_type.to_string(), handler);
    }

    /// Execute a job by looking up its handler
    ///
    /// Returns an error if the job type is not registered.
    pub async fn execute(&self, data: JobData, ctx: Arc<AppContext>) -> Result<()> {
        let handlers = self.handlers.read().await;
        let handler = handlers.get(&data.job_type)
            .ok_or_else(|| TidewayError::internal(format!("No handler registered for job type: {}", data.job_type)))?;

        handler(data, ctx).await
    }

    /// Check if a job type is registered
    pub async fn is_registered(&self, job_type: &str) -> bool {
        let handlers = self.handlers.read().await;
        handlers.contains_key(job_type)
    }

    /// Get all registered job types
    pub async fn registered_types(&self) -> Vec<String> {
        let handlers = self.handlers.read().await;
        handlers.keys().cloned().collect()
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}
