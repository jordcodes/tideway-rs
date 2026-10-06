//! Background delivery of emails through the job system.

use crate::app::AppContext;
use crate::error::{Result, TidewayError};
use crate::jobs::JobRegistry;
use crate::traits::job::{Job, JobData};
use crate::traits::mailer::Email;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Job type identifier used by [`SendEmailJob`].
pub const SEND_EMAIL_JOB_TYPE: &str = "tideway.send_email";

/// Sends a pre-rendered [`Email`] using the worker's [`AppContext::mailer`].
///
/// Usually enqueued by [`LifecycleEmailer::queued`](super::LifecycleEmailer::queued).
/// Failures are retried by the job worker according to the queue's retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendEmailJob {
    pub email: Email,
}

impl SendEmailJob {
    pub fn new(email: Email) -> Self {
        Self { email }
    }

    fn from_job_data(data: &JobData) -> Result<Self> {
        serde_json::from_value(data.payload.clone())
            .map_err(|e| TidewayError::internal(format!("Invalid send_email job payload: {e}")))
    }
}

#[async_trait]
impl Job for SendEmailJob {
    fn job_type(&self) -> &str {
        SEND_EMAIL_JOB_TYPE
    }

    fn serialize(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self)
            .map_err(|e| TidewayError::internal(format!("Failed to serialize email job: {e}")))
    }

    async fn execute(&self, ctx: &AppContext) -> Result<()> {
        ctx.mailer()?.send(&self.email).await
    }
}

/// Register the handler for [`SendEmailJob`] so workers can deliver queued emails.
///
/// The worker's [`AppContext`] must have a mailer configured
/// (see [`AppContextBuilder::with_mailer`](crate::AppContextBuilder::with_mailer)).
pub async fn register_email_jobs(registry: &JobRegistry) {
    registry
        .register(
            SEND_EMAIL_JOB_TYPE,
            |data: JobData, ctx: Arc<AppContext>| {
                Box::pin(async move {
                    let job = SendEmailJob::from_job_data(&data)?;
                    job.execute(&ctx).await
                })
            },
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::{EmailBranding, LifecycleEmail, LifecycleEmailer};
    use crate::jobs::InMemoryJobQueue;
    use crate::traits::job::JobQueue;
    use crate::traits::mailer::Mailer;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingMailer(Mutex<Vec<Email>>);

    #[async_trait]
    impl Mailer for RecordingMailer {
        async fn send(&self, email: &Email) -> Result<()> {
            self.0.lock().unwrap().push(email.clone());
            Ok(())
        }

        fn is_healthy(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn queued_lifecycle_email_is_delivered_by_worker_not_caller() {
        let queue = Arc::new(InMemoryJobQueue::new(3, 60));
        let mailer = Arc::new(RecordingMailer::default());
        let emailer = LifecycleEmailer::queued(
            queue.clone(),
            "noreply@acme.test",
            EmailBranding::new("Acme"),
        );

        emailer
            .send(
                "user@example.com",
                &LifecycleEmail::verify_email(
                    "https://acme.test/verify?token=abc",
                    Duration::from_secs(86_400),
                ),
            )
            .await
            .unwrap();

        // Nothing is sent on the caller's path.
        assert!(mailer.0.lock().unwrap().is_empty());

        let data = queue.dequeue().await.unwrap().expect("email job enqueued");
        assert_eq!(data.job_type, SEND_EMAIL_JOB_TYPE);

        let registry = JobRegistry::new();
        register_email_jobs(&registry).await;
        let ctx = Arc::new(AppContext::builder().with_mailer(mailer.clone()).build());
        registry.execute(data, ctx).await.unwrap();

        let sent = mailer.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, vec!["user@example.com".to_string()]);
        assert_eq!(sent[0].subject, "Verify your Acme email");
        assert!(
            sent[0]
                .text
                .as_deref()
                .unwrap()
                .contains("https://acme.test/verify?token=abc")
        );
    }

    #[tokio::test]
    async fn worker_without_mailer_fails_so_job_is_retried() {
        let registry = JobRegistry::new();
        register_email_jobs(&registry).await;
        let job = SendEmailJob::new(Email::new("a@acme.test", "b@acme.test", "Hi").text("Hi"));
        let data = JobData::new(
            "id".into(),
            SEND_EMAIL_JOB_TYPE.into(),
            Job::serialize(&job).unwrap(),
            3,
        );
        assert!(
            registry
                .execute(data, Arc::new(AppContext::new()))
                .await
                .is_err()
        );
    }
}
