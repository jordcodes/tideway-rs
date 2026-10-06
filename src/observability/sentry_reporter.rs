//! [`ErrorReporter`] that sends errors to Sentry as issues.

use super::{ErrorEvent, ErrorReporter, ErrorSource};
use sentry::protocol::{Context, Event, Exception, Level, Mechanism, TraceContext};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Sends Tideway [`ErrorEvent`]s to Sentry, where they become issues.
///
/// Each event carries the full internal message, a transaction named after the
/// route (`GET /users/{id}`) or job, and searchable tags: `error_id` (the ID
/// returned to the client), `http.status_code`, `request_id`, `job.id` and
/// `job.type`. With the `otel` feature exporting traces, the event's trace
/// context uses the request's OpenTelemetry trace ID, so Sentry links the issue
/// to the trace.
///
/// # Zero-code setup
///
/// Set `SENTRY_DSN` (and optionally `SENTRY_ENVIRONMENT` and `SENTRY_RELEASE`).
/// [`App`](crate::App) then registers a reporter automatically when the
/// [`AppContext`](crate::AppContext) has none, and [`App::serve`](crate::App::serve)
/// flushes it on shutdown. The client is also bound to Sentry's main hub, so
/// `sentry::capture_message` and friends in application code report to the same
/// project.
///
/// # Explicit setup
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use tideway::AppContext;
/// use tideway::observability::{SentryReporter, sentry};
///
/// let mut options = sentry::ClientOptions::new();
/// options.dsn = "https://key@o0.ingest.sentry.io/0".parse().ok();
/// options.environment = Some("production".into());
/// let reporter = SentryReporter::new(options);
/// let context = AppContext::builder()
///     .with_error_reporter(Arc::new(reporter))
///     .build();
/// ```
///
/// Apps that already call `sentry::init` can share that client with
/// [`SentryReporter::with_client`].
#[derive(Clone)]
pub struct SentryReporter {
    client: Arc<sentry::Client>,
}

impl SentryReporter {
    /// Create a reporter with its own client. Unset options fall back to
    /// Sentry's defaults and environment variables (`SENTRY_DSN`,
    /// `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE`).
    pub fn new(options: impl Into<sentry::ClientOptions>) -> Self {
        let options = sentry::apply_defaults(options.into());
        Self::with_client(Arc::new(sentry::Client::with_options(options)))
    }

    /// Report through an existing client, e.g. `sentry::Hub::current().client()`.
    pub fn with_client(client: Arc<sentry::Client>) -> Self {
        Self { client }
    }

    /// Create a reporter from `SENTRY_DSN`, or `None` when it is unset or invalid.
    ///
    /// The client is bound to Sentry's main hub unless one is already bound.
    pub fn from_env() -> Option<Self> {
        let dsn = std::env::var("SENTRY_DSN").ok()?;
        let dsn = dsn.trim();
        if dsn.is_empty() {
            return None;
        }
        let dsn = match dsn.parse::<sentry::types::Dsn>() {
            Ok(dsn) => dsn,
            Err(error) => {
                eprintln!("Warning: Ignoring invalid SENTRY_DSN: {error}");
                return None;
            }
        };
        let reporter = Self::new(dsn);
        let hub = sentry::Hub::main();
        if hub.client().is_none() {
            hub.bind_client(Some(reporter.client.clone()));
        }
        Some(reporter)
    }

    /// The underlying Sentry client.
    pub fn client(&self) -> &Arc<sentry::Client> {
        &self.client
    }
}

/// The process-wide reporter created from `SENTRY_DSN`, shared by every app.
pub(crate) fn from_env_shared() -> Option<Arc<dyn ErrorReporter>> {
    static REPORTER: OnceLock<Option<Arc<dyn ErrorReporter>>> = OnceLock::new();
    REPORTER
        .get_or_init(|| {
            SentryReporter::from_env().map(|reporter| Arc::new(reporter) as Arc<dyn ErrorReporter>)
        })
        .clone()
}

impl ErrorReporter for SentryReporter {
    fn report(&self, event: &ErrorEvent) {
        self.client.capture_event(to_sentry_event(event), None);
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.client.flush(Some(timeout))
    }
}

fn to_sentry_event(event: &ErrorEvent) -> Event<'static> {
    let mut sentry_event = Event {
        level: if event.panic {
            Level::Fatal
        } else {
            Level::Error
        },
        logger: Some("tideway".to_owned()),
        ..Default::default()
    };
    let tags = &mut sentry_event.tags;
    if let Some(error_id) = &event.error_id {
        tags.insert("error_id".to_owned(), error_id.clone());
    }
    if let Some(status) = event.status {
        tags.insert("http.status_code".to_owned(), status.to_string());
    }

    let ty = match &event.source {
        ErrorSource::Request(request) => {
            let target = request.route.as_deref().unwrap_or(&request.path);
            sentry_event.transaction = Some(format!("{} {target}", request.method));
            sentry_event.request = Some(sentry::protocol::Request {
                method: Some(request.method.clone()),
                ..Default::default()
            });
            tags.insert("http.method".to_owned(), request.method.clone());
            tags.insert("url.path".to_owned(), request.path.clone());
            if let Some(request_id) = &request.request_id {
                tags.insert("request_id".to_owned(), request_id.clone());
            }
            "ServerError"
        }
        ErrorSource::Job(job) => {
            sentry_event.transaction = Some(format!("job {}", job.job_type));
            tags.insert("job.id".to_owned(), job.id.clone());
            tags.insert("job.type".to_owned(), job.job_type.clone());
            "JobFailed"
        }
        ErrorSource::Other => "Error",
    };

    sentry_event.exception = vec![Exception {
        ty: if event.panic { "panic" } else { ty }.to_owned(),
        value: Some(event.message.clone()),
        mechanism: Some(Mechanism {
            ty: if event.panic { "panic" } else { "tideway" }.to_owned(),
            handled: Some(!event.panic),
            ..Default::default()
        }),
        ..Default::default()
    }]
    .into();

    if let Some(trace_id) = event.trace_id.as_deref().and_then(|id| id.parse().ok()) {
        sentry_event.contexts.insert(
            "trace".to_owned(),
            Context::Trace(Box::new(TraceContext {
                trace_id,
                ..Default::default()
            })),
        );
    }

    sentry_event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::JobInfo;

    #[test]
    fn trace_id_links_the_issue_to_its_trace() {
        let mut event = ErrorEvent::new("boom");
        event.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned());
        let sentry_event = to_sentry_event(&event);
        let Some(Context::Trace(trace)) = sentry_event.contexts.get("trace") else {
            panic!("missing trace context");
        };
        assert_eq!(
            trace.trace_id.to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
    }

    #[test]
    fn panics_are_fatal_and_unhandled() {
        let sentry_event =
            to_sentry_event(&ErrorEvent::new("Handler panicked: x").with_panic(true));
        assert_eq!(sentry_event.level, Level::Fatal);
        let exception = &sentry_event.exception.values[0];
        assert_eq!(exception.ty, "panic");
        assert_eq!(exception.mechanism.as_ref().unwrap().handled, Some(false));
    }

    #[test]
    fn jobs_are_named_and_tagged() {
        let event = ErrorEvent::new("smtp timeout")
            .with_source(ErrorSource::Job(JobInfo::new("job-1", "send_email")));
        let sentry_event = to_sentry_event(&event);
        assert_eq!(sentry_event.transaction.as_deref(), Some("job send_email"));
        assert_eq!(sentry_event.tags["job.id"], "job-1");
        assert_eq!(sentry_event.exception.values[0].ty, "JobFailed");
    }
}
