//! Error reporting hook for external error trackers (Sentry, Rollbar, Honeybadger, ...).
//!
//! Register an [`ErrorReporter`] on the [`AppContext`](crate::AppContext) and Tideway
//! reports, automatically:
//!
//! - every 5xx HTTP response, with the full internal error message that is hidden
//!   from clients in production, the `error_id` returned to the client, and request
//!   metadata
//! - handler panics (the panic still propagates afterwards, as without a reporter)
//! - failed and panicked background jobs (with the `jobs` feature)
//!
//! Client errors (4xx) are expected traffic and are not reported.

use axum::{
    body::Body,
    extract::Request,
    http::{Response, StatusCode},
};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tower::Service;

/// Receives errors that should be sent to an external error tracker.
///
/// `report` is called synchronously on the request or worker task, so
/// implementations must not block: hand the event to a non-blocking client or a
/// channel. Closures `Fn(&ErrorEvent)` implement this trait.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use tideway::AppContext;
/// use tideway::observability::{ErrorEvent, ErrorReporter};
///
/// struct SentryReporter;
///
/// impl ErrorReporter for SentryReporter {
///     fn report(&self, event: &ErrorEvent) {
///         // sentry::capture_message(&event.message, sentry::Level::Error);
///         let _ = event;
///     }
/// }
///
/// let context = AppContext::builder()
///     .with_error_reporter(Arc::new(SentryReporter))
///     .build();
/// ```
pub trait ErrorReporter: Send + Sync + 'static {
    /// Report a single error event.
    fn report(&self, event: &ErrorEvent);

    /// Wait up to `timeout` for queued reports to be delivered, returning `false`
    /// if some may be lost. [`App::serve`](crate::App::serve) calls this after
    /// graceful shutdown. Blocking; the default does nothing.
    fn flush(&self, timeout: std::time::Duration) -> bool {
        let _ = timeout;
        true
    }
}

impl<F> ErrorReporter for F
where
    F: Fn(&ErrorEvent) + Send + Sync + 'static,
{
    fn report(&self, event: &ErrorEvent) {
        self(event)
    }
}

/// An error captured by Tideway for reporting.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorEvent {
    /// Full internal error message. This is never sanitized: it may contain
    /// details that are hidden from clients in production.
    pub message: String,
    /// The `error_id` returned to the client, for correlating support tickets.
    pub error_id: Option<String>,
    /// HTTP status of the failed response, for request errors.
    pub status: Option<u16>,
    /// Whether the error was a panic.
    pub panic: bool,
    /// Where the error happened.
    pub source: ErrorSource,
    /// OpenTelemetry trace ID (32 hex chars) when trace export is active.
    pub trace_id: Option<String>,
}

impl ErrorEvent {
    /// Create an event for an error outside a request or job, e.g. in an
    /// application-spawned background task.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_id: None,
            status: None,
            panic: false,
            source: ErrorSource::Other,
            trace_id: super::current_trace_id(),
        }
    }

    /// Set the client-visible error ID.
    pub fn with_error_id(mut self, error_id: impl Into<String>) -> Self {
        self.error_id = Some(error_id.into());
        self
    }

    /// Set the HTTP status.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Mark the event as a panic.
    pub fn with_panic(mut self, panic: bool) -> Self {
        self.panic = panic;
        self
    }

    /// Set where the error happened.
    pub fn with_source(mut self, source: ErrorSource) -> Self {
        self.source = source;
        self
    }
}

/// Where a reported error happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ErrorSource {
    /// An HTTP request.
    Request(RequestInfo),
    /// A background job.
    Job(JobInfo),
    /// Anything else.
    Other,
}

/// Request metadata attached to request errors.
///
/// Only the path is captured: query strings, headers and bodies can carry
/// credentials and are never included.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RequestInfo {
    /// HTTP method.
    pub method: String,
    /// Request path, without the query string.
    pub path: String,
    /// Matched route template, e.g. `/users/{id}`, when the request was routed.
    pub route: Option<String>,
    /// The `x-request-id` header value.
    pub request_id: Option<String>,
}

/// Job metadata attached to job errors.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JobInfo {
    /// Job ID.
    pub id: String,
    /// Registered job type.
    pub job_type: String,
}

impl JobInfo {
    /// Create job metadata.
    pub fn new(id: impl Into<String>, job_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            job_type: job_type.into(),
        }
    }
}

struct RequestScope {
    reporter: Arc<dyn ErrorReporter>,
    request: RequestInfo,
    route: OnceLock<String>,
    reported: AtomicBool,
}

impl RequestScope {
    fn report(&self, event: ErrorEvent) {
        self.reported.store(true, Ordering::Relaxed);
        let mut request = self.request.clone();
        request.route = self.route.get().cloned();
        self.reporter
            .report(&event.with_source(ErrorSource::Request(request)));
    }
}

tokio::task_local! {
    static CURRENT_REQUEST_SCOPE: Arc<RequestScope>;
}

/// Remember the matched route for reports from the current request.
pub(crate) fn set_current_route(route: &str) {
    let _ = CURRENT_REQUEST_SCOPE.try_with(|scope| scope.route.set(route.to_owned()));
}

/// Report a 5xx `TidewayError` response produced inside an [`ErrorReportingLayer`].
pub(crate) fn report_error_response(status: StatusCode, error_id: &str, message: String) {
    let _ = CURRENT_REQUEST_SCOPE.try_with(|scope| {
        scope.report(
            ErrorEvent::new(message)
                .with_error_id(error_id)
                .with_status(status.as_u16()),
        );
    });
}

pub(crate) fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("unknown panic payload")
}

/// Layer that reports 5xx responses and panics to an [`ErrorReporter`].
///
/// [`App`](crate::App) installs this automatically when the context has an error
/// reporter; use it directly only with a custom middleware stack.
#[derive(Clone)]
pub struct ErrorReportingLayer {
    reporter: Arc<dyn ErrorReporter>,
}

impl ErrorReportingLayer {
    /// Create a layer that reports to `reporter`.
    pub fn new(reporter: Arc<dyn ErrorReporter>) -> Self {
        Self { reporter }
    }
}

impl<S> tower::Layer<S> for ErrorReportingLayer {
    type Service = ErrorReportingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ErrorReportingService {
            inner,
            reporter: self.reporter.clone(),
        }
    }
}

/// Service produced by [`ErrorReportingLayer`].
#[derive(Clone)]
pub struct ErrorReportingService<S> {
    inner: S,
    reporter: Arc<dyn ErrorReporter>,
}

impl<S> Service<Request> for ErrorReportingService<S>
where
    S: Service<Request, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let scope = Arc::new(RequestScope {
            reporter: self.reporter.clone(),
            request: RequestInfo {
                method: req.method().to_string(),
                path: req.uri().path().to_string(),
                request_id: req
                    .headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                route: None,
            },
            route: OnceLock::new(),
            reported: AtomicBool::new(false),
        });
        let future = CURRENT_REQUEST_SCOPE.scope(scope.clone(), self.inner.call(req));

        Box::pin(async move {
            match AssertUnwindSafe(future).catch_unwind().await {
                Ok(Ok(response)) => {
                    let status = response.status();
                    // Responses built from TidewayError were reported with their full
                    // message already; this catches 5xx responses built any other way.
                    if status.is_server_error() && !scope.reported.load(Ordering::Relaxed) {
                        scope.report(
                            ErrorEvent::new(format!("HTTP {status} response"))
                                .with_status(status.as_u16()),
                        );
                    }
                    Ok(response)
                }
                Ok(Err(error)) => Err(error),
                Err(panic) => {
                    scope.report(
                        ErrorEvent::new(format!(
                            "Handler panicked: {}",
                            panic_message(panic.as_ref())
                        ))
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR.as_u16())
                        .with_panic(true),
                    );
                    std::panic::resume_unwind(panic)
                }
            }
        })
    }
}
