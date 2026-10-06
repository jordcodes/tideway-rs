//! Production observability: OpenTelemetry trace export and error reporting.
//!
//! # Traces (`otel` feature)
//!
//! With the `otel` feature, [`init_tracing`](crate::init_tracing) and
//! [`init_tracing_with_config`](crate::init_tracing_with_config) install an OTLP/HTTP
//! exporter whenever `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Every request becomes a
//! server span named after its route (`GET /users/{id}`), continuing the caller's
//! trace from a W3C `traceparent` header. Log events inside a request are attached
//! to its span, and 5xx errors mark the span as failed with an exception event, so
//! errors reach the tracing backend without an extra integration.
//! [`App::serve`](crate::App::serve) flushes buffered spans on shutdown; call
//! [`shutdown_tracing`] yourself when serving manually.
//!
//! See the `otel` submodule (or `docs/observability.md`) for the supported
//! environment variables.
//!
//! # Error reporting
//!
//! Register an [`ErrorReporter`] with
//! [`AppContextBuilder::with_error_reporter`](crate::AppContextBuilder::with_error_reporter)
//! to forward 5xx responses, panics and failed jobs to an error tracker such as
//! Sentry. See [`ErrorReporter`].
//!
//! # Sentry (`sentry` feature)
//!
//! With the `sentry` feature, setting `SENTRY_DSN` is enough: [`App`](crate::App)
//! registers a [`SentryReporter`] automatically when the context has no reporter,
//! and errors become Sentry issues linked to their OpenTelemetry trace. See
//! [`SentryReporter`].

mod error_reporting;
#[cfg(feature = "otel")]
pub mod otel;
#[cfg(feature = "sentry")]
mod sentry_reporter;

/// The `sentry` crate, re-exported so client options match Tideway's version.
#[cfg(feature = "sentry")]
pub use ::sentry;
#[cfg(feature = "jobs")]
pub(crate) use error_reporting::panic_message;
pub use error_reporting::{
    ErrorEvent, ErrorReporter, ErrorReportingLayer, ErrorReportingService, ErrorSource, JobInfo,
    RequestInfo,
};
#[cfg(feature = "otel")]
pub use otel::otlp_enabled_from_env;
#[cfg(feature = "sentry")]
pub use sentry_reporter::SentryReporter;

use axum::http::{HeaderMap, Request, Response};

/// Flush buffered trace spans and stop the exporter.
///
/// [`App::serve`](crate::App::serve) calls this after graceful shutdown. Call it
/// before exiting when you serve the router yourself or run a short-lived binary
/// such as a worker or CLI task. Blocks until the export finishes; from async code
/// wrap it in `tokio::task::spawn_blocking`. A no-op when nothing is exported.
pub fn shutdown_tracing() {
    #[cfg(feature = "otel")]
    otel::shutdown();
}

/// Add W3C trace context headers for the current span to an outgoing request so
/// the downstream service continues the same trace. A no-op when nothing is
/// exported.
pub fn inject_trace_context(headers: &mut HeaderMap) {
    #[cfg(feature = "otel")]
    otel::inject_trace_context(headers);
    #[cfg(not(feature = "otel"))]
    let _ = headers;
}

/// Record a 5xx `TidewayError` on the current trace span and error reporter.
pub(crate) fn on_server_error(status: axum::http::StatusCode, error_id: &str, message: String) {
    #[cfg(feature = "otel")]
    otel::record_exception(error_id, &message);
    error_reporting::report_error_response(status, error_id, message);
}

/// The reporter used when the application registers none: a [`SentryReporter`]
/// when the `sentry` feature is enabled and `SENTRY_DSN` is set.
pub(crate) fn default_error_reporter() -> Option<std::sync::Arc<dyn ErrorReporter>> {
    #[cfg(feature = "sentry")]
    {
        sentry_reporter::from_env_shared()
    }
    #[cfg(not(feature = "sentry"))]
    {
        None
    }
}

pub(crate) fn current_trace_id() -> Option<String> {
    #[cfg(feature = "otel")]
    {
        otel::current_trace_id()
    }
    #[cfg(not(feature = "otel"))]
    {
        None
    }
}

/// Build the span for one HTTP request.
///
/// The span is DEBUG level, so the default `info` log filter does not print it;
/// with the `otel` feature active the exporter enables it independently.
pub(crate) fn request_span<B>(request: &Request<B>) -> tracing::Span {
    let span = tracing::debug_span!(
        target: "tideway::request",
        "request",
        method = %request.method(),
        uri = %request.uri(),
        version = ?request.version(),
        request_id = ?request.headers().get("x-request-id"),
        otel.name = %request.method(),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.request.method = %request.method(),
        url.path = request.uri().path(),
        http.route = tracing::field::Empty,
        http.response.status_code = tracing::field::Empty,
    );
    #[cfg(feature = "otel")]
    otel::set_remote_parent(&span, request.headers());
    span
}

/// Record the response status on a request span.
pub(crate) fn record_response<B>(response: &Response<B>, span: &tracing::Span) {
    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
}

/// Whether request spans should be named after their matched route.
pub(crate) fn traces_routes() -> bool {
    #[cfg(feature = "otel")]
    {
        otel::is_active()
    }
    #[cfg(not(feature = "otel"))]
    {
        false
    }
}

/// Route-level middleware recording the matched route on the request span and
/// for error reports.
pub(crate) async fn record_route(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(route) = request.extensions().get::<axum::extract::MatchedPath>() {
        error_reporting::set_current_route(route.as_str());
        let span = tracing::Span::current();
        if !span.is_disabled() {
            span.record("http.route", route.as_str());
            span.record(
                "otel.name",
                format!("{} {}", request.method(), route.as_str()),
            );
        }
    }
    next.run(request).await
}
