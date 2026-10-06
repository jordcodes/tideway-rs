//! OpenTelemetry trace export over OTLP/HTTP.
//!
//! Configured with the standard OpenTelemetry environment variables, so the same
//! settings work for any OTLP backend (an OpenTelemetry Collector, Honeycomb,
//! Grafana Tempo, Datadog, Sentry, ...):
//!
//! | Variable | Purpose |
//! |---|---|
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Enables export. OTLP/HTTP base URL, e.g. `http://localhost:4318` |
//! | `OTEL_EXPORTER_OTLP_HEADERS` | Auth headers, e.g. `x-honeycomb-team=KEY` |
//! | `OTEL_SERVICE_NAME` | Service name (defaults to the executable name) |
//! | `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, e.g. `deployment.environment=prod` |
//! | `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` | Sampling, e.g. `parentbased_traceidratio` / `0.1` |
//! | `OTEL_SDK_DISABLED` | `true` disables export |
//!
//! Only the `http/protobuf` protocol is supported. Point gRPC-only setups at the
//! collector's HTTP port (4318).

use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::sync::OnceLock;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::{EnvFilter, Layer, registry::LookupSpan};

const ENDPOINT_VARS: [&str; 2] = [
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
];

static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Returns `true` when the environment asks for OTLP trace export.
pub fn otlp_enabled_from_env() -> bool {
    let disabled = std::env::var("OTEL_SDK_DISABLED")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    !disabled
        && ENDPOINT_VARS.iter().any(|name| {
            std::env::var(name)
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
        })
}

/// Returns `true` once an OTLP exporter has been installed by `init_tracing*`.
pub(crate) fn is_active() -> bool {
    PROVIDER.get().is_some()
}

/// Build the OpenTelemetry subscriber layer when the environment enables export.
///
/// `directives` is the application's log filter. The layer also enables Tideway's
/// request spans (DEBUG level, target `tideway::request`) so every request becomes a
/// server span, without changing what the fmt layer prints.
pub(crate) fn build_layer<S>(directives: &str) -> Option<Box<dyn Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span> + Send + Sync,
{
    if !otlp_enabled_from_env() || PROVIDER.get().is_some() {
        return None;
    }

    if let Ok(protocol) = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL")
        && !protocol.trim().is_empty()
        && protocol.trim() != "http/protobuf"
    {
        eprintln!(
            "Warning: OTEL_EXPORTER_OTLP_PROTOCOL={protocol} is not supported by Tideway; exporting with http/protobuf"
        );
    }

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .build()
    {
        Ok(exporter) => exporter,
        Err(error) => {
            eprintln!("Warning: Failed to create OTLP trace exporter: {error}");
            return None;
        }
    };

    let mut resource = Resource::builder();
    if !service_name_configured()
        && let Some(name) = executable_name()
    {
        resource = resource.with_service_name(name);
    }

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource.build())
        .build();
    let tracer = provider.tracer("tideway");

    if PROVIDER.set(provider.clone()).is_err() {
        return None;
    }
    opentelemetry::global::set_tracer_provider(provider);
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let filter = EnvFilter::try_new(format!("{directives},tideway::request=debug"))
        .unwrap_or_else(|_| EnvFilter::new("info,tideway::request=debug"));

    Some(
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(filter)
            .boxed(),
    )
}

fn service_name_configured() -> bool {
    let named = |name: &str| {
        std::env::var(name)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    };
    named("OTEL_SERVICE_NAME")
        || std::env::var("OTEL_RESOURCE_ATTRIBUTES")
            .map(|attributes| {
                attributes
                    .split(',')
                    .any(|pair| pair.trim_start().starts_with("service.name="))
            })
            .unwrap_or(false)
}

fn executable_name() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.file_stem()?.to_string_lossy().into_owned())
}

/// Flush buffered spans and stop the exporter. Blocks until done.
pub(crate) fn shutdown() {
    if let Some(provider) = PROVIDER.get()
        && let Err(error) = provider.shutdown()
    {
        eprintln!("Warning: Failed to flush OpenTelemetry spans: {error}");
    }
}

/// Continue the caller's trace when the request carries a W3C `traceparent` header.
pub(crate) fn set_remote_parent(span: &tracing::Span, headers: &axum::http::HeaderMap) {
    if !is_active() || span.is_disabled() {
        return;
    }
    let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(headers))
    });
    let _ = span.set_parent(parent);
}

/// Hex trace ID of the current span, when it is being exported.
pub(crate) fn current_trace_id() -> Option<String> {
    use opentelemetry::trace::TraceContextExt as _;

    if !is_active() {
        return None;
    }
    let context = tracing::Span::current().context();
    let span = context.span();
    let span_context = span.span_context();
    span_context
        .is_valid()
        .then(|| span_context.trace_id().to_string())
}

/// Attach a server error to the current span as an OpenTelemetry exception event.
pub(crate) fn record_exception(error_id: &str, message: &str) {
    if !is_active() {
        return;
    }
    let span = tracing::Span::current();
    span.add_event(
        "exception",
        vec![
            opentelemetry::KeyValue::new("exception.type", "TidewayError"),
            opentelemetry::KeyValue::new("exception.message", message.to_owned()),
            opentelemetry::KeyValue::new("error.id", error_id.to_owned()),
        ],
    );
    span.set_status(opentelemetry::trace::Status::error(message.to_owned()));
}

/// Add W3C trace context headers for the current span to an outgoing request,
/// so downstream services join the same trace.
pub(crate) fn inject_trace_context(headers: &mut axum::http::HeaderMap) {
    if !is_active() {
        return;
    }
    let context = tracing::Span::current().context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(headers))
    });
}

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

struct HeaderInjector<'a>(&'a mut axum::http::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(key.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}
