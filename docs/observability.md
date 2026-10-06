# Observability

Tideway exports traces over OpenTelemetry (OTLP), reports errors to Sentry, and lets you plug
in any other error tracker through a hook. Prometheus metrics are covered in the README
(`metrics` feature).

## Traces with OpenTelemetry

Enable the `otel` feature:

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["otel"] }
```

Apps generated with the `api`, `saas`, and `worker` presets already enable it. Your app needs no
code changes. `init_tracing()` and `init_tracing_with_config()` install an OTLP/HTTP exporter
when `OTEL_EXPORTER_OTLP_ENDPOINT` is set, and `App::serve()` flushes buffered spans during
graceful shutdown.

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318   # OpenTelemetry Collector, Tempo, Jaeger
OTEL_SERVICE_NAME=my_app                            # defaults to the executable name
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production
```

Hosted backends need an endpoint and an auth header. Check your backend's OTLP documentation
for the exact values:

| Backend | Endpoint variable | Headers variable |
| --- | --- | --- |
| Honeycomb | `OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io` | `OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=<api key>` |
| Grafana Cloud | `OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-<zone>.grafana.net/otlp` | `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic%20<base64 instance:token>` |
| Sentry | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://o<org>.ingest.sentry.io/api/<project>/integration/otlp/v1/traces` | `OTEL_EXPORTER_OTLP_TRACES_HEADERS=x-sentry-auth=sentry sentry_key=<public key>` |

Sentry's endpoint and public key are under Project settings > Client Keys (DSN). Sentry's OTLP
ingestion drops span events, including the `exception` events Tideway records, so OTLP alone
shows traces in Sentry but does not create issues. Enable the `sentry` feature as well (see
[Sentry](#sentry)) to get issues linked to those traces.

Tideway honours the standard `OTEL_*` variables: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`,
`OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_TRACES_SAMPLER` with `OTEL_TRACES_SAMPLER_ARG` (for example
`parentbased_traceidratio` and `0.1`), and `OTEL_SDK_DISABLED=true`. Only the `http/protobuf`
protocol is supported. If your collector accepts only gRPC, use its HTTP port (4318) instead.

### What gets exported

- Each request becomes a server span named after its route, such as `GET /users/{id}`. Spans
  carry `http.request.method`, `http.route`, `url.path`, and `http.response.status_code`.
- An incoming W3C `traceparent` header is continued, so the request joins the caller's trace.
  To propagate the trace to services you call, use
  `tideway::observability::inject_trace_context(&mut headers)` on outgoing request headers.
- Log events emitted inside a request, including from your handlers, are attached to its span
  as span events.
- 5xx responses set the span status to error. A `TidewayError` also adds an `exception` event
  with the full internal message and the `error_id` returned to the client, so you can look up
  a support ticket's trace by its error ID.

Exporting does not change log output. Request spans use the DEBUG level, and the exporter
enables them through its own filter, so `RUST_LOG=info` prints the same lines as before.

### Custom subscribers

If your app builds its own `tracing_subscriber` stack, call `init_tracing*` only if the defaults
suit you. Otherwise add `tracing_opentelemetry::layer()` to your stack, and remember that the
request span target is `tideway::request` at DEBUG level. When serving the router yourself
(not with `App::serve`), call `tideway::shutdown_tracing()` from a blocking context before
exiting.

## Sentry

Enable the `sentry` feature and set the project DSN:

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["otel", "sentry"] }
```

```bash
SENTRY_DSN=https://<public key>@o<org>.ingest.sentry.io/<project>
SENTRY_ENVIRONMENT=production   # defaults to "production" in release builds
SENTRY_RELEASE=my_app@1.4.2     # optional
```

Generated `api`, `saas`, and `worker` apps already enable the feature, so setting `SENTRY_DSN`
is all they need. When the `AppContext` has no error reporter, `App` registers a
`SentryReporter` built from the environment, and `App::serve()` flushes it on shutdown. The
client is also bound to Sentry's main hub, so `sentry::capture_message` and similar calls in
your code report to the same project. The crate is re-exported as
`tideway::observability::sentry`.

Every error in the table below becomes a Sentry issue:

- The exception carries the full internal message. The transaction is the route
  (`GET /users/{id}`) or `job <type>`.
- Tags: `error_id` (the ID returned to the client, so you can search for a support ticket's
  issue), `http.status_code`, `http.method`, `url.path`, `request_id`, `job.id`, and `job.type`.
- Panics have level `fatal` and are marked unhandled.
- With `otel` exporting traces, the issue's trace context uses the request's trace ID, so
  Sentry links the issue to its trace. This works with any tracing backend, including
  Sentry's own OTLP endpoint.

To configure the client in code instead, register a reporter yourself:

```rust
use std::sync::Arc;
use tideway::observability::{SentryReporter, sentry};

let mut options = sentry::ClientOptions::new();
options.dsn = "https://key@o0.ingest.sentry.io/0".parse().ok();
options.sample_rate = 0.5;
let context = AppContext::builder()
    .with_error_reporter(Arc::new(SentryReporter::new(options)))
    .build();
```

If your app already calls `sentry::init`, use
`SentryReporter::with_client(sentry::Hub::current().client().unwrap())` to share its client.

## Error reporting

To use another error tracker, such as Rollbar or Honeybadger, register an `ErrorReporter`. A
closure works:

```rust
use std::sync::Arc;
use tideway::{AppContext, ErrorEvent};

let context = AppContext::builder()
    .with_error_reporter(Arc::new(|event: &ErrorEvent| {
        my_tracker::notify(&event.message, event.error_id.as_deref());
    }))
    .build();

App::new().with_context(context) /* ... */;
```

Tideway reports these automatically:

| Event | `ErrorEvent` contents |
| --- | --- |
| 5xx response from a `TidewayError` | full internal message (hidden from clients in production), `error_id`, status |
| Any other 5xx response | `HTTP <status> response`, status |
| Handler panic | panic message, `panic = true`. The panic still propagates as before. |
| Failed or panicked job (`jobs`) | error message, `ErrorSource::Job` with job ID and type |

Request events include `ErrorSource::Request`, which carries the method, the matched route,
the path without the query string, and `x-request-id`. When traces are exported, `trace_id` links the report to its
trace. 4xx responses are expected traffic and are not reported.

`report` runs on the request or worker task, so implementations must not block. Hand events to
a non-blocking client or a channel, and implement `flush` so `App::serve()` can deliver queued
events on shutdown. Report errors from your own
background tasks with `ctx.error_reporter_opt()` and `ErrorEvent::new(message)`.
