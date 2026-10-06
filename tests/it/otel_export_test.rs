//! End-to-end OTLP export: runs in its own child process because it installs the
//! global subscriber and tracer provider from the environment, like a real app.

use axum::{Router, body::Bytes, extract::State, routing::get, routing::post};
use std::sync::{Arc, Mutex};
use tideway::observability::ErrorEvent;
use tideway::{App, AppContext, Config, RouteModule, TidewayError};

struct Routes;

impl RouteModule for Routes {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route(
            "/users/{id}",
            get(|| async { Err::<(), _>(TidewayError::internal("replica lag exceeded")) }),
        )
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_are_exported_as_otlp_server_spans_with_errors() {
    if crate::support::isolated(
        module_path!(),
        "requests_are_exported_as_otlp_server_spans_with_errors",
        |_| {},
    ) {
        return;
    }
    // Mock OTLP/HTTP collector.
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let collector = Router::new()
        .route(
            "/v1/traces",
            post(
                |State(received): State<Arc<Mutex<Vec<u8>>>>, body: Bytes| async move {
                    received.lock().unwrap().extend_from_slice(&body);
                },
            ),
        )
        .with_state(received.clone());
    let collector_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let collector_addr = collector_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(collector_listener, collector).await });

    // SAFETY: this child process runs only this test, and nothing else reads the
    // environment concurrently.
    unsafe {
        std::env::set_var(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://{collector_addr}"),
        );
        std::env::set_var("OTEL_SERVICE_NAME", "otel-export-test");
    }
    assert!(tideway::observability::otlp_enabled_from_env());
    tideway::init_tracing();

    let reported: Arc<Mutex<Vec<ErrorEvent>>> = Arc::default();
    let context = AppContext::builder()
        .with_error_reporter(Arc::new({
            let reported = reported.clone();
            move |event: &ErrorEvent| reported.lock().unwrap().push(event.clone())
        }))
        .build();
    let mut config = Config::default();
    config.dev.enabled = false;
    let app = App::with_config(config)
        .with_context(context)
        .register_module(Routes)
        .into_router_with_middleware();
    let app_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(app_listener, app).await });

    // The caller's trace context must be continued.
    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let response = reqwest::Client::new()
        .get(format!("http://{app_addr}/users/42"))
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    tokio::task::spawn_blocking(tideway::shutdown_tracing)
        .await
        .unwrap();

    let body = received.lock().unwrap().clone();
    assert!(!body.is_empty(), "no spans were exported");
    assert!(contains(&body, b"otel-export-test"), "service name missing");
    assert!(
        contains(&body, b"GET /users/{id}"),
        "span must be named after the route"
    );
    let trace_id_bytes: Vec<u8> = (0..trace_id.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trace_id[i..i + 2], 16).unwrap())
        .collect();
    assert!(
        contains(&body, &trace_id_bytes),
        "span must continue the incoming traceparent"
    );
    assert!(
        contains(&body, b"replica lag exceeded"),
        "the server-side error must be attached to the span"
    );
    assert!(
        contains(&body, b"exception"),
        "error must be an exception event"
    );

    let reported = reported.lock().unwrap();
    assert_eq!(reported.len(), 1);
    assert_eq!(
        reported[0].trace_id.as_deref(),
        Some(trace_id),
        "error reports must link to the trace"
    );
}
