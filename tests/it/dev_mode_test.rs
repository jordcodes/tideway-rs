use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::{Router, routing::get};
use std::fmt;
use std::sync::{Arc, Mutex};
use tideway::{
    App, AppContext, ConfigBuilder, DevConfigBuilder, ErrorContext, ErrorWithContext, RouteModule,
    TidewayError,
};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

#[derive(Clone, Default)]
struct CapturedEvents {
    messages: Arc<Mutex<Vec<String>>>,
}

impl CapturedEvents {
    fn push(&self, message: String) {
        self.messages
            .lock()
            .expect("lock captured events")
            .push(message);
    }

    fn contents(&self) -> Vec<String> {
        self.messages.lock().expect("lock captured events").clone()
    }
}

#[derive(Clone)]
struct CaptureLayer {
    events: CapturedEvents,
}

impl<S> Layer<S> for CaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        if let Some(message) = visitor.message {
            self.events.push(message);
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime")
}

struct PingModule;

impl RouteModule for PingModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/ping", get(|| async { "pong" }))
    }
}

struct ErrorModule;

impl RouteModule for ErrorModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/boom", get(boom))
            .route("/boom-context", get(boom_with_context))
    }
}

async fn boom() -> tideway::Result<&'static str> {
    Err(TidewayError::internal("connection pool exhausted"))
}

async fn boom_with_context() -> std::result::Result<&'static str, ErrorWithContext> {
    Err(TidewayError::internal("db-prod-01 failed")
        .with_context(ErrorContext::new().with_detail("Failed to connect to the primary database")))
}

fn run_request_with_dev_config(dev: tideway::DevConfig) -> Vec<String> {
    let events = CapturedEvents::default();
    let subscriber = Registry::default()
        .with(LevelFilter::DEBUG)
        .with(CaptureLayer {
            events: events.clone(),
        });
    let dispatch = tracing::Dispatch::new(subscriber);

    tracing::dispatcher::with_default(&dispatch, || {
        tracing::debug!("capture-ready");
        build_runtime().block_on(async {
            let config = ConfigBuilder::new()
                .with_dev_config(dev)
                .build()
                .expect("build config");

            let app = App::with_config(config)
                .register_module(PingModule)
                .into_router_with_middleware();

            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/ping")
                        .body(Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("request should succeed");

            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    events.contents()
}

fn run_error_request_with_dev_config(dev: tideway::DevConfig, path: &str) -> serde_json::Value {
    build_runtime().block_on(async {
        let config = ConfigBuilder::new()
            .with_dev_config(dev)
            .build()
            .expect("build config");

        let app = App::with_config(config)
            .register_module(ErrorModule)
            .into_router_with_middleware();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        serde_json::from_slice::<serde_json::Value>(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read response body"),
        )
        .expect("parse json body")
    })
}

#[test]
fn test_dev_request_dumper_is_applied_in_app_middleware() {
    let events = run_request_with_dev_config(
        DevConfigBuilder::new()
            .enabled(true)
            .with_request_dumper(true)
            .build(),
    );

    assert!(
        events
            .iter()
            .any(|message| message.contains("\"type\": \"request\"")),
        "expected request dumper request log, got:\n{:?}",
        events
    );
    assert!(
        events
            .iter()
            .any(|message| message.contains("\"type\": \"response\"")),
        "expected request dumper response log, got:\n{:?}",
        events
    );
    assert!(
        events
            .iter()
            .any(|message| message.contains("\"uri\": \"/ping\"")),
        "expected request URI in dump output, got:\n{:?}",
        events
    );
}

#[test]
fn test_dev_request_dumper_respects_path_filter() {
    let events = run_request_with_dev_config(
        DevConfigBuilder::new()
            .enabled(true)
            .with_request_dumper(true)
            .with_dump_path_pattern(Some("/debug".to_string()))
            .build(),
    );

    assert!(
        !events
            .iter()
            .any(|message| message.contains("\"type\": \"request\"")),
        "expected no request dump for filtered path, got:\n{:?}",
        events
    );
    assert!(
        !events
            .iter()
            .any(|message| message.contains("\"type\": \"response\"")),
        "expected no response dump for filtered path, got:\n{:?}",
        events
    );
}

#[test]
fn test_dev_mode_includes_stack_traces_for_plain_tideway_errors() {
    let body = run_error_request_with_dev_config(
        DevConfigBuilder::new()
            .enabled(true)
            .with_stack_traces(true)
            .build(),
        "/boom",
    );

    assert_eq!(
        body["error"],
        serde_json::json!("Internal server error: connection pool exhausted")
    );
    assert_eq!(
        body["stack_trace"],
        serde_json::json!("Internal(\"connection pool exhausted\")")
    );
}

#[test]
fn test_dev_mode_includes_stack_traces_for_errors_with_context() {
    let body = run_error_request_with_dev_config(
        DevConfigBuilder::new()
            .enabled(true)
            .with_stack_traces(true)
            .build(),
        "/boom-context",
    );

    assert_eq!(
        body["error"],
        serde_json::json!("Internal server error: db-prod-01 failed")
    );
    assert_eq!(
        body["details"],
        serde_json::json!("Failed to connect to the primary database")
    );
    assert_eq!(
        body["stack_trace"],
        serde_json::json!("Internal(\"db-prod-01 failed\")")
    );
}

#[test]
fn test_dev_mode_without_stack_traces_omits_stack_trace_field() {
    let body =
        run_error_request_with_dev_config(DevConfigBuilder::new().enabled(true).build(), "/boom");

    assert_eq!(
        body["error"],
        serde_json::json!("Internal server error: connection pool exhausted")
    );
    assert!(body.get("stack_trace").is_none());
}
