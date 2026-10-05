use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use std::sync::{Arc, Mutex};
use tideway::{App, AppContext, Config, RouteModule};
use tower::ServiceExt;

struct TestRoutes;
impl RouteModule for TestRoutes {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/fast", get(|| async { "ok" }))
            .route("/slow", get(|| std::future::pending::<StatusCode>()))
    }
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn app() -> App {
    let mut config = Config::default();
    config.dev.enabled = false;
    config.request_logging.enabled = true;
    config.timeout.timeout_seconds = 0;
    config.rate_limit.enabled = true;
    config.rate_limit.strategy = "global".into();
    config.rate_limit.max_requests = 1;
    config.rate_limit.window_seconds = 3600;
    #[cfg(feature = "metrics")]
    {
        config.metrics.enabled = true;
    }
    App::with_config(config).register_module(TestRoutes)
}

#[tokio::test]
async fn generated_ids_reach_responses_and_logs() {
    let output = LogBuffer::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    // This integration-test binary owns its subscriber so parallel unit tests
    // cannot interfere with tracing callsite interest.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    {
        // Each router has a fresh rate limiter. Exercise ordinary, fallback,
        // timeout, and rate-limit responses, including a supplied ID.
        for (path, expected) in [
            ("/fast", StatusCode::OK),
            ("/missing", StatusCode::NOT_FOUND),
            ("/slow", StatusCode::REQUEST_TIMEOUT),
            ("/fast", StatusCode::TOO_MANY_REQUESTS),
        ] {
            let router = app().into_router_with_middleware();
            if expected == StatusCode::TOO_MANY_REQUESTS {
                let _ = router
                    .clone()
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
            }
            let response = router
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            let id = response
                .headers()
                .get("x-request-id")
                .expect("generated response ID")
                .to_str()
                .unwrap();
            uuid::Uuid::parse_str(id).unwrap();
            let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
            assert!(
                logs.contains(id),
                "request ID {id} missing from logs: {logs}"
            );
        }
        let router = app().into_router_with_middleware();
        for expected in [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/fast")
                        .header("x-request-id", "supplied-id")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["x-request-id"], "supplied-id");
        }
        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.lines()
                .any(|line| line.contains("429") && line.contains("supplied-id")),
            "429 log missing: {logs}"
        );
    }
}
