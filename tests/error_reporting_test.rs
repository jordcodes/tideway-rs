use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use std::sync::{Arc, Mutex};
use tideway::observability::{ErrorEvent, ErrorSource};
use tideway::{App, AppContext, Config, RouteModule, TidewayError};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<ErrorEvent>>>);

impl Captured {
    fn context(&self) -> AppContext {
        let events = self.0.clone();
        AppContext::builder()
            .with_error_reporter(Arc::new(move |event: &ErrorEvent| {
                events.lock().unwrap().push(event.clone());
            }))
            .build()
    }

    fn take(&self) -> Vec<ErrorEvent> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct Routes;

impl RouteModule for Routes {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route(
                "/internal",
                get(|| async {
                    Err::<(), _>(TidewayError::internal("connection to db-primary refused"))
                }),
            )
            .route("/raw", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .route(
                "/missing",
                get(|| async { Err::<(), _>(TidewayError::not_found("user")) }),
            )
            .route(
                "/panic",
                get(|| async {
                    panic!("invariant broken");
                    #[allow(unreachable_code)]
                    ()
                }),
            )
    }
}

fn router(captured: &Captured) -> Router {
    let mut config = Config::default();
    config.dev.enabled = false;
    App::with_config(config)
        .with_context(captured.context())
        .register_module(Routes)
        .into_router_with_middleware()
}

async fn get_path(router: Router, path: &str) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .uri(format!("{path}?token=secret"))
                .header("x-request-id", "req-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn server_errors_are_reported_with_full_message_and_request_metadata() {
    let captured = Captured::default();
    let response = get_path(router(&captured), "/internal").await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "Internal server error");

    let events = captured.take();
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(
        event.message,
        "Internal server error: connection to db-primary refused"
    );
    assert_eq!(event.status, Some(500));
    assert_eq!(event.error_id.as_deref(), body["error_id"].as_str());
    assert!(!event.panic);
    let ErrorSource::Request(request) = &event.source else {
        panic!("expected request source, got {:?}", event.source);
    };
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path, "/internal",
        "query strings must not be reported"
    );
    assert_eq!(request.request_id.as_deref(), Some("req-123"));
    assert_eq!(request.route.as_deref(), Some("/internal"));
}

#[tokio::test]
async fn server_errors_not_built_from_tideway_error_are_reported() {
    let captured = Captured::default();
    let response = get_path(router(&captured), "/raw").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let events = captured.take();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].status, Some(503));
    assert!(events[0].error_id.is_none());
}

#[tokio::test]
async fn client_errors_are_not_reported() {
    let captured = Captured::default();
    let response = get_path(router(&captured), "/missing").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = get_path(router(&captured), "/no-such-route").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(captured.take().is_empty());
}

#[tokio::test]
async fn handler_panics_are_reported_and_still_propagate() {
    let captured = Captured::default();
    let router = router(&captured);
    let outcome = tokio::spawn(async move { get_path(router, "/panic").await }).await;
    assert!(outcome.unwrap_err().is_panic(), "panic must propagate");

    let events = captured.take();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(events[0].panic);
    assert_eq!(events[0].message, "Handler panicked: invariant broken");
}

#[tokio::test]
async fn apps_without_a_reporter_are_unchanged() {
    let response = App::new()
        .register_module(Routes)
        .into_router_with_middleware()
        .oneshot(Request::get("/internal").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[cfg(feature = "jobs")]
#[tokio::test]
async fn failed_and_panicked_jobs_are_reported() {
    use tideway::jobs::{InMemoryJobQueue, JobRegistry, WorkerPool};
    use tideway::traits::job::JobQueue;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Flaky;

    #[async_trait::async_trait]
    impl tideway::Job for Flaky {
        fn job_type(&self) -> &str {
            "flaky"
        }
        fn serialize(&self) -> tideway::Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
        async fn execute(&self, _ctx: &AppContext) -> tideway::Result<()> {
            Ok(())
        }
    }

    let captured = Captured::default();
    let queue = Arc::new(InMemoryJobQueue::new(1, 0));
    let registry = Arc::new(JobRegistry::new());
    registry
        .register("flaky", |data, _| {
            Box::pin(async move {
                if data.retry_count == 0 {
                    return Err(TidewayError::internal("smtp timeout"));
                }
                panic!("retry exploded");
            })
        })
        .await;
    let job_id = queue.enqueue(&Flaky).await.unwrap();
    let pool = WorkerPool::new(queue.clone(), registry, Arc::new(captured.context()), 1);

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while captured.0.lock().unwrap().len() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    pool.shutdown().await;
    queue.shutdown().await;

    let events = captured.take();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].message, "Internal server error: smtp timeout");
    assert!(!events[0].panic);
    assert!(events[1].panic);
    assert!(events[1].message.contains("retry exploded"));
    for event in &events {
        let ErrorSource::Job(job) = &event.source else {
            panic!("expected job source, got {:?}", event.source);
        };
        assert_eq!(job.id, job_id);
        assert_eq!(job.job_type, "flaky");
    }
}
