//! Sentry delivery through the real transport, against a mock ingest server.

use axum::{Router, body::Bytes, extract::State, routing::get, routing::post};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tideway::observability::{ErrorReporter, SentryReporter};
use tideway::{App, AppContext, Config, RouteModule, TidewayError};
use tower::ServiceExt;

struct Routes;

impl RouteModule for Routes {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route(
                "/users/{id}",
                get(|| async { Err::<(), _>(TidewayError::internal("replica lag exceeded")) }),
            )
            .route(
                "/missing",
                get(|| async { Err::<(), _>(TidewayError::not_found("user")) }),
            )
    }
}

type Envelopes = Arc<Mutex<Vec<String>>>;

/// Start a mock Sentry ingest endpoint and return its DSN.
async fn mock_sentry() -> (String, Envelopes) {
    let envelopes: Envelopes = Arc::default();
    let router = Router::new()
        .route(
            "/api/1/envelope/",
            post(
                |State(envelopes): State<Envelopes>, body: Bytes| async move {
                    envelopes
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&body).into_owned());
                },
            ),
        )
        .with_state(envelopes.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    (format!("http://public@{addr}/1"), envelopes)
}

/// Sentry events sent so far: the JSON envelope items that carry an exception.
fn events(envelopes: &Envelopes) -> Vec<Value> {
    envelopes
        .lock()
        .unwrap()
        .iter()
        .flat_map(|envelope| envelope.lines().map(str::to_owned).collect::<Vec<_>>())
        .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
        .filter(|item| item.get("exception").is_some())
        .collect()
}

fn app(context: AppContext) -> Router {
    let mut config = Config::default();
    config.dev.enabled = false;
    App::with_config(config)
        .with_context(context)
        .register_module(Routes)
        .into_router_with_middleware()
}

async fn request(router: &Router, path: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            axum::http::Request::get(path)
                .header("x-request-id", "req-7")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn server_errors_become_sentry_issues() {
    let (dsn, envelopes) = mock_sentry().await;
    let reporter = Arc::new(SentryReporter::new(dsn.as_str()));
    let router = app(AppContext::builder()
        .with_error_reporter(reporter.clone())
        .build());

    let body = request(&router, "/users/42?token=secret").await;
    request(&router, "/missing").await;
    let flushed = tokio::task::spawn_blocking(move || reporter.flush(Duration::from_secs(5)))
        .await
        .unwrap();
    assert!(flushed);

    let events = events(&envelopes);
    assert_eq!(events.len(), 1, "only the 5xx is reported: {events:#?}");
    let event = &events[0];
    // Sentry omits the default "error" level.
    assert!(event.get("level").is_none_or(|level| level == "error"));
    assert_eq!(event["transaction"], "GET /users/{id}");
    let exception = &event["exception"]["values"][0];
    assert_eq!(exception["type"], "ServerError");
    assert_eq!(
        exception["value"],
        "Internal server error: replica lag exceeded"
    );
    assert_eq!(exception["mechanism"]["handled"], true);
    let tags = &event["tags"];
    assert_eq!(tags["error_id"], body["error_id"]);
    assert_eq!(tags["http.status_code"], "500");
    assert_eq!(tags["request_id"], "req-7");
    assert_eq!(tags["url.path"], "/users/42");
    assert!(
        !event.to_string().contains("secret"),
        "query strings must not be sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sentry_dsn_alone_enables_reporting() {
    // The env-derived reporter is cached process-wide and binds Sentry's main hub.
    if crate::support::isolated(module_path!(), "sentry_dsn_alone_enables_reporting", |_| {}) {
        return;
    }
    let (dsn, envelopes) = mock_sentry().await;
    // SAFETY: this child process runs only this test, and no app has read
    // SENTRY_DSN yet.
    unsafe { std::env::set_var("SENTRY_DSN", &dsn) };

    // No reporter configured: the app picks Sentry up from the environment.
    let router = app(AppContext::new());
    request(&router, "/users/1").await;
    tokio::task::spawn_blocking(|| {
        let client = tideway::observability::sentry::Hub::main()
            .client()
            .expect("from_env binds the main hub");
        assert!(client.flush(Some(Duration::from_secs(5))));
    })
    .await
    .unwrap();

    let events = events(&envelopes);
    assert_eq!(events.len(), 1, "{events:#?}");
    assert_eq!(events[0]["transaction"], "GET /users/{id}");
}
