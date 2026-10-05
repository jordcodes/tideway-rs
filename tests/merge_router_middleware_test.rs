use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use tideway::{App, AppContext, Config, RouteModule};
use tower::ServiceExt;

struct ModuleRoutes;
impl RouteModule for ModuleRoutes {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/module", get(|| async { "ok" }))
    }
}

fn app() -> App {
    let mut config = Config::default();
    config.dev.enabled = false;
    config.security.enabled = true;
    config.security.nosniff = true;
    config.timeout.timeout_seconds = 0;
    config.rate_limit.enabled = true;
    config.rate_limit.strategy = "global".into();
    config.rate_limit.max_requests = 1;
    config.rate_limit.window_seconds = 3600;
    App::with_config(config)
        .register_module(ModuleRoutes)
        .merge_router(
            Router::new()
                .route("/merged/fast", get(|| async { "ok" }))
                .route("/merged/slow", get(|| std::future::pending::<StatusCode>())),
        )
}

fn request(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn merged_routes_receive_security_headers_and_request_ids() {
    let response = app()
        .into_router_with_middleware()
        .oneshot(request("/merged/fast"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap()).unwrap();
}

#[tokio::test]
async fn merged_routes_are_rate_limited() {
    let router = app().into_router_with_middleware();
    let first = router.clone().oneshot(request("/merged/fast")).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = router.clone().oneshot(request("/merged/fast")).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().contains_key("x-request-id"));

    // Merged and module routes share the application's rate limit budget.
    let module = router.oneshot(request("/module")).await.unwrap();
    assert_eq!(module.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn merged_routes_time_out() {
    // Bound the test so a missing timeout layer fails instead of hanging.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        app()
            .into_router_with_middleware()
            .oneshot(request("/merged/slow")),
    )
    .await
    .expect("merged route was not timed out by middleware")
    .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}
