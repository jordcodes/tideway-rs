use axum::{Router, routing::get};
use axum::http::HeaderValue;
use tideway::{App, AppContext, RouteModule};
use tideway::testing::TestApp;

struct PingModule;

impl RouteModule for PingModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new().route("/ping", get(|| async { "pong" }))
    }
}

#[tokio::test]
async fn test_test_app_with_middleware() {
    let layer = axum::middleware::from_fn(
        |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
        let mut response = next.run(req).await;
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-test"),
            HeaderValue::from_static("1"),
        );
        response
    });

    let app = App::new()
        .register_module(PingModule)
        .with_global_layer(layer);
    let test_app = TestApp::new(app);

    test_app
        .get("/ping")
        .execute()
        .await
        .assert_ok()
        .assert_header("x-test", "1");
}

#[tokio::test]
async fn test_test_app_without_middleware() {
    let layer = axum::middleware::from_fn(
        |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
        let mut response = next.run(req).await;
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-test"),
            HeaderValue::from_static("1"),
        );
        response
    });

    let app = App::new()
        .register_module(PingModule)
        .with_global_layer(layer);
    let test_app = TestApp::without_middleware(app);

    let response = test_app.get("/ping").execute().await.response();
    assert!(response.headers().get("x-test").is_none());
}

#[tokio::test]
async fn test_auth_test_app_sets_bearer() {
    async fn auth_echo(
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response<axum::body::Body> {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header("x-auth", token)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    let app = App::new().merge_router(
        Router::new().route("/auth", axum::routing::get(auth_echo)),
    );
    let test_app = TestApp::new(app);

    test_app
        .auth("test-token")
        .get("/auth")
        .send()
        .await
        .assert_ok()
        .assert_header("x-auth", "Bearer test-token");
}
