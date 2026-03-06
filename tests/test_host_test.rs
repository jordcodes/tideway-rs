use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::extract::Form;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::{Json, Router, routing::get, routing::post};
use serde::Deserialize;
use serde_json::json;
use tideway::App;
use tideway::testing::{TestHost, post as test_post};

#[tokio::test]
async fn test_host_supports_declarative_scenarios() {
    async fn health() -> Json<serde_json::Value> {
        Json(json!({
            "ok": true,
            "meta": { "mode": "test-host" }
        }))
    }

    let app = App::new().merge_router(Router::new().route("/host-health", get(health)));
    let host = TestHost::new(app);

    let outcome = host
        .scenario(|scenario| {
            scenario.get("/host-health");
            scenario.header_should_exist("content-type");
            scenario.json_path_should_be("ok", json!(true));
            scenario.json_should_contain(json!({
                "meta": { "mode": "test-host" }
            }));
            scenario.assert_with(|outcome| {
                if outcome.status() == StatusCode::OK {
                    Ok(())
                } else {
                    Err(format!("expected ok, got {}", outcome.status()))
                }
            });
        })
        .await;

    assert_eq!(outcome.json_value()["ok"], json!(true));
}

#[tokio::test]
async fn test_host_runs_before_and_after_hooks() {
    async fn create_widget(headers: HeaderMap) -> Response<Body> {
        let trace = headers
            .get("x-trace")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing");

        Response::builder()
            .status(StatusCode::CREATED)
            .header("x-trace", trace)
            .body(Body::from("widget created"))
            .unwrap()
    }

    let hook_ran = Arc::new(AtomicBool::new(false));
    let app = App::new().merge_router(Router::new().route("/widgets", post(create_widget)));
    let host = TestHost::new(app)
        .before_each(|request| {
            request
                .headers_mut()
                .insert("x-trace", "spec-123".parse().unwrap());
        })
        .after_each({
            let hook_ran = Arc::clone(&hook_ran);
            move |outcome| {
                hook_ran.store(true, Ordering::SeqCst);
                assert_eq!(outcome.request().header("x-trace"), Some("spec-123"));
            }
        });

    let outcome = host
        .scenario(|scenario| {
            scenario.post("/widgets");
            scenario.status_code_should_be(201);
            scenario.header_should_be("x-trace", "spec-123");
            scenario.content_should_contain("widget created");
        })
        .await;

    assert_eq!(outcome.status(), StatusCode::CREATED);
    assert!(hook_ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_host_supports_async_hooks() {
    async fn echo_header(headers: HeaderMap) -> Response<Body> {
        let value = headers
            .get("x-async")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing");

        Response::builder()
            .status(StatusCode::OK)
            .header("x-async", value)
            .body(Body::empty())
            .unwrap()
    }

    let before_seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let after_seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let app = App::new().merge_router(Router::new().route("/async", get(echo_header)));
    let host = TestHost::new(app)
        .before_each_async({
            let before_seen = Arc::clone(&before_seen);
            move |request| {
                let before_seen = Arc::clone(&before_seen);
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    before_seen
                        .lock()
                        .await
                        .push(request.uri().path().to_string());
                    request
                        .headers_mut()
                        .insert("x-async", "enabled".parse().unwrap());
                })
            }
        })
        .after_each_async({
            let after_seen = Arc::clone(&after_seen);
            move |outcome| {
                let after_seen = Arc::clone(&after_seen);
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    after_seen.lock().await.push(outcome.status());
                })
            }
        });

    host.scenario(|scenario| {
        scenario.get("/async");
        scenario.header_should_be("x-async", "enabled");
    })
    .await;

    assert_eq!(before_seen.lock().await.clone(), vec!["/async".to_string()]);
    assert_eq!(after_seen.lock().await.clone(), vec![StatusCode::OK]);
}

#[tokio::test]
async fn test_host_try_scenario_reports_default_status_failures() {
    let host = TestHost::from_router(Router::new());

    let error = host
        .try_scenario(|scenario| {
            scenario.get("/missing");
        })
        .await
        .expect_err("missing route should fail the default 200 expectation");

    let message = error.to_string();
    assert!(message.contains("GET /missing"));
    assert!(message.contains("Expected status 200 OK, got 404 Not Found"));
}

#[tokio::test]
async fn test_scenario_aliases_match_documented_api() {
    async fn echo(headers: HeaderMap, Json(payload): Json<serde_json::Value>) -> Response<Body> {
        let x_test = headers
            .get("x-test")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing");

        Response::builder()
            .status(StatusCode::OK)
            .header("x-test", x_test)
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    }

    let app = Router::new().route("/echo", post(echo));

    let response = test_post(app, "/echo")
        .with_header("x-test", "1")
        .with_json(&json!({ "ok": true }))
        .send()
        .await
        .assert_json_ok()
        .assert_header("x-test", "1");

    assert_eq!(response.json_value().await["ok"], json!(true));
}

#[tokio::test]
async fn test_host_supports_form_posts() {
    #[derive(Deserialize)]
    struct SignupForm {
        email: String,
    }

    async fn signup(Form(form): Form<SignupForm>) -> Json<serde_json::Value> {
        Json(json!({ "email": form.email }))
    }

    let app = App::new().merge_router(Router::new().route("/signup", post(signup)));
    let host = TestHost::new(app);

    let outcome = host
        .scenario(|scenario| {
            scenario.post("/signup");
            scenario.with_form(&[("email", "form@example.com")]);
            scenario.json_path_should_be("email", json!("form@example.com"));
        })
        .await;

    assert_eq!(outcome.json_value()["email"], json!("form@example.com"));
}

#[tokio::test]
async fn test_host_supports_redirect_assertions() {
    async fn redirect_handler() -> Response<Body> {
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("location", "/done")
            .body(Body::empty())
            .unwrap()
    }

    let app = App::new().merge_router(Router::new().route("/old", get(redirect_handler)));
    let host = TestHost::new(app);

    let outcome = host
        .scenario(|scenario| {
            scenario.get("/old");
            scenario.status_code_should_be(303);
            scenario.redirect_to_should_be("/done");
        })
        .await;

    assert_eq!(outcome.status(), StatusCode::SEE_OTHER);
}
