use criterion::{black_box, criterion_group, criterion_main, Criterion};
use axum::{Router, routing::get, Json};
use serde_json::json;
use tower::ServiceExt;
use axum::http::Request;

// Raw Axum hello world
fn raw_axum_hello() -> Router {
    Router::new().route("/hello", get(|| async { "Hello, World!" }))
}

// Tideway hello world with default middleware
fn tideway_hello() -> Router {
    // Simplified for benchmark - in real usage would use App::new()
    Router::new().route("/hello", get(|| async { "Hello, World!" }))
}

// Raw Axum JSON response
fn raw_axum_json() -> Router {
    Router::new().route("/json", get(|| async {
        Json(json!({"message": "Hello", "status": "ok"}))
    }))
}

// Tideway JSON response with ApiResponse
fn tideway_json() -> Router {
    Router::new().route("/json", get(|| async {
        use tideway::ApiResponse;
        Json(ApiResponse::success(json!({"message": "Hello"})))
    }))
}

async fn make_request(router: &Router, path: &str) {
    let req = Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())
        .unwrap();

    let _response = router.clone().oneshot(req).await.unwrap();
}

fn benchmark_hello_world(c: &mut Criterion) {
    let mut group = c.benchmark_group("hello_world");

    let raw_router = raw_axum_hello();
    let tideway_router = tideway_hello();

    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("raw_axum", |b| {
        b.iter(|| {
            rt.block_on(make_request(black_box(&raw_router), "/hello"));
        });
    });

    group.bench_function("tideway", |b| {
        b.iter(|| {
            rt.block_on(make_request(black_box(&tideway_router), "/hello"));
        });
    });

    group.finish();
}

fn benchmark_json_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_response");

    let raw_router = raw_axum_json();
    let tideway_router = tideway_json();

    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("raw_axum", |b| {
        b.iter(|| {
            rt.block_on(make_request(black_box(&raw_router), "/json"));
        });
    });

    group.bench_function("tideway", |b| {
        b.iter(|| {
            rt.block_on(make_request(black_box(&tideway_router), "/json"));
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_hello_world, benchmark_json_response);
criterion_main!(benches);
