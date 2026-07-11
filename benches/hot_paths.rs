use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use axum::{Router, routing::post};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tideway::auth::{AccessTokenClaims, JwtIssuer, JwtIssuerConfig, JwtVerifier, TokenSubject};
use tideway::jobs::InMemoryJobQueue;
use tideway::ratelimit::{RateLimitConfig, build_rate_limit_layer};
use tideway::request_logging::{RequestLoggingConfig, build_request_logging_layer};
use tideway::traits::job::{Job, JobQueue};
use tideway::websocket::{Connection, ConnectionManager};
use tideway::{AppContext, Result};
use tokio::sync::RwLock;
use tower::ServiceExt;

const JWT_SECRET: &str = "0123456789abcdef0123456789abcdef";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime")
}

fn benchmark_jwt(c: &mut Criterion) {
    let rt = runtime();
    let issuer = JwtIssuer::new(
        JwtIssuerConfig::with_secure_secret(JWT_SECRET, "bench")
            .expect("secure benchmark secret")
            .audience("bench"),
    )
    .expect("JWT issuer");
    let token = issuer
        .issue(TokenSubject::new("user-1"), false)
        .expect("issue token")
        .access_token;
    let verifier = JwtVerifier::<AccessTokenClaims>::from_secret_checked(JWT_SECRET.as_bytes())
        .expect("JWT verifier")
        .with_issuer("bench")
        .with_audience("bench");

    c.bench_function("jwt/hs256_access_verify", |b| {
        b.iter(|| {
            rt.block_on(verifier.verify_access_token(black_box(&token)))
                .expect("valid access token")
        });
    });
}

async fn ok_handler(_: Bytes) {}

fn benchmark_rate_limit(c: &mut Criterion) {
    let rt = runtime();
    let config = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(1_000_000)
        .window_seconds(1)
        .per_ip()
        .build();
    let layer = build_rate_limit_layer(&config).expect("enabled rate limiter");
    let router = Router::new().route("/", post(ok_handler)).layer(layer);
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);

    c.bench_function("rate_limit/per_ip_request", |b| {
        b.iter(|| {
            let mut request = Request::post("/").body(Body::empty()).expect("request");
            request.extensions_mut().insert(ConnectInfo(peer));
            rt.block_on(router.clone().oneshot(request))
                .expect("rate-limited response")
        });
    });
}

fn logging_router(preview_size: usize) -> Router {
    let config = RequestLoggingConfig::builder()
        .enabled(true)
        .body_preview_size(preview_size)
        .body_preview_redaction(true)
        .build();
    Router::new()
        .route("/", post(ok_handler))
        .layer(build_request_logging_layer(&config).expect("enabled request logging"))
}

fn benchmark_request_redaction(c: &mut Criterion) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::sink)
        .try_init();
    let rt = runtime();
    let mut group = c.benchmark_group("request_logging/json_redaction");

    for size in [1_024_usize, 16_384] {
        let padding = "x".repeat(size.saturating_sub(128));
        let payload = serde_json::to_vec(&json!({
            "email": "user@example.com",
            "password": "secret",
            "nested": { "access_token": "token", "padding": padding }
        }))
        .expect("JSON payload");
        let router = logging_router(payload.len());
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                let request = Request::post("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, payload.len())
                    .body(Body::from(payload.clone()))
                    .expect("request");
                rt.block_on(router.clone().oneshot(request))
                    .expect("logged response")
            });
        });
    }
    group.finish();
}

#[derive(Debug)]
struct BenchmarkJob;

#[async_trait]
impl Job for BenchmarkJob {
    fn job_type(&self) -> &str {
        "benchmark"
    }

    fn serialize(&self) -> Result<serde_json::Value> {
        Ok(json!({"value": 1}))
    }

    async fn execute(&self, _ctx: &AppContext) -> Result<()> {
        Ok(())
    }
}

fn benchmark_job_queue(c: &mut Criterion) {
    let rt = runtime();
    let queue = rt.block_on(async { InMemoryJobQueue::with_history_limit(0, 1, 1) });
    let job = BenchmarkJob;

    c.bench_function("jobs/enqueue_dequeue_complete", |b| {
        b.iter(|| {
            rt.block_on(async {
                let job_id = queue.enqueue(&job).await.expect("enqueue");
                let dequeued = queue.dequeue().await.expect("dequeue").expect("job");
                assert_eq!(dequeued.job_id, job_id);
                queue.complete(&job_id).await.expect("complete");
            });
        });
    });
    rt.block_on(queue.shutdown());
}

fn benchmark_websocket_fanout(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("websocket/broadcast_text");

    for connections in [10_usize, 100, 1_000] {
        let manager = ConnectionManager::with_max_connections(connections);
        let mut receivers = rt.block_on(async {
            let mut receivers = Vec::with_capacity(connections);
            for index in 0..connections {
                let (connection, receiver) = Connection::channel(format!("conn-{index}"), 1);
                manager
                    .register(Arc::new(RwLock::new(connection)))
                    .await
                    .expect("register connection");
                receivers.push(receiver);
            }
            receivers
        });

        group.throughput(Throughput::Elements(connections as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(connections),
            &connections,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        manager
                            .broadcast_text(black_box("benchmark message"))
                            .await
                            .expect("broadcast");
                        for receiver in &mut receivers {
                            receiver.recv().await.expect("broadcast delivery");
                        }
                    })
                });
            },
        );

        drop(manager);
        drop(receivers);
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_jwt,
    benchmark_rate_limit,
    benchmark_request_redaction,
    benchmark_job_queue,
    benchmark_websocket_fanout
);
criterion_main!(benches);
