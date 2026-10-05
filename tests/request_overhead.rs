//! Repeatable in-process concurrent request benchmark (no socket/network overhead).
//! cargo test --release --features billing,test-billing --test request_overhead -- --ignored --nocapture
#![cfg(all(feature = "billing", feature = "test-billing"))]

use axum::{Router, body::Body, http::Request, routing::get};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tideway::{
    billing::{CachedEntitlementsManager, EntitlementsManager, InMemoryBillingStore, Plans},
    security::{SecurityConfig, build_security_headers_layer},
};
use tower::ServiceExt;

#[test]
#[ignore = "manual concurrent latency benchmark"]
fn concurrent_request_latency() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .features(["reports", "email_support"])
            .done()
            .unwrap()
            .build()
            .unwrap();
        let cache = Arc::new(CachedEntitlementsManager::new(
            EntitlementsManager::new(InMemoryBillingStore::new(), plans),
            Duration::from_secs(3600),
        ));
        let _ = cache.get_entitlements("org").await.unwrap();
        let app = Router::new()
            .route(
                "/",
                get(move || {
                    let cache = cache.clone();
                    async move {
                        let _ = std::hint::black_box(cache.get_entitlements("org").await.unwrap());
                        "ok"
                    }
                }),
            )
            .layer(
                build_security_headers_layer(&SecurityConfig {
                    content_security_policy: Some(
                        "default-src 'self'; frame-ancestors 'none'".into(),
                    ),
                    permissions_policy: Some("geolocation=(), microphone=()".into()),
                    ..Default::default()
                })
                .unwrap(),
            );
        for round in 0..6 {
            let start = Instant::now();
            let mut workers = Vec::new();
            for _ in 0..8 {
                let app = app.clone();
                workers.push(tokio::spawn(async move {
                    let mut latencies = Vec::with_capacity(25_000);
                    for _ in 0..25_000 {
                        let start = Instant::now();
                        let response = app
                            .clone()
                            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                            .await
                            .unwrap();
                        assert_eq!(response.status(), 200);
                        latencies.push(start.elapsed().as_nanos() as u64);
                    }
                    latencies
                }));
            }
            let mut samples = Vec::new();
            for worker in workers {
                samples.extend(worker.await.unwrap());
            }
            let elapsed = start.elapsed();
            samples.sort_unstable();
            eprintln!(
                "round={round} requests/s={:.0} mean_ns={} p50_ns={} p95_ns={} p99_ns={}",
                samples.len() as f64 / elapsed.as_secs_f64(),
                samples.iter().sum::<u64>() / samples.len() as u64,
                samples[samples.len() / 2],
                samples[samples.len() * 95 / 100],
                samples[samples.len() * 99 / 100]
            );
        }
    });
}
