use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, header},
    routing::get,
};
use tideway::{App, CompressionConfig, ConfigBuilder};
use tower::ServiceExt;
use tower_http::compression::{CompressionLayer, CompressionLevel};

struct Responses;
impl tideway::RouteModule for Responses {
    fn routes(&self) -> Router<tideway::AppContext> {
        Router::new().route("/", get(|| async { payload() }))
    }
}

fn payload() -> String {
    (0..500)
        .map(|i| {
            format!(
                "record {}: response compression should preserve this repeated text\n",
                i % 37
            )
        })
        .collect()
}

async fn response(router: Router, accept: &str) -> (Option<String>, Vec<u8>) {
    let mut request = Request::builder().uri("/");
    for value in accept.split('|').filter(|value| !value.is_empty()) {
        request = request.header(header::ACCEPT_ENCODING, value);
    }
    let response = router
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let encoding = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .map(|v| v.to_str().unwrap().to_owned());
    (
        encoding,
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
}

#[test]
fn compression_config_survives_from_env() {
    if isolated("compression_config_survives_from_env", &[]) {
        return;
    }
    let expected = CompressionConfig::builder()
        .enabled(false)
        .gzip()
        .level(2)
        .brotli_quality(10)
        .build();
    let actual = ConfigBuilder::new()
        .with_compression(expected.clone())
        .from_env()
        .build()
        .unwrap()
        .compression;
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[tokio::test]
async fn compression_response_uses_configured_quality() {
    if isolated("compression_response_uses_configured_quality", &[]) {
        return;
    }
    for before_env in [false, true] {
        for algorithm in ["gzip", "br", "both"] {
            for (level, quality) in [(1, 2), (9, 10)] {
                let builder = CompressionConfig::builder()
                    .level(level)
                    .brotli_quality(quality);
                let compression = match algorithm {
                    "gzip" => builder.gzip(),
                    "br" => builder.brotli(),
                    _ => builder.both(),
                }
                .build();
                let builder = if before_env {
                    ConfigBuilder::new()
                        .with_compression(compression)
                        .from_env()
                } else {
                    ConfigBuilder::new()
                        .from_env()
                        .with_compression(compression)
                };
                let app = App::with_config(builder.build().unwrap())
                    .register_module(Responses)
                    .into_router_with_middleware();
                for accept in [
                    "gzip",
                    "br",
                    "gzip, br",
                    "gzip;q=1, br;q=0.5",
                    "gzip;q=0.5, br;q=1",
                    "gzip;q=0, br;q=0",
                    "identity",
                    "br;q=bogus, gzip",
                    "x-gzip",
                    "BR;Q=1, gzip;q=0.9",
                    "gzip;q=0.8|br;q=0.9",
                    "br;q=0.5000, gzip",
                    "br;q=1.001, gzip",
                    "br;q=.5, gzip",
                    "br;q=0.5;q=1, gzip",
                    "br;q=0.5, identity;q=1",
                    "",
                    "*",
                ] {
                    // The reference uses tower-http's negotiation, then the exact quality
                    // configured for the selected algorithm.
                    let reference = CompressionLayer::new()
                        .no_deflate()
                        .no_zstd()
                        .gzip(algorithm != "br")
                        .br(algorithm != "gzip");
                    let (encoding, _) = response(
                        Router::new()
                            .route("/", get(|| async { payload() }))
                            .layer(reference.clone()),
                        accept,
                    )
                    .await;
                    let expected_quality = if encoding.as_deref() == Some("br") {
                        quality
                    } else {
                        level
                    };
                    let expected = response(
                        Router::new().route("/", get(|| async { payload() })).layer(
                            reference.quality(CompressionLevel::Precise(expected_quality.into())),
                        ),
                        accept,
                    )
                    .await;
                    let actual = response(app.clone(), accept).await;
                    assert!(
                        actual == expected,
                        "before_env={before_env}, algorithm={algorithm}, level={level}, quality={quality}, accept={accept}"
                    );
                }
            }
        }
    }
}

// Run environment-dependent cases in child processes without mutating the
// process environment shared by the test runner's other threads.
fn isolated(test: &str, overrides: &[(&str, &str)]) -> bool {
    crate::support::isolated(module_path!(), test, |command| {
        for key in [
            "COMPRESSION_ENABLED",
            "COMPRESSION_ALGORITHM",
            "COMPRESSION_LEVEL",
            "COMPRESSION_BROTLI_QUALITY",
        ] {
            command.env_remove(key).env_remove(format!("TIDEWAY_{key}"));
        }
        command.envs(overrides.iter().copied());
    })
}

#[test]
fn compression_env_overrides_only_present_settings() {
    if isolated(
        "compression_env_overrides_only_present_settings",
        &[
            ("TIDEWAY_COMPRESSION_LEVEL", "8"),
            ("COMPRESSION_LEVEL", "3"),
        ],
    ) {
        return;
    }
    let compression = CompressionConfig::builder()
        .enabled(false)
        .brotli()
        .level(2)
        .brotli_quality(10)
        .build();
    let config = ConfigBuilder::new()
        .with_compression(compression.clone())
        .from_env()
        .build()
        .unwrap();
    let mut expected = compression.clone();
    expected.level = 8;
    assert_eq!(
        serde_json::to_value(config.compression).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    let config = ConfigBuilder::new()
        .from_env()
        .with_compression(compression.clone())
        .build()
        .unwrap();
    assert_eq!(
        serde_json::to_value(config.compression).unwrap(),
        serde_json::to_value(compression).unwrap()
    );
}

#[test]
fn compression_invalid_env_preserves_settings() {
    if isolated(
        "compression_invalid_env_preserves_settings",
        &[
            ("TIDEWAY_COMPRESSION_ENABLED", "invalid"),
            ("TIDEWAY_COMPRESSION_ALGORITHM", "invalid"),
            ("TIDEWAY_COMPRESSION_LEVEL", "invalid"),
            ("TIDEWAY_COMPRESSION_BROTLI_QUALITY", "invalid"),
        ],
    ) {
        return;
    }
    let expected = CompressionConfig::builder()
        .enabled(false)
        .gzip()
        .level(2)
        .brotli_quality(10)
        .build();
    let actual = ConfigBuilder::new()
        .with_compression(expected.clone())
        .from_env()
        .build()
        .unwrap()
        .compression;
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}
