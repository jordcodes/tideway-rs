use axum::{Router, body::Body, http::Request, routing::get};
use tideway::security::{SecurityConfig, build_security_headers_layer};
use tower::ServiceExt;

#[tokio::test]
async fn configured_headers_are_consistent_across_requests() {
    let config = SecurityConfig {
        hsts_max_age: 123,
        hsts_include_subdomains: true,
        hsts_preload: true,
        content_security_policy: Some("default-src 'self'".into()),
        permissions_policy: Some("geolocation=()".into()),
        ..Default::default()
    };
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [("x-frame-options", "SAMEORIGIN"), ("x-custom", "retained")],
                    "ok",
                )
            }),
        )
        .layer(build_security_headers_layer(&config).unwrap());
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(Request::new(Body::empty()))
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(
            headers["strict-transport-security"],
            "max-age=123; includeSubDomains; preload"
        );
        assert_eq!(headers["content-security-policy"], "default-src 'self'");
        assert_eq!(headers["permissions-policy"], "geolocation=()");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-xss-protection"], "0");
        assert_eq!(
            headers["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        assert_eq!(headers["x-custom"], "retained");
    }
}

#[tokio::test]
async fn invalid_or_disabled_headers_preserve_handler_headers() {
    let config = SecurityConfig {
        hsts_max_age: 0,
        nosniff: false,
        x_frame_options: None,
        xss_protection: None,
        referrer_policy: None,
        content_security_policy: Some("invalid\nvalue".into()),
        permissions_policy: Some("invalid\rvalue".into()),
        ..Default::default()
    };
    let app = Router::new()
        .route(
            "/",
            get(|| async { ([("content-security-policy", "default-src 'none'")], "ok") }),
        )
        .layer(build_security_headers_layer(&config).unwrap());
    let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'none'"
    );
    for name in [
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ] {
        assert!(!response.headers().contains_key(name));
    }
}
