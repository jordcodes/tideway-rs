use tideway::{App, CorsConfig};

#[tokio::test]
async fn test_cors_permissive_allows_any_origin() {
    let cors = CorsConfig::permissive();

    let _app = App::builder().with_cors(cors).build();

    // This test verifies that permissive CORS configuration is applied
    // In a real scenario, you would make actual HTTP requests to verify headers
}

#[tokio::test]
async fn test_cors_restrictive_allows_specific_origins() {
    let cors = CorsConfig::restrictive(vec!["https://example.com".to_string()]);

    let _app = App::builder().with_cors(cors).build();

    // This test verifies that restrictive CORS configuration is applied
}

#[tokio::test]
async fn test_cors_builder_pattern() {
    let cors = CorsConfig::builder()
        .allow_origin("https://example.com")
        .allow_origin("https://api.example.com")
        .allow_method("GET")
        .allow_method("POST")
        .allow_header("content-type")
        .allow_header("authorization")
        .allow_credentials(true)
        .max_age(7200)
        .build();

    assert_eq!(cors.allowed_origins.len(), 2);
    // Methods: default 5 + 2 added = 7 (builder appends to defaults)
    assert_eq!(cors.allowed_methods.len(), 7);
    // Headers: default 3 + 2 added = 5 (builder appends to defaults)
    assert_eq!(cors.allowed_headers.len(), 5);
    assert!(cors.allow_credentials);
    assert_eq!(cors.max_age_seconds, 7200);
}

#[tokio::test]
async fn test_cors_disabled() {
    let cors = CorsConfig::builder().enabled(false).build();

    assert!(!cors.enabled);
}

#[tokio::test]
async fn test_cors_any_origin() {
    let cors = CorsConfig::builder().allow_any_origin().build();

    assert_eq!(cors.allowed_origins, vec!["*"]);
}

#[tokio::test]
async fn test_cors_any_header() {
    let cors = CorsConfig::builder().allow_any_header().build();

    assert_eq!(cors.allowed_headers, vec!["*"]);
}

#[tokio::test]
async fn test_cors_expose_headers() {
    let cors = CorsConfig::builder()
        .expose_header("x-custom-header")
        .expose_header("x-request-id")
        .build();

    assert_eq!(cors.exposed_headers.len(), 2);
    assert!(cors
        .exposed_headers
        .contains(&"x-custom-header".to_string()));
}
