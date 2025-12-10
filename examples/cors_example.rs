/// Example demonstrating CORS configuration in Tideway
///
/// Run with: cargo run --example cors_example
use tideway::{App, ConfigBuilder, CorsConfig};

#[tokio::main]
async fn main() {
    // Initialize logging
    tideway::init_tracing();

    // Example 1: Permissive CORS for development
    // WARNING: Do not use in production!
    let _dev_cors = CorsConfig::permissive();

    // Example 2: Restrictive CORS for production
    let _prod_cors = CorsConfig::restrictive(vec![
        "https://example.com".to_string(),
        "https://www.example.com".to_string(),
    ]);

    // Example 3: Custom CORS using builder pattern
    let custom_cors = CorsConfig::builder()
        .allow_origin("https://app.example.com")
        .allow_origin("https://admin.example.com")
        .allow_methods(vec![
            "GET".to_string(),
            "POST".to_string(),
            "PUT".to_string(),
            "DELETE".to_string(),
        ])
        .allow_headers(vec![
            "content-type".to_string(),
            "authorization".to_string(),
            "x-api-key".to_string(),
        ])
        .expose_header("x-request-id")
        .allow_credentials(true)
        .max_age(3600)
        .build();

    // Example 4: Configure via environment variables
    // Set these environment variables:
    // TIDEWAY_CORS_ENABLED=true
    // TIDEWAY_CORS_ALLOWED_ORIGINS=https://example.com,https://api.example.com
    // TIDEWAY_CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE
    // TIDEWAY_CORS_ALLOWED_HEADERS=content-type,authorization
    // TIDEWAY_CORS_ALLOW_CREDENTIALS=true
    // TIDEWAY_CORS_MAX_AGE=7200

    let config = ConfigBuilder::new()
        .from_env() // This loads CORS config from environment
        .build();

    // Example 5: Programmatically set CORS on App
    let app = App::builder().with_cors(custom_cors).build();

    // Example 6: Use config-based CORS
    let _app_with_config = App::with_config(config.unwrap());

    // Start the server
    println!("Starting server with CORS enabled...");
    println!("Try making a cross-origin request to http://localhost:8000/health");
    app.serve().await.unwrap();
}
