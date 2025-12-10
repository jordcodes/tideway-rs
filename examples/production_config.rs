/// Production configuration example
///
/// This example demonstrates:
/// - Environment-based configuration
/// - Logging setup
/// - Error handling
/// - Graceful shutdown
/// - Health monitoring
/// - Production-ready settings
///
/// Run with: cargo run --example production_config
use tideway::{App, ConfigBuilder, CorsConfig, RateLimitConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging early
    // Production: Use JSON logging for log aggregation systems
    let log_json = std::env::var("TIDEWAY_LOG_JSON")
        .map(|v| v.parse().unwrap_or(false))
        .unwrap_or(false);

    if log_json {
        tideway::init_tracing();
    } else {
        tideway::init_tracing();
    }

    // Load configuration from environment
    // Production: Use ConfigBuilder to load from environment variables
    let base_config = ConfigBuilder::new()
        .from_env() // Loads from TIDEWAY_* env vars
        .build()
        .unwrap();

    // Override CORS for production
    let cors = if cfg!(debug_assertions) {
        // Development: permissive
        CorsConfig::permissive()
    } else {
        // Production: restrictive
        let allowed_origins = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "https://app.example.com".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        CorsConfig::restrictive(allowed_origins)
    };

    // Configure rate limiting for production
    let rate_limit = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(
            std::env::var("RATE_LIMIT_MAX_REQUESTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100)
        )
        .window_seconds(
            std::env::var("RATE_LIMIT_WINDOW_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60)
        )
        .per_ip() // Per-IP limiting in production
        .build();

    // Build final config
    let config = ConfigBuilder::new()
        .with_host(&base_config.server.host)
        .with_port(base_config.server.port)
        .with_log_level(&base_config.logging.level)
        .with_json_logging(base_config.logging.json)
        .with_cors(cors)
        .with_rate_limit(rate_limit)
        .build();

    // Create app with production config
    let app = App::with_config(config.unwrap());

    // Log startup information
    tracing::info!("Starting production server");
    tracing::info!("Environment: {}", if cfg!(debug_assertions) { "development" } else { "production" });
    tracing::info!("Server ready and listening");

    // Start server with graceful shutdown
    // Ctrl+C and SIGTERM are handled automatically
    match app.serve().await {
        Ok(()) => {
            tracing::info!("Server shut down gracefully");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Server error: {}", e);
            Err(Box::new(e) as Box<dyn std::error::Error>)
        }
    }
}
