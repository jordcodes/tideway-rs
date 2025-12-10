//! Development Mode Example
//!
//! Demonstrates development mode features including enhanced error responses,
//! request/response dumping, and stack traces.

use axum::{Json, Router, routing::get};
use serde_json::json;
use tideway::{App, ConfigBuilder, DevConfigBuilder, Result, TidewayError};

async fn success_handler() -> Json<serde_json::Value> {
    Json(json!({"status": "success", "message": "All good!"}))
}

async fn error_handler() -> Result<Json<serde_json::Value>> {
    Err(TidewayError::internal("This is a test error for dev mode"))
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tideway::init_tracing();

    // Create config with dev mode enabled
    let config = ConfigBuilder::new()
        .with_dev_config(
            DevConfigBuilder::new()
                .enabled(true)
                .with_stack_traces(true)
                .with_request_dumper(true)
                .build(),
        )
        .with_log_level("debug")
        .build();

    // Create app
    let app = App::with_config(config.unwrap()).merge_router(
        Router::new()
            .route("/success", get(success_handler))
            .route("/error", get(error_handler)),
    );

    println!("Dev mode server starting on http://localhost:8000");
    println!("Try:");
    println!("  - http://localhost:8000/success (successful response)");
    println!("  - http://localhost:8000/error (error response with stack trace)");
    println!();
    println!("Check logs for request/response dumps (JSON format)");

    // Start server
    app.serve().await.unwrap();
}
