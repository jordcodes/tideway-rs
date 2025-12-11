//! API Macro Example
//!
//! Demonstrates the `#[tideway::api]` macro for defining HTTP handlers
//! with automatic OpenAPI documentation generation.
//!
//! Run with: cargo run --example api_macro_example --features macros,openapi

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tideway::{api, App, AppContext, ConfigBuilder, Result, RouteModule};
use uuid::Uuid;

/// User response type
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
}

/// Create user request
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateUserRequest {
    pub name: String,
    pub email: String,
}

/// Get a user by ID
///
/// Retrieves user information based on the provided UUID.
#[api(get, "/users/:id", tag = "users")]
async fn get_user(
    State(_ctx): State<AppContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>> {
    // In a real app, this would query the database
    Ok(Json(UserResponse {
        id,
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
    }))
}

/// Create a new user
#[api(post, "/users", tag = "users", summary = "Create a new user account")]
async fn create_user(
    State(_ctx): State<AppContext>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>> {
    Ok(Json(UserResponse {
        id: Uuid::new_v4(),
        name: req.name,
        email: req.email,
    }))
}

/// List all users
#[api(get, "/users", tag = "users")]
async fn list_users(State(_ctx): State<AppContext>) -> Result<Json<Vec<UserResponse>>> {
    Ok(Json(vec![
        UserResponse {
            id: Uuid::new_v4(),
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
        },
        UserResponse {
            id: Uuid::new_v4(),
            name: "Bob".to_string(),
            email: "bob@example.com".to_string(),
        },
    ]))
}

/// Health check endpoint (no tag specified - uses default)
#[api(get, "/health", skip_openapi = true)]
async fn health_check() -> &'static str {
    "OK"
}

// Define the route module
struct UsersModule;

impl RouteModule for UsersModule {
    fn routes(&self) -> axum::Router<AppContext> {
        use axum::routing::get;

        axum::Router::new()
            .route("/users", get(list_users).post(create_user))
            .route("/users/:id", get(get_user))
            .route("/health", get(health_check))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

#[tokio::main]
async fn main() {
    tideway::init_tracing();

    let config = ConfigBuilder::new()
        .with_host("0.0.0.0")
        .with_port(3000)
        .from_env()
        .build()
        .expect("Failed to build config");

    let app = App::with_config(config).register_module(UsersModule);

    tracing::info!("API Macro Example running on http://0.0.0.0:3000");
    tracing::info!("Endpoints:");
    tracing::info!("  GET  /api/users");
    tracing::info!("  POST /api/users");
    tracing::info!("  GET  /api/users/:id");
    tracing::info!("  GET  /api/health");

    app.serve().await.unwrap();
}
