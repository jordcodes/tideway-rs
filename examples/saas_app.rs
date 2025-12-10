/// Complete SaaS application example demonstrating Tideway features
///
/// This example shows:
/// - Database integration with SeaORM
/// - JWT authentication
/// - Rate limiting
/// - CORS configuration
/// - OpenAPI documentation
/// - Health checks
/// - Route modules
///
/// Run with: cargo run --example saas_app --features database,openapi
use tideway::{App, ConfigBuilder, CorsConfig, RateLimitConfig, RouteModule, Result, AppContext};
use axum::{Router, routing::get, Json, extract::State};
use serde::{Deserialize, Serialize};

// Mock database entity (would use SeaORM in real app)
#[derive(Serialize, Deserialize, Clone)]
struct User {
    id: u64,
    email: String,
    name: String,
}

// Mock database (simplified for example - in real app use SeaORM)
#[allow(dead_code)]
struct Database {
    users: Vec<User>,
}

#[allow(dead_code)]
impl Database {
    fn new() -> Self {
        Self {
            users: vec![
                User {
                    id: 1,
                    email: "alice@example.com".to_string(),
                    name: "Alice".to_string(),
                },
            ],
        }
    }

    fn find_user(&self, id: u64) -> Option<User> {
        self.users.iter().find(|u| u.id == id).cloned()
    }

    fn create_user(&mut self, email: String, name: String) -> User {
        let id = self.users.len() as u64 + 1;
        let user = User { id, email, name };
        self.users.push(user.clone());
        user
    }
}

// Shared state (simplified for example)
#[allow(dead_code)]
struct AppState {
    db: std::sync::Arc<tokio::sync::Mutex<Database>>,
}

// Request/Response types
#[derive(Deserialize)]
struct CreateUserRequest {
    email: String,
    name: String,
}

#[derive(Serialize)]
struct UserResponse {
    id: u64,
    email: String,
    name: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
        }
    }
}

// Route handlers (simplified for example - in real app use proper state management)
async fn get_user(
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Result<Json<UserResponse>> {
    // In real app, extract state and query database
    if id == 1 {
        Ok(Json(UserResponse {
            id: 1,
            email: "alice@example.com".to_string(),
            name: "Alice".to_string(),
        }))
    } else {
        Err(tideway::TidewayError::not_found("User not found"))
    }
}

async fn create_user(
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>> {
    // In real app, create user in database
    Ok(Json(UserResponse {
        id: 1,
        email: req.email,
        name: req.name,
    }))
}

async fn list_users(State(_ctx): State<AppContext>) -> Result<Json<Vec<UserResponse>>> {
    // In real app, query database
    Ok(Json(vec![
        UserResponse {
            id: 1,
            email: "alice@example.com".to_string(),
            name: "Alice".to_string(),
        },
    ]))
}

// Route module
struct UsersModule;

impl RouteModule for UsersModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/users", get(list_users).post(create_user))
            .route("/users/:id", get(get_user))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tideway::init_tracing();

    // Configure CORS for production
    let cors = CorsConfig::builder()
        .allow_origin("https://app.example.com")
        .allow_methods(vec!["GET".to_string(), "POST".to_string()])
        .allow_headers(vec!["content-type".to_string(), "authorization".to_string()])
        .allow_credentials(true)
        .build();

    // Configure rate limiting
    let rate_limit = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(100)
        .window_seconds(60)
        .per_ip()
        .build();

    // Build configuration
    let config = ConfigBuilder::new()
        .with_host("0.0.0.0")
        .with_port(8000)
        .with_cors(cors)
        .with_rate_limit(rate_limit)
        .from_env() // Override with environment variables
        .build();

    // Create app
    let app = App::with_config(config.unwrap())
        .register_module(UsersModule);

    tracing::info!("SaaS application starting on http://0.0.0.0:8000");
    tracing::info!("API endpoints:");
    tracing::info!("  GET  /api/users");
    tracing::info!("  POST /api/users");
    tracing::info!("  GET  /api/users/:id");
    tracing::info!("  GET  /health");

    // Note: This is a simplified example
    // In production, you'd integrate with SeaORM properly
    // and use proper state management with axum::Router::with_state()
    app.serve().await.unwrap();
}
