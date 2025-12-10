use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
/// Authentication flow example demonstrating JWT authentication
///
/// This example shows:
/// - User registration
/// - Login with JWT token generation
/// - Protected routes using AuthUser extractor
/// - Optional authentication
///
/// Run with: cargo run --example auth_flow
use tideway::{App, AppContext, Result, RouteModule};

// Mock user structure
#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: u64,
    email: String,
    password_hash: String, // In real app, use bcrypt/argon2
}

// Mock claims
#[derive(Clone, Deserialize, Serialize)]
struct Claims {
    sub: String,
    email: String,
    exp: usize,
}

impl Default for Claims {
    fn default() -> Self {
        Self {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
        }
    }
}

// Mock auth provider (simplified - in real app use tideway::auth::AuthProvider)
#[allow(dead_code)]
struct MockAuthProvider;

// Request/Response types
#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    #[allow(dead_code)]
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    #[allow(dead_code)]
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
    user: UserResponse,
}

#[derive(Serialize)]
struct UserResponse {
    id: u64,
    email: String,
}

// Route handlers
async fn register(Json(req): Json<RegisterRequest>) -> Result<Json<AuthResponse>> {
    // In real app: hash password, create user in database
    let user = User {
        id: 1,
        email: req.email,
        password_hash: "hashed_password".to_string(),
    };

    // In real app: generate JWT token
    let token = "mock_jwt_token".to_string();

    Ok(Json(AuthResponse {
        token,
        user: UserResponse {
            id: user.id,
            email: user.email,
        },
    }))
}

async fn login(Json(req): Json<LoginRequest>) -> Result<Json<AuthResponse>> {
    // In real app: verify password, generate JWT
    let user = User {
        id: 1,
        email: req.email,
        password_hash: "hashed_password".to_string(),
    };

    let token = "mock_jwt_token".to_string();

    Ok(Json(AuthResponse {
        token,
        user: UserResponse {
            id: user.id,
            email: user.email,
        },
    }))
}

async fn protected_profile() -> Result<Json<UserResponse>> {
    // In real app: extract user from AuthUser<YourAuthProvider>
    // For this example, return mock data
    Ok(Json(UserResponse {
        id: 1,
        email: "user@example.com".to_string(),
    }))
}

async fn public_info(State(_ctx): State<AppContext>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "This is public information",
        "requires_auth": false
    }))
}

// Route module
struct AuthModule;

impl RouteModule for AuthModule {
    fn routes(&self) -> Router<AppContext> {
        Router::<AppContext>::new()
            .route("/register", post(register))
            .route("/login", post(login))
            .route("/profile", get(protected_profile))
            .route("/info", get(public_info))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api/auth")
    }
}

#[tokio::main]
async fn main() {
    tideway::init_tracing();

    let app = App::new().register_module(AuthModule);

    tracing::info!("Auth flow example starting on http://0.0.0.0:8000");
    tracing::info!("Endpoints:");
    tracing::info!("  POST /api/auth/register");
    tracing::info!("  POST /api/auth/login");
    tracing::info!("  GET  /api/auth/profile (protected)");
    tracing::info!("  GET  /api/auth/info (public)");

    app.serve().await.unwrap();
}
