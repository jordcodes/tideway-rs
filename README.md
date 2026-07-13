# Tideway

[![Crates.io](https://img.shields.io/crates/v/tideway.svg)](https://crates.io/crates/tideway)
[![Documentation](https://docs.rs/tideway/badge.svg)](https://docs.rs/tideway)
[![License](https://img.shields.io/crates/l/tideway.svg)](https://github.com/jordcodes/tideway-rs)

**Tideway** is a batteries-included Rust web framework built on [Axum](https://github.com/tokio-rs/axum) and [Tokio](https://tokio.rs/). It provides opinionated defaults for building SaaS applications quickly while maintaining the performance and flexibility you expect from Rust. The primary CLI path and tested scaffolds target backend/API workflows; frontend helpers are advanced and currently Vue-focused.

## Features

- **Fast & Reliable**: Built on Axum and Tokio for maximum performance
- **Batteries Included**: Pre-configured logging, tracing, error handling, and health checks
- **Modular Architecture**: Organize your application into reusable route modules
- **Trait-Based Extensibility**: Swap database, cache, session, and email implementations easily
- **Production Middleware**: Compression, security headers, timeouts, and Prometheus metrics
- **Request Validation**: Type-safe validation with custom validators and extractors
- **Enhanced Error Handling**: Rich error responses with context, IDs, and dev-mode stack traces
- **Background Jobs**: In-memory and Redis-backed job queues with retry logic
- **Email**: SMTP and console mailers with support for Resend, SendGrid, and more
- **Developer Experience**: Alba-style testing, test fixtures, dev request dumping, and richer dev errors
- **WebSocket Support**: Real-time communication with connection management and broadcasting
- **Type-Safe**: Full Rust type safety with excellent error messages
- **Production Ready**: Graceful shutdown, request IDs, and structured logging out of the box
- **Developer Friendly**: Simple, intuitive API with sensible defaults

## Feature Matrix

Feature flags are opt-in unless marked Default.

| Feature | Module | Docs | Example | Notes |
| --- | --- | --- | --- | --- |
| `feature-gate-errors` | — | — | — | Optional compile-time errors for missing features |
| `feature-gate-warnings` | — | — | — | Optional warnings for missing features |
| `macros` | `tideway-macros` / `openapi` | `docs/openapi.md` | `examples/api_macro_example.rs` | Default |
| `database` | `database` | `docs/database_traits.md` | `examples/custom_database.rs` | Default (SeaORM) |
| `database-sqlx` | `database` | `docs/database_traits.md` | — | Experimental placeholder only; not implemented yet |
| `openapi` | `openapi` | `docs/openapi.md` | `examples/api_macro_example.rs` | Default |
| `validation` | `validation` | `docs/validation.md` | `examples/validation_example.rs` | — |
| `metrics` | `metrics` | `README.md#built-in-middleware` | `tests/metrics_integration_test.rs` | — |
| `cache` | `cache` | `docs/caching.md` | `examples/redis_cache.rs` | — |
| `cache-redis` | `cache` | `docs/caching.md` | `examples/redis_cache.rs` | — |
| `sessions` | `session` | `docs/sessions.md` | `examples/sessions_example.rs` | — |
| `jobs` | `jobs` | `docs/background_jobs.md` | `examples/background_jobs.rs` | — |
| `jobs-redis` | `jobs` | `docs/background_jobs.md` | — | — |
| `websocket` | `websocket` | `docs/websockets.md` | `examples/websocket_chat.rs` | — |
| `email` | `email` | `docs/email.md` | `examples/email_example.rs` | — |
| `auth` | `auth` | `docs/auth.md` | `examples/seaorm_auth.rs` | — |
| `auth-mfa` | `auth::mfa` | `docs/auth.md` | `examples/seaorm_auth.rs` | — |
| `auth-breach` | `auth::breach` | `docs/auth.md` | — | — |
| `test-auth-bypass` | `auth` | `docs/auth.md` | `tests/auth_integration_test.rs` | Tests only |
| `billing` | `billing` | `docs/billing.md` | — | — |
| `billing-seaorm` | `billing` | `docs/billing.md` | — | — |
| `test-billing` | `billing` | `docs/billing.md` | `tests/` | Tests only |
| `organizations` | `organizations` | `docs/organizations.md` | — | — |
| `organizations-seaorm` | `organizations` | `docs/organizations.md` | — | — |
| `organizations-billing` | `organizations` | `docs/organizations.md` | — | — |
| `test-organizations` | `organizations` | `docs/organizations.md` | `tests/` | Tests only |
| `test-containers` | `testing` | `docs/testing.md` | `docs/testing.md` | Optional container-backed postgres for integration tests |
| `admin` | `admin` | `docs/admin.md` | — | — |

## Quick Start

### CLI (Fastest Start)

Use the CLI to scaffold the recommended API-first Tideway app:

```bash
cargo install tideway-cli
tideway new my_app
cd my_app
tideway dev --fix-env
```

`tideway dev` verifies that the configured port is free, then watches Rust sources, migrations, Cargo manifests, and `.env` by default. Successful builds restart the server; failed builds leave the last working server running. Use `tideway dev --no-watch` for a one-shot run.

Then visit `http://localhost:8000/health`.
If OpenAPI is enabled, visit `http://localhost:8000/swagger-ui`.
Generated authentication and MFA operations are included in the API preset's OpenAPI document, including JWT bearer security. `--fix-env` creates independent random local JWT and MFA encryption secrets without changing configured values; production secrets belong in your deployment secret manager.

The default API-first scaffold uses SQLite for local development.
If you want local Postgres instead, add `--with-docker` and start it with `docker compose up -d`.
It also seeds a sample `todo` resource that already follows the recommended entity -> repository -> service path, with pagination and `q` search on the list route.

Canonical next step: run `tideway resource <name>` to add a fully wired DB-backed
resource, then run `tideway migrate`. The zero-flag API profile includes routes,
an entity and migration, a repository, a service, pagination, and search.

Optional sanity check: run `tideway doctor` if you want a project/setup audit before you keep building.

When no flags are provided, the CLI will prompt you interactively (similar to Vite).
The first interactive screen promotes `api`, `saas`, and `worker`; advanced paths like `minimal`, backend presets, and custom feature picking are still available, but one step deeper.
Use `--no-prompt` for the same API-first defaults in CI/non-interactive runs.
Use `--preset minimal` only when you explicitly want the lightweight starter.
For preset variants (`api`, `saas`, `worker`), see `docs/cli.md`.
Frontend `generate` / `setup` helpers are advanced and currently intended for existing Vue apps, not the primary onboarding path.

### Agent Quickstart

If you're using coding agents (Codex, Claude Code, OpenCode), start here:

- Use `tideway new my_app` and follow the wizard (fastest path).
- Add full API resources with `tideway resource <name>`.
- Run `tideway dev --fix-env` to boot with env + migrations.

Agent-friendly flags:
- `--json` emits machine-readable JSON lines.
- `--plan` shows planned file operations without writing.

Project-specific guidance lives in `SKILLS.md`.

### Getting Started Guide

Read the full walkthrough at `docs/getting_started.md`.
For module composition contracts, see `docs/module_contracts.md`.
For recovery from common CLI failures, see `docs/error_recovery.md`.

### CLI Reference

See `docs/cli.md` for command examples.
Maintainers: see `docs/maintainer_verify.md` for `scripts/verify.sh` troubleshooting.

**Common `tideway new` flags:**
| Flag | Example | Purpose |
| --- | --- | --- |
| `--preset` | `--preset api` | Apply a preset scaffold |
| `--features` | `--features auth,database` | Enable crate features |
| `--with-config` | `--with-config` | Generate `config.rs` / `error.rs` |
| `--with-docker` | `--with-docker` | Add `docker-compose.yml` |
| `--with-ci` | `--with-ci` | Add GitHub Actions workflow |
| `--with-env` | `--with-env` | Generate `.env.example` |
| `--no-prompt` | `--no-prompt` | Disable interactive prompts |

### Library Usage (Optional Advanced)

If you prefer integrating Tideway directly as a dependency (without CLI scaffolding):

#### Installation

Add Tideway to your `Cargo.toml`:

```toml
[dependencies]
tideway = "0.7.22"
tokio = { version = "1.48", features = ["macros", "rt-multi-thread"] }
```

#### Hello World

```rust
use tideway::{self, App, ConfigBuilder};

#[tokio::main]
async fn main() {
    // Initialize logging
    tideway::init_tracing();

    // Create app with default configuration
    let app = App::new();

    // Start server
    app.serve().await.unwrap();
}
```

#### Manual Serving

If you want to serve Tideway with `axum::serve`, use the middleware-aware router:

```rust
use tideway::App;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = App::new();
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app.into_make_service_with_connect_info()).await
}
```

Note: `into_router()` does **not** apply the full middleware stack. Use
`into_router_with_middleware()` when you need the raw router, and
`into_make_service_with_connect_info()` when you want manual serving to match
`serve()` including client address wiring.

Run your app:

```bash
cargo run
```

Visit `http://localhost:8000/health` to see the built-in health check.

## Core Concepts

Canonical onboarding path:
- `tideway new my_app`
- `tideway dev --fix-env`
- `tideway resource <name>`
- `tideway migrate`

For advanced/manual composition patterns, see `docs/module_contracts.md`.

### 1. Application Structure

Tideway applications are organized into layers:

```
src/
├── main.rs           # Application entry point
├── lib.rs           # Library exports
└── routes/          # Your application routes
    └── ...
```

When using Tideway as a dependency, import from the `tideway` crate:

```rust
use tideway::{App, ConfigBuilder, Result, TidewayError};
```
For onboarding, prefer one composition style:
- define modules with `module!`
- register them with `App::register_module(...)`
- let the scaffold own `main.rs` wiring unless you intentionally need an advanced/manual setup

For advanced composition variants, manual OpenAPI composition, or trait-based module contracts,
see `docs/advanced_composition.md`, `docs/module_contracts.md`, and `docs/openapi.md`.

**Quick guards with `ensure!`:**
```rust
use tideway::ensure;

ensure!(user.is_admin, TidewayError::forbidden("Admin access required"));
ensure!(user.id != target_id, "Cannot delete your own account");
```
See `docs/error_handling.md` for more examples.

**Testing helpers (HTTP):**
```rust
use tideway::testing::get as test_get;
use tideway::{App, RouteModule};

let app = App::new().register_module(UsersModule).into_router();
test_get(app, "/api/users")
    .execute()
    .await
    .assert_ok();
```
See `docs/testing.md` for more helpers.

### 2. Configuration

Configure your application with environment variables or code:

```rust
use tideway::ConfigBuilder;

let config = ConfigBuilder::new()
    .with_host("0.0.0.0")
    .with_port(3000)
    .with_log_level("debug")
    .with_max_body_size(50 * 1024 * 1024) // 50MB global limit
    .from_env()  // Override with TIDEWAY_* env vars
    .build()?;  // Returns Result<Config> - validates configuration
```

**Environment Variables:**
- `TIDEWAY_HOST` - Server host (default: 0.0.0.0)
- `TIDEWAY_PORT` - Server port (default: 8000)
- `TIDEWAY_LOG_LEVEL` - Log level (default: info)
- `TIDEWAY_LOG_JSON` - Enable JSON logging (default: false)
- `TIDEWAY_MAX_BODY_SIZE` - Maximum request body size in bytes (default: 10MB)
- `RUST_LOG` - Standard Rust log filter

### 3. Route Modules

Canonical module style:

```rust
tideway::module!(
    UsersModule,
    prefix = "/api",
    routes = [
        (get, "/users", list_users),
        (post, "/users", create_user),
    ]
);

let app = App::new().register_module(UsersModule);
```

Use this style for onboarding and examples.
For trait-based `RouteModule` implementations, grouped route syntax, mixed module lists, optional modules,
or iterator registration, see `docs/module_contracts.md` and `docs/advanced_composition.md`.

### 4. Error Handling

Use `TidewayError` for consistent error responses:

```rust
use tideway::{Result, TidewayError, ErrorContext};
use axum::Json;

async fn get_user(id: u64) -> Result<Json<User>> {
    let user = database.find(id)
        .ok_or_else(|| {
            TidewayError::not_found("User not found")
                .with_context(
                    ErrorContext::new()
                        .with_error_id(uuid::Uuid::new_v4().to_string())
                        .with_detail(format!("User ID {} does not exist", id))
                )
        })?;

    Ok(Json(user))
}
```

**Error Types:**
- `TidewayError::not_found(msg)` - 404 Not Found
- `TidewayError::bad_request(msg)` - 400 Bad Request
- `TidewayError::unauthorized(msg)` - 401 Unauthorized
- `TidewayError::forbidden(msg)` - 403 Forbidden
- `TidewayError::internal(msg)` - 500 Internal Server Error
- `TidewayError::service_unavailable(msg)` - 503 Service Unavailable

**Quick Guards with `ensure!`:**
```rust
use tideway::{ensure, Result, TidewayError};

fn require_admin(user: &User) -> Result<()> {
    ensure!(user.is_admin, TidewayError::forbidden("Admin access required"));
    Ok(())
}
```

```rust
fn prevent_self_delete(user: &User, target_id: uuid::Uuid) -> Result<()> {
    ensure!(user.id != target_id, "Cannot delete your own account");
    Ok(())
}
```

**Enhanced Error Responses:**
All errors automatically return JSON responses with:
- Error message
- Unique error ID for tracking
- Optional details and context
- Field-specific validation errors
- Stack traces (in dev mode when enabled)

```json
{
  "error": "Bad request: Validation failed",
  "error_id": "550e8400-e29b-41d4-a716-446655440000",
  "details": "Invalid input data",
  "field_errors": {
    "email": ["must be a valid email"],
    "age": ["must be between 18 and 100"]
  }
}
```

### 5. Request Validation

Validate request data with type-safe extractors:

```rust
use tideway::validation::{ValidatedJson, ValidatedQuery, validate_uuid};
use validator::Validate;
use serde::Deserialize;

#[derive(Deserialize, Validate)]
struct CreateUserRequest {
    #[validate(email)]
    email: String,
    #[validate(custom = "validate_uuid")]
    organization_id: String,
    #[validate(length(min = 8))]
    password: String,
}

async fn create_user(
    ValidatedJson(req): ValidatedJson<CreateUserRequest>
) -> tideway::Result<axum::Json<serde_json::Value>> {
    // req is guaranteed to be valid
    Ok(axum::Json(serde_json::json!({"status": "created"})))
}

#[derive(Deserialize, Validate)]
struct SearchQuery {
    #[validate(length(min = 1, max = 100))]
    q: String,
    #[validate(range(min = 1, max = 100))]
    limit: Option<u32>,
}

async fn search(
    ValidatedQuery(query): ValidatedQuery<SearchQuery>
) -> tideway::Result<axum::Json<serde_json::Value>> {
    // query is guaranteed to be valid
    Ok(axum::Json(serde_json::json!({"results": []})))
}
```

**Custom Validators:**
- `validate_uuid()` - UUID v4 validation
- `validate_slug()` - Slug format validation
- `validate_phone()` - Phone number validation
- `validate_json_string()` - JSON string validation
- `validate_duration()` - Duration format (30s, 5m, 1h, 2d)

### 6. Response Helpers

Use `ApiResponse` for standardized JSON responses:

```rust
use tideway::{ApiResponse, PaginatedData, PaginationMeta};
use axum::Json;

async fn list_todos(page: u32) -> Json<ApiResponse<PaginatedData<Todo>>> {
    let todos = get_todos_from_db(page);
    Json(ApiResponse::paginated(todos.items, PaginationMeta {
        page,
        per_page: 20,
        total: todos.total,
    }))
}

async fn create_todo() -> tideway::Result<CreatedResponse<Todo>> {
    let todo = create_todo_in_db();
    Ok(CreatedResponse::new(todo, "/api/todos/123"))
}
```

**Response Formats:**
```json
// Success response
{
  "success": true,
  "data": [...],
  "message": "Optional message"
}

// Paginated response
{
  "success": true,
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 100
  }
}

// Created response (201)
{
  "success": true,
  "data": {...},
  "location": "/api/todos/123"
}
```

### 7. Health Checks

The built-in `/health` endpoint is automatically available. Customize health checks:

```rust
use tideway::health::{HealthCheck, ComponentHealth, HealthStatus};
use std::pin::Pin;

struct DatabaseHealthCheck;

impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    fn check(&self) -> Pin<Box<dyn Future<Output = ComponentHealth> + Send + '_>> {
        Box::pin(async {
            // Check database connection
            let is_healthy = check_db_connection().await;

            ComponentHealth {
                name: "database".to_string(),
                status: if is_healthy {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unhealthy
                },
                message: Some("Database connection status".to_string()),
            }
        })
    }
}
```

### 8. Testing

Tideway provides Alba-style testing utilities for easy HTTP endpoint testing:

```rust
use tideway::testing::{get, post, TestDb};
use tideway::testing::fake;

#[tokio::test]
async fn test_create_user() {
    let app = create_app();
    let user_data = serde_json::json!({
        "email": fake::email(),
        "name": fake::name(),
    });

    post(app, "/api/users")
        .with_json(&user_data)
        .execute()
        .await
        .assert_created()
        .assert_json_path("data.email", user_data["email"].clone())
        .await;
}

#[tokio::test]
async fn test_with_database() {
    let db = TestDb::new().await.unwrap();

    db.seed("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)").await.unwrap();

    db.with_transaction_rollback(|tx| async move {
        // Test code - transaction will be rolled back
        // Database state is isolated between tests
    }).await.unwrap();
}
```

### 9. Development Mode

Enable development mode for request dumping and richer debugging responses:

```rust
use tideway::{ConfigBuilder, DevConfigBuilder};

let config = ConfigBuilder::new()
    .with_dev_config(
        DevConfigBuilder::new()
            .enabled(true)
            .with_stack_traces(true)
            .with_request_dumper(true)
            .build()
    )
    .build()?;  // Returns Result<Config> - validates configuration
```

`with_request_dumper(true)` is applied by Tideway's middleware stack.
`with_stack_traces(true)` adds stack traces to normal `TidewayError` responses during dev-mode requests.

**Environment Variables:**
- `TIDEWAY_DEV_MODE` - Enable dev mode (default: false)
- `TIDEWAY_DEV_STACK_TRACES` - Include stack traces (default: false)
- `TIDEWAY_DEV_DUMP_REQUESTS` - Enable request dumper (default: false)
- `TIDEWAY_DEV_DUMP_PATH` - Path pattern to dump (default: all)

### 10. Logging & Tracing

Structured logging is enabled by default:

```rust
#[tokio::main]
async fn main() {
    // Initialize with defaults
    tideway::init_tracing();

    // Or with custom config
    let config = ConfigBuilder::new().build();
    tideway::init_tracing_with_config(&config);

    tracing::info!("Application started");
    tracing::debug!(user_id = 123, "Processing request");
}
```

All HTTP requests are automatically logged with:
- Request ID (x-request-id header)
- Method and URI
- Response status
- Response time in milliseconds

## Examples

Tideway includes comprehensive examples demonstrating real-world usage:

### Complete SaaS Application

[`examples/saas_app.rs`](examples/saas_app.rs) - Full-featured SaaS app with:
- Database integration
- JWT authentication
- Rate limiting
- CORS configuration
- OpenAPI documentation
- Health checks

```bash
cargo run --example saas_app --features database,openapi
```

### Custom Database Implementation

[`examples/custom_database.rs`](examples/custom_database.rs) - Implementing a custom `DatabasePool`:

```bash
cargo run --example custom_database --features database
```

### Redis Caching

[`examples/redis_cache.rs`](examples/redis_cache.rs) - Using Redis for caching:

```bash
cargo run --example redis_cache --features cache-redis
```

### Session Management

[`examples/sessions_example.rs`](examples/sessions_example.rs) - Session management examples:

```bash
cargo run --example sessions_example --features sessions
```

### Authentication Flow

[`examples/auth_flow.rs`](examples/auth_flow.rs) - Complete auth implementation:
- User registration
- Login with JWT
- Protected routes
- Public endpoints

```bash
cargo run --example auth_flow
```

### Testing Guide

[`examples/testing_example.rs`](examples/testing_example.rs) - Testing patterns:
- Alba-style HTTP testing
- Database testing with TestDb
- Error case testing

```bash
cargo test --example testing_example
```

### Validation Example

[`examples/validation_example.rs`](examples/validation_example.rs) - Request validation:
- ValidatedJson extractor
- ValidatedQuery extractor
- Custom validators
- Field-level error handling

```bash
cargo run --example validation_example --features validation
```

### Development Mode

[`examples/dev_mode.rs`](examples/dev_mode.rs) - Development tools:
- Enhanced error responses
- Request/response dumper
- Stack trace debugging

```bash
cargo run --example dev_mode
```

### Production Configuration

[`examples/production_config.rs`](examples/production_config.rs) - Production setup:
- Environment-based config
- Logging setup
- Graceful shutdown
- Health monitoring

```bash
cargo run --example production_config
```

### WebSocket Chat

[`examples/websocket_chat.rs`](examples/websocket_chat.rs) - Real-time chat with rooms:
- WebSocket connection handling
- Room management
- Broadcasting messages
- User join/leave notifications

```bash
cargo run --example websocket_chat --features websocket
```

### WebSocket Notifications

[`examples/websocket_notifications.rs`](examples/websocket_notifications.rs) - Real-time notifications:
- Server-to-client push notifications
- User-specific channels
- Integration with background jobs

```bash
cargo run --example websocket_notifications --features websocket
```

## Architecture

Tideway follows a layered architecture:

```
┌─────────────────────────────────┐
│         HTTP Layer              │
│  (Routes, Middleware, Handlers) │
├─────────────────────────────────┤
│       Application Core          │
│   (Business Logic, Services)    │
├─────────────────────────────────┤
│      Infrastructure             │
│ (Database, Cache, External APIs)│
└─────────────────────────────────┘
```

**Key Components:**

- **App**: Main application structure with routing and middleware
- **AppContext**: Dependency injection container for shared state (database, cache, sessions)
- **RouteModule**: Trait for modular route organization
- **Config**: Environment-aware configuration
- **TidewayError**: Unified error handling
- **ApiResponse**: Standardized JSON responses

**Trait-Based Components:**

- **DatabasePool**: Abstract database connection pooling (SeaORM, SQLx placeholder)
- **Cache**: Key-value caching abstraction (in-memory, Redis)
- **SessionStore**: Session management abstraction (in-memory, cookie-based)
- **JobQueue**: Background job processing (in-memory, Redis)
- **ConnectionManager**: WebSocket connection management (rooms, broadcasting)

## Built-in Middleware

All requests automatically include:

1. **Request ID**: Unique UUID for request tracking
2. **Body Size Limit**: Global default limit (10MB) to prevent DoS attacks
3. **Tracing**: Structured logging with request/response details
4. **Error Handling**: Automatic error to JSON response conversion
5. **CORS**: Configurable CORS support (disabled by default for security)
6. **Rate Limiting**: Per-IP and global rate limiting (health endpoints excluded)
7. **Compression**: Gzip/Brotli response compression
8. **Security Headers**: HSTS, CSP, X-Frame-Options, and more
9. **Timeout**: Configurable request timeouts
10. **Request Logging**: Structured request/response logging
11. **Metrics**: Prometheus metrics collection (optional, uses route templates when available)

## Dependency Injection

Tideway provides `AppContext` for dependency injection:

```rust
use tideway::{AppContext, SeaOrmPool, InMemoryCache, InMemorySessionStore};
use std::sync::Arc;

let db_pool = Arc::new(SeaOrmPool::from_config(&db_config).await?);
let cache = Arc::new(InMemoryCache::new(10000));
let sessions = Arc::new(InMemorySessionStore::new(Duration::from_secs(3600)));

let context = AppContext::builder()
    .with_database(db_pool)
    .with_cache(cache)
    .with_sessions(sessions)
    .build();
```

Use in your handlers:

```rust
use axum::extract::State;
use tideway::AppContext;

async fn my_handler(State(ctx): State<AppContext>) -> Json<Response> {
    // Use helper methods for cleaner access
    if let Ok(cache) = ctx.cache() {
        // Use cache - returns error if not configured
    }

    // Or use optional access
    if let Some(cache) = ctx.cache_opt() {
        // Use cache - returns None if not configured
    }

    Json(Response { /* ... */ })
}
```

## Database, Cache & Sessions

### Database

Tideway exposes a database abstraction through the `DatabasePool` trait, but the built-in production path today is SeaORM:

- **SeaORM** (default): Full-featured ORM with migrations
- **SQLx** (`database-sqlx`): Experimental placeholder only (not implemented yet)

```rust
use tideway::{SeaOrmPool, DatabasePool};

let pool = SeaOrmPool::from_config(&config).await?;
let pool: Arc<dyn DatabasePool> = Arc::new(pool);
```

### Cache

Multiple cache backends supported:

- **In-Memory**: Fast HashMap-based cache (default)
- **Redis**: Distributed caching with `cache-redis` feature

```rust
use tideway::cache::{InMemoryCache, RedisCache};
use tideway::CacheExt; // Provides get<T>() and set<T>()

let cache: Arc<dyn Cache> = Arc::new(InMemoryCache::new(10000));

// Type-safe operations
cache.set("user:123", &user_data, Some(Duration::from_secs(3600))).await?;
let user: Option<User> = cache.get("user:123").await?;
```

### Sessions

Session management with multiple storage backends:

- **In-Memory**: For development/testing
- **Cookie-Based**: Encrypted cookie sessions

```rust
use tideway::session::{InMemorySessionStore, CookieSessionStore};
use tideway::{SessionStore, SessionData};

let store: Arc<dyn SessionStore> = Arc::new(
    InMemorySessionStore::new(Duration::from_secs(3600))
);

let mut session = SessionData::new(Duration::from_secs(3600));
session.set("user_id".to_string(), "123".to_string());
store.save("session-id", session).await?;
```

See [`docs/database_traits.md`](docs/database_traits.md), [`docs/caching.md`](docs/caching.md), and [`docs/sessions.md`](docs/sessions.md) for detailed documentation.

## Testing

Tideway applications are easy to test, and include Alba-style helpers:

```rust
use tideway::testing::{get, post};
use tideway::testing::fake;

#[tokio::test]
async fn test_create_user() {
    let app = create_app();

    post(app, "/api/users")
        .with_json(&serde_json::json!({
            "email": fake::email(),
            "name": fake::name(),
        }))
        .execute()
        .await
        .assert_created();
}
```

For Alba-style host bootstrapping and dependency overrides, prefer
`TestHost::builder(app)` for prebuilt apps and `TestHost::bootstrap()` when the
spec needs config or environment overrides; see [`docs/testing.md`](docs/testing.md).

See [`docs/testing.md`](docs/testing.md) and [`examples/testing_example.rs`](examples/testing_example.rs) for more patterns.

Run tests:

```bash
cargo test
```

## Roadmap

### Completed ✅
- [x] Rate limiting middleware
- [x] CORS configuration
- [x] OpenAPI/Swagger generation
- [x] Request validation support
- [x] Compression middleware
- [x] Security headers middleware
- [x] Request/response logging
- [x] Timeout middleware
- [x] Prometheus metrics
- [x] Global request body size limit (DoS protection)
- [x] Trait-based database abstraction (SeaORM)
- [x] Trait-based caching (in-memory, Redis)
- [x] Trait-based session management (in-memory, cookies)
- [x] Dependency injection with AppContext
- [x] Custom validators (UUID, slug, phone, JSON, duration)
- [x] ValidatedQuery and ValidatedForm extractors
- [x] Enhanced error handling (context, IDs, dev-mode stack traces)
- [x] Alba-style testing utilities
- [x] Test fixtures and fake data helpers
- [x] Database testing improvements (seed, reset, transactions)
- [x] Development mode configuration, richer error responses, and request dumper
- [x] Response helpers (paginated, created, no_content)
- [x] WebSocket support (connection management, rooms, broadcasting)

### In Progress 🚧
- [ ] SQLx database backend implementation

### Planned 📋
- [ ] CLI tool for scaffolding
- [ ] Deployment guides
- [ ] Additional cache backends (Memcached)
- [ ] Additional session backends (database-backed)

## Performance

Tideway adds minimal overhead compared to raw Axum. Benchmarks are available in the `benches/` directory.

Run benchmarks:

```bash
cargo bench
```

See [`benches/README.md`](benches/README.md) for detailed performance metrics.

## Contributing

Contributions are welcome! This is currently in early development.

## License

MIT

## Acknowledgments

Built with:
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Tokio](https://tokio.rs/) - Async runtime
- [Tower](https://github.com/tower-rs/tower) - Middleware
- [Tracing](https://github.com/tokio-rs/tracing) - Logging

---

**Start building your SaaS with Tideway today!**
