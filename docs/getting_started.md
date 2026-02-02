# Getting Started

This guide takes you from `tideway new` to a working API with routes, errors, and tests.

## 1) Create a new app

```bash
cargo install tideway-cli
tideway new my_app --features auth,database
cd my_app
cp .env.example .env
```

Or use the API preset:

```bash
tideway new my_app --preset api
```

## 2) Run the server

```bash
cargo run
```

Visit:
- `http://localhost:8000/health`
- `http://localhost:8000/api`

## 3) Add a route module

Create `src/routes/users.rs` and add it to `src/routes/mod.rs`:

```rust
pub mod users;
```

Then add the module file:

```rust
use axum::{routing::get, Router};
use tideway::{AppContext, MessageResponse, RouteModule};

pub struct UsersModule;

impl RouteModule for UsersModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/", get(list_users))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api/users")
    }
}

async fn list_users() -> MessageResponse {
    MessageResponse::success("Users list")
}
```

If you prefer less boilerplate, you can use the `module!` macro:

```rust
tideway::module!(
    UsersModule,
    prefix = "/api",
    routes = [
        (get, "/users", list_users),
        (get, "/users/:id", get_user),
    ]
);
```

Wire it in `src/main.rs`:

```rust
mod routes;

let app = App::new()
    .register_module(routes::ApiModule)
    .register_module(routes::users::UsersModule);
```

If you have many modules, you can use the helper macro:

```rust
let app = tideway::register_modules!(
    App::new(),
    routes::ApiModule,
    users::UsersModule,
);
```

If you already have a homogeneous list of modules (same type), you can also use
`App::register_modules(modules)` with any iterator.

For optional modules:

```rust
let app = tideway::register_modules!(
    App::new(),
    routes::ApiModule;
    optional: optional_module
);
```

For optional-only modules:

```rust
let app = tideway::register_optional_modules!(
    App::new(),
    optional_module
);
```

For the stable module composition contract (including `prelude` and
feature-gate behavior), see `docs/module_contracts.md`.

## 4) Add OpenAPI docs (optional)

If you enable the `openapi` feature, you can define small docs per module and merge them:

```rust
#[cfg(feature = "openapi")]
mod openapi_docs {
    tideway::openapi_doc!(pub(crate) UsersDoc, paths(crate::routes::users::list_users));
    tideway::openapi_components!(
        pub(crate) ComponentsDoc,
        schemas(crate::routes::users::UserResponse)
    );
}
```

Then wire them when OpenAPI is enabled:

```rust
#[cfg(feature = "openapi")]
if config.openapi.enabled {
    let openapi = tideway::openapi_merge_module!(openapi_docs, UsersDoc, ComponentsDoc);
    let openapi_router = tideway::openapi::create_openapi_router(openapi, &config.openapi);
    app = app.merge_router(openapi_router);
}
```

## 5) Add database access (optional)

If you enabled `database`, wire a SeaORM pool into the app context:

```rust
use std::sync::Arc;
use tideway::{AppContext, SeaOrmPool};

let db = sea_orm::Database::connect(&std::env::var("DATABASE_URL")?).await?;
let context = AppContext::builder()
    .with_database(Arc::new(SeaOrmPool::new(db, std::env::var("DATABASE_URL")?)))
    .build();

let app = App::new()
    .with_context(context)
    .register_module(routes::ApiModule);
```

## 5) Add auth (optional)

If you enabled `auth`, you can create a JWT issuer and wire your auth module:

```rust
use std::sync::Arc;
use tideway::auth::{JwtIssuer, JwtIssuerConfig};

let jwt_issuer = Arc::new(JwtIssuer::new(JwtIssuerConfig::with_secret(
    &std::env::var("JWT_SECRET")?,
    "my_app",
))?);
```

## 6) Configure middleware

Tideway applies sensible defaults when you use `serve()`, but you can customize config:

```rust
use tideway::ConfigBuilder;

let config = ConfigBuilder::new()
    .with_log_level("debug")
    .with_dev_mode(true)
    .build()?;

let app = App::with_config(config)
    .register_module(routes::ApiModule);
```

If you need to manually serve with Axum, use middleware-aware router:

```rust
let router = app.into_router_with_middleware();
axum::serve(listener, router).await?;
```

If you want to add a layer that should apply after all modules are registered:

```rust
let app = App::new()
    .register_module(routes::ApiModule)
    .with_global_layer(my_layer);
```

## 7) Return structured errors

```rust
use tideway::{Result, TidewayError};

async fn get_user() -> Result<String> {
    Err(TidewayError::not_found("User not found"))
}
```

## 8) Test endpoints

```rust
use tideway::testing::get as test_get;

#[tokio::test]
async fn test_health() {
    let app = tideway::App::new().into_router();

    test_get(app, "/health")
        .execute()
        .await
        .assert_ok();
}
```

## 9) Next steps

### Useful commands

```bash
tideway doctor
tideway init --minimal
```

- See `docs/auth.md`, `docs/database_traits.md`, `docs/validation.md`
- Try `tideway doctor` for setup checks
