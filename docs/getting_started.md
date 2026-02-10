# Getting Started

This guide takes you from `tideway new` to a working API using the canonical Tideway path.

## 1) Create a new app

```bash
tideway new my_app
cd my_app
tideway dev --fix-env
```

Or use the API preset:

```bash
tideway new my_app --preset api
cd my_app
tideway dev --fix-env
```

## 2) Run the server

```bash
tideway dev --fix-env
```

Visit:
- `http://localhost:8000/health`
- `http://localhost:8000/api`

## 3) Add a DB-backed resource (recommended)

```bash
tideway resource user --wire --db --repo --service --paginate --search
tideway migrate
tideway dev --fix-env
```

This command scaffolds routes, database entity/migration, repository, service, pagination, search, and wiring.

## 4) Add OpenAPI docs (optional)

If you prefer manual route modules and composition contracts, see:
- `docs/module_contracts.md`
- `docs/advanced_composition.md`
- `README.md` Core Concepts section

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

## 5) Add database access (optional advanced)

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

## 6) Add auth (optional advanced)

If you enabled `auth`, you can create a JWT issuer and wire your auth module:

```rust
use std::sync::Arc;
use tideway::auth::{JwtIssuer, JwtIssuerConfig};

let jwt_issuer = Arc::new(JwtIssuer::new(JwtIssuerConfig::with_secret(
    &std::env::var("JWT_SECRET")?,
    "my_app",
))?);
```

## 7) Configure middleware

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

## 8) Return structured errors

```rust
use tideway::{Result, TidewayError};

async fn get_user() -> Result<String> {
    Err(TidewayError::not_found("User not found"))
}
```

## 9) Test endpoints

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

## 10) Next steps

### Useful commands

```bash
tideway doctor
```

- See `docs/auth.md`, `docs/database_traits.md`, `docs/validation.md`
- For advanced existing-project wiring, see `docs/cli.md` (`tideway init`, `tideway backend`, `tideway add`)
