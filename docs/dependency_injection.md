# Dependency Injection with AppContext

Tideway's `AppContext` provides dependency injection for database pools, cache, and session stores.

## AppContext Structure

`AppContext` holds optional references to your application dependencies. Use helper methods for cleaner access:

```rust
use tideway::AppContext;

// Access dependencies with error handling
match context.database() {
    Ok(db) => {
        // Use database - returns error if not configured
    }
    Err(_) => {
        // Database not configured
    }
}

// Or use optional access
if let Some(cache) = context.cache_opt() {
    // Use cache - returns None if not configured
}

// Required dependency pattern
let sessions = context.sessions()?;  // Returns error if not configured
```

## Builder Pattern

Use the builder to construct your context:

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

## Using with Axum

Make `AppContext` available to your handlers via Axum's `State`:

```rust
use axum::{extract::State, Json};
use tideway::AppContext;

async fn my_handler(State(context): State<AppContext>) -> Json<Response> {
    // Use helper methods for cleaner access
    if let Ok(cache) = context.cache() {
        // Use cache - returns error if not configured
    }

    // Or use optional access
    if let Some(cache) = context.cache_opt() {
        // Use cache - returns None if not configured
    }

    Json(Response { /* ... */ })
}

// In your router setup:
let app = Router::new()
    .route("/api/endpoint", get(my_handler))
    .with_state(context);
```

## Dependency Patterns

### Pattern 1: Optional Dependencies

Handle missing dependencies gracefully:

```rust
async fn handler(State(ctx): State<AppContext>) -> Result<Response> {
    // Use optional access for graceful fallback
    let result = if let Some(cache) = ctx.cache_opt() {
        cache.get("key").await?
    } else {
        None
    };

    // Fallback logic when cache is unavailable
    Ok(Response { /* ... */ })
}
```

### Pattern 2: Required Dependencies

Assert dependencies exist:

```rust
async fn handler(State(ctx): State<AppContext>) -> Result<Response> {
    // Use helper method - returns error if not configured
    let db = ctx.database()?;

    // Use database
    Ok(Response { /* ... */ })
}
```

## Testing

Create test contexts with mock implementations:

```rust
use tideway::{AppContext, NoOpCache};

let test_context = AppContext::builder()
    .with_cache(Arc::new(NoOpCache))
    .build();
```
