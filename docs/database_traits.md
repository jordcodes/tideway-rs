# Database Traits

Tideway provides a trait-based abstraction for database connection pooling, allowing you to swap between SeaORM, SQLx, or custom implementations without changing your application code.

## DatabasePool Trait

The `DatabasePool` trait abstracts database connection management:

```rust
use tideway::DatabasePool;

async fn example(pool: Arc<dyn DatabasePool>) -> tideway::Result<()> {
    let conn = pool.connection().await?;

    // Use the connection...
    // Note: You may need to downcast to the concrete type for specific operations

    Ok(())
}
```

## Implementations

### SeaORM

The default database implementation uses SeaORM:

```rust
use tideway::{AppContext, SeaOrmPool};
use std::sync::Arc;

#[tokio::main]
async fn main() -> tideway::Result<()> {
    let config = tideway::database::DatabaseConfig {
        url: "postgres://user:pass@localhost/db".to_string(),
        ..Default::default()
    };

    let pool = SeaOrmPool::from_config(&config).await?;
    let pool: Arc<dyn DatabasePool> = Arc::new(pool);

    let context = AppContext::builder()
        .with_database(pool)
        .build();

    // Use context in your app...
    Ok(())
}
```

### SQLx (Coming Soon)

SQLx support is planned for a future release.

## Custom Implementation

You can implement `DatabasePool` for your own database backend:

```rust
use tideway::{DatabasePool, DatabaseConnection};
use async_trait::async_trait;

struct MyCustomPool {
    // Your pool implementation
}

#[async_trait]
impl DatabasePool for MyCustomPool {
    async fn connection(&self) -> tideway::Result<Box<dyn DatabaseConnection>> {
        // Return a connection
    }

    fn is_healthy(&self) -> bool {
        // Check health
    }

    async fn close(self: Box<Self>) -> tideway::Result<()> {
        // Cleanup
    }

    fn connection_url(&self) -> Option<&str> {
        Some("your://connection/url")
    }
}
```

## Environment Variables

- `DATABASE_URL` - Connection string
- `DATABASE_MAX_CONNECTIONS` - Max pool size (default: 10)
- `DATABASE_MIN_CONNECTIONS` - Min pool size (default: 1)
- `DATABASE_CONNECT_TIMEOUT` - Connection timeout in seconds (default: 30)
- `DATABASE_AUTO_MIGRATE` - Run migrations on startup (default: false)
