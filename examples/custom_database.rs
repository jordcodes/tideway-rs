//! Example: Implementing a custom DatabasePool trait
//!
//! This example shows how to implement the DatabasePool trait
//! for a custom database backend.
//!
//! Run with: cargo run --example custom_database --features database

#[cfg(feature = "database")]
use tideway::{DatabasePool, DatabaseConnection, Result};
#[cfg(feature = "database")]
use async_trait::async_trait;
#[cfg(feature = "database")]
use std::sync::Arc;

#[cfg(not(feature = "database"))]
fn main() {
    println!("This example requires the 'database' feature");
    println!("Run with: cargo run --example custom_database --features database");
}

#[cfg(feature = "database")]

// Mock database connection
struct MockConnection {
    id: u64,
}

impl DatabaseConnection for MockConnection {
    fn is_valid(&self) -> bool {
        true
    }
}

// Custom database pool implementation
struct CustomDatabasePool {
    url: String,
}

impl CustomDatabasePool {
    fn new(url: String) -> Self {
        Self { url }
    }
}

#[async_trait]
impl DatabasePool for CustomDatabasePool {
    async fn connection(&self) -> Result<Box<dyn DatabaseConnection>> {
        // Create a mock connection
        Ok(Box::new(MockConnection { id: 1 }))
    }

    fn is_healthy(&self) -> bool {
        true
    }

    async fn close(self: Box<Self>) -> Result<()> {
        // Cleanup logic here
        Ok(())
    }

    fn connection_url(&self) -> Option<&str> {
        Some(&self.url)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tideway::init_tracing();

    // Create custom pool
    let pool: Arc<dyn DatabasePool> = Arc::new(
        CustomDatabasePool::new("custom://database/url".to_string())
    );

    // Use it in AppContext
    let _context = tideway::AppContext::builder()
        .with_database(pool.clone())
        .build();

    // Get a connection
    let conn = pool.connection().await?;
    println!("Got connection, valid: {}", conn.is_valid());

    println!("Custom database pool example completed!");
    Ok(())
}
