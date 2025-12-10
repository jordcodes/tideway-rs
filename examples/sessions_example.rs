//! Example: Using cookie-based sessions
//!
//! This example demonstrates session management with cookie storage.
//! Requires the `sessions` feature.
//!
//! Run with: cargo run --example sessions_example --features sessions

#[cfg(feature = "sessions")]
use tideway::session::{CookieSessionStore, SessionConfig, InMemorySessionStore};
#[cfg(feature = "sessions")]
use tideway::{SessionStore, SessionData};
#[cfg(feature = "sessions")]
use std::sync::Arc;
#[cfg(feature = "sessions")]
use std::time::Duration;

#[cfg(not(feature = "sessions"))]
fn main() {
    println!("This example requires the 'sessions' feature");
    println!("Run with: cargo run --example sessions_example --features sessions");
}

#[cfg(feature = "sessions")]

#[tokio::main]
async fn main() -> tideway::Result<()> {
    tideway::init_tracing();

    // Example 1: In-memory sessions (for development)
    println!("=== In-Memory Sessions ===");
    let memory_store: Arc<dyn SessionStore> = Arc::new(
        InMemorySessionStore::new(Duration::from_secs(3600))
    );

    let session_id = "session-abc123";
    let mut session = SessionData::new(Duration::from_secs(3600));
    session.set("user_id".to_string(), "123".to_string());
    session.set("username".to_string(), "alice".to_string());

    memory_store.save(session_id, session.clone()).await?;
    println!("Saved session: {}", session_id);

    if let Some(loaded) = memory_store.load(session_id).await? {
        println!("Loaded session - User ID: {:?}", loaded.get("user_id"));
        println!("Loaded session - Username: {:?}", loaded.get("username"));
    }

    // Example 2: Cookie sessions
    println!("\n=== Cookie Sessions ===");
    let cookie_config = SessionConfig {
        cookie_name: "my_session".to_string(),
        default_ttl_seconds: 3600 * 24, // 24 hours
        cookie_secure: false, // Set to true in production with HTTPS
        cookie_http_only: true,
        encryption_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()), // 64 hex chars = 32 bytes
        ..Default::default()
    };

    let cookie_store: Arc<dyn SessionStore> = Arc::new(
        CookieSessionStore::new(&cookie_config)?
    );

    let mut cookie_session = SessionData::new(Duration::from_secs(3600));
    cookie_session.set("user_id".to_string(), "456".to_string());
    cookie_session.set("role".to_string(), "admin".to_string());

    cookie_store.save("cookie-session-xyz", cookie_session).await?;
    println!("Saved cookie session");

    // Use in AppContext
    let context = tideway::AppContext::builder()
        .with_sessions(memory_store.clone())
        .build();

    // Cleanup expired sessions (typically done periodically)
    let removed = memory_store.cleanup_expired().await?;
    println!("Cleaned up {} expired sessions", removed);

    println!("\nSession example completed!");
    Ok(())
}
