# Session Management

Tideway provides session management with multiple storage backends.

## SessionStore Trait

The `SessionStore` trait abstracts session storage:

```rust
use tideway::{SessionStore, SessionData};
use std::sync::Arc;
use std::time::Duration;

async fn example(store: Arc<dyn SessionStore>) -> tideway::Result<()> {
    let session_id = "session-123";

    // Create session data
    let mut session = SessionData::new(Duration::from_secs(3600));
    session.set("user_id".to_string(), "123".to_string());

    // Save session
    store.save(session_id, session).await?;

    // Load session
    if let Some(session) = store.load(session_id).await? {
        let user_id = session.get("user_id");
    }

    // Delete session
    store.delete(session_id).await?;

    Ok(())
}
```

## Implementations

### In-Memory Session Store

For development and testing:

```rust
use tideway::session::InMemorySessionStore;
use std::sync::Arc;
use std::time::Duration;

let store = Arc::new(
    InMemorySessionStore::new(Duration::from_secs(3600 * 24)) // 24 hours
);
```

### Cookie Session Store

Stores sessions in encrypted HTTP cookies:

```rust
use tideway::session::{CookieSessionStore, SessionConfig};
use std::sync::Arc;

let config = SessionConfig {
    cookie_name: "session".to_string(),
    default_ttl_seconds: 3600 * 24,
    encryption_key: Some("your-32-byte-hex-key".to_string()),
    ..Default::default()
};

let store = Arc::new(CookieSessionStore::new(&config)?);
```

## SessionData

The `SessionData` struct provides a key-value interface:

```rust
use tideway::SessionData;
use std::time::Duration;

let mut session = SessionData::new(Duration::from_secs(3600));

// Set values
session.set("user_id".to_string(), "123".to_string());
session.set("role".to_string(), "admin".to_string());

// Get values
if let Some(user_id) = session.get("user_id") {
    println!("User ID: {}", user_id);
}

// Remove values
session.remove("role");

// Extend expiration
session.extend(Duration::from_secs(7200));
```

## Environment Variables

- `TIDEWAY_SESSION_BACKEND` - Backend type: `in_memory` or `cookie`
- `TIDEWAY_SESSION_TTL_SECONDS` - Default TTL (default: 86400 = 24 hours)
- `TIDEWAY_SESSION_COOKIE_NAME` - Cookie name (default: "tideway_session")
- `TIDEWAY_SESSION_COOKIE_PATH` - Cookie path (default: "/")
- `TIDEWAY_SESSION_COOKIE_SECURE` - HTTPS only (default: true)
- `TIDEWAY_SESSION_COOKIE_HTTP_ONLY` - HTTP only flag (default: true)
- `TIDEWAY_SESSION_ENCRYPTION_KEY` - 32-byte hex key for cookie encryption

## Custom Implementation

```rust
use tideway::{SessionStore, SessionData};
use async_trait::async_trait;

struct MyCustomStore {
    // Your store implementation
}

#[async_trait]
impl SessionStore for MyCustomStore {
    async fn load(&self, session_id: &str) -> tideway::Result<Option<SessionData>> {
        // Your implementation
    }

    // ... implement other methods
}
```
