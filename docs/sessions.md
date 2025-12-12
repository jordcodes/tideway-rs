# Session Management

Tideway provides session management with multiple storage backends.

## Quick Start

```rust
use tideway::session::{SessionConfig, CookieSessionStore, InMemorySessionStore};
use std::sync::Arc;

// For production: use cookie sessions with encryption key
let config = SessionConfig {
    encryption_key: Some(std::env::var("SESSION_ENCRYPTION_KEY").expect("SESSION_ENCRYPTION_KEY required")),
    ..Default::default()
};
let store = Arc::new(CookieSessionStore::new(&config)?);

// For development: use in-memory sessions
let store = Arc::new(InMemorySessionStore::new(Duration::from_secs(3600)));
```

## Cookie Sessions (Production)

Cookie sessions store encrypted session data in HTTP cookies. This is stateless and works across multiple server instances.

### Security Requirements

**Cookie sessions require an encryption key.** This is a security measure to prevent:
- Session forgery attacks
- Session data tampering
- Information disclosure

Generate a secure key:
```bash
openssl rand -hex 64
```

### Configuration

```rust
use tideway::session::{CookieSessionStore, SessionConfig};

let config = SessionConfig {
    // REQUIRED: 64-byte hex-encoded encryption key (128 hex characters)
    encryption_key: Some("your-128-character-hex-key-here".to_string()),

    // Optional settings
    cookie_name: "my_session".to_string(),
    cookie_path: "/".to_string(),
    cookie_secure: true,      // HTTPS only (recommended for production)
    cookie_http_only: true,   // Prevent JavaScript access
    default_ttl_seconds: 86400, // 24 hours

    ..Default::default()
};

let store = CookieSessionStore::new(&config)?;
```

### Development Mode

For local development only, you can allow insecure random keys:

```rust
let config = SessionConfig {
    allow_insecure_key: true,  // WARNING: Never use in production!
    ..Default::default()
};
```

This will generate a random key on startup with loud warnings. Sessions will not persist across restarts.

## In-Memory Sessions (Development/Testing)

For development and single-instance deployments:

```rust
use tideway::session::InMemorySessionStore;
use std::time::Duration;

let store = InMemorySessionStore::new(Duration::from_secs(3600 * 24));
```

**Note:** In-memory sessions are lost on server restart and don't work across multiple instances.

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

// Check expiration
if session.is_expired() {
    println!("Session expired");
}

// Extend expiration
session.extend(Duration::from_secs(7200));
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TIDEWAY_SESSION_BACKEND` | Backend type: `in_memory` or `cookie` | `in_memory` |
| `TIDEWAY_SESSION_TTL_SECONDS` | Default TTL in seconds | `86400` (24 hours) |
| `TIDEWAY_SESSION_COOKIE_NAME` | Cookie name | `tideway_session` |
| `TIDEWAY_SESSION_COOKIE_DOMAIN` | Cookie domain (optional) | - |
| `TIDEWAY_SESSION_COOKIE_PATH` | Cookie path | `/` |
| `TIDEWAY_SESSION_COOKIE_SECURE` | HTTPS only | `true` |
| `TIDEWAY_SESSION_COOKIE_HTTP_ONLY` | HTTP only flag | `true` |
| `TIDEWAY_SESSION_ENCRYPTION_KEY` | **Required for cookie sessions**: 64-byte hex key (128 chars) | - |
| `TIDEWAY_SESSION_ALLOW_INSECURE_KEY` | Allow random key (dev only) | `false` |

## Custom Implementation

Implement `SessionStore` for custom backends (Redis, database, etc.):

```rust
use tideway::{SessionStore, SessionData};
use async_trait::async_trait;

struct RedisSessionStore {
    client: redis::Client,
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn load(&self, session_id: &str) -> tideway::Result<Option<SessionData>> {
        // Load from Redis
        todo!()
    }

    async fn save(&self, session_id: &str, data: SessionData) -> tideway::Result<()> {
        // Save to Redis with TTL
        todo!()
    }

    async fn delete(&self, session_id: &str) -> tideway::Result<()> {
        // Delete from Redis
        todo!()
    }

    async fn cleanup_expired(&self) -> tideway::Result<usize> {
        // Redis handles expiration automatically
        Ok(0)
    }

    fn is_healthy(&self) -> bool {
        // Check Redis connection
        true
    }
}
```

## Security Best Practices

1. **Always use HTTPS** in production (`cookie_secure: true`)
2. **Generate a strong encryption key** using `openssl rand -hex 64`
3. **Store the key securely** (environment variable, secrets manager)
4. **Rotate keys periodically** (will invalidate existing sessions)
5. **Set appropriate TTL** based on your security requirements
6. **Use `http_only: true`** to prevent XSS attacks from stealing sessions
