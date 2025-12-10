# CORS (Cross-Origin Resource Sharing) in Tideway

Tideway provides built-in CORS support through a flexible configuration system that works both programmatically and via configuration files/environment variables.

## Quick Start

**Security Note**: CORS is **disabled by default** for security. You must explicitly enable and configure CORS to allow cross-origin requests.

### 1. Permissive CORS (Development)

For local development, use the permissive configuration:

```rust
use tideway::{App, CorsConfig};

let cors = CorsConfig::permissive();
let app = App::builder().with_cors(cors).build();
```

**⚠️ WARNING**: Do not use permissive CORS in production as it allows any origin.

### 2. Restrictive CORS (Production)

For production, specify allowed origins explicitly:

```rust
use tideway::{App, CorsConfig};

let cors = CorsConfig::restrictive(vec![
    "https://example.com".to_string(),
    "https://www.example.com".to_string(),
]);
let app = App::builder().with_cors(cors).build();
```

### 3. Custom CORS Configuration

Use the builder pattern for fine-grained control:

```rust
use tideway::CorsConfig;

let cors = CorsConfig::builder()
    .allow_origin("https://app.example.com")
    .allow_origin("https://admin.example.com")
    .allow_methods(vec!["GET".to_string(), "POST".to_string()])
    .allow_headers(vec!["content-type".to_string(), "authorization".to_string()])
    .expose_header("x-request-id")
    .allow_credentials(true)
    .max_age(3600)
    .build();
```

## Configuration Options

### CorsConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Whether CORS is enabled (disabled by default for security) |
| `allowed_origins` | `Vec<String>` | `[]` | Allowed origins (empty = none, `["*"]` = all) |
| `allowed_methods` | `Vec<String>` | `["GET", "POST", "PUT", "PATCH", "DELETE"]` | Allowed HTTP methods |
| `allowed_headers` | `Vec<String>` | `["content-type", "authorization", "x-request-id"]` | Allowed headers |
| `exposed_headers` | `Vec<String>` | `[]` | Headers exposed to browser |
| `allow_credentials` | `bool` | `false` | Whether to allow credentials (disabled by default for security) |
| `max_age_seconds` | `u64` | `3600` | Preflight cache duration |

### Builder Methods

```rust
CorsConfig::builder()
    .enabled(true)                          // Enable/disable CORS
    .allow_origin("https://example.com")    // Add an allowed origin
    .allow_origins(vec![...])               // Set all allowed origins
    .allow_any_origin()                     // Allow any origin (use "*")
    .allow_method("GET")                    // Add an allowed method
    .allow_methods(vec![...])               // Set all allowed methods
    .allow_header("x-api-key")              // Add an allowed header
    .allow_headers(vec![...])               // Set all allowed headers
    .allow_any_header()                     // Allow any header (use "*")
    .expose_header("x-request-id")          // Add an exposed header
    .expose_headers(vec![...])              // Set all exposed headers
    .allow_credentials(true)                // Enable credentials
    .max_age(7200)                          // Set max age in seconds
    .build()
```

## Environment Variables

CORS can be configured via environment variables with the `TIDEWAY_` prefix:

```bash
# Enable/disable CORS
TIDEWAY_CORS_ENABLED=true

# Allowed origins (comma-separated)
TIDEWAY_CORS_ALLOWED_ORIGINS=https://example.com,https://api.example.com

# Allowed methods (comma-separated)
TIDEWAY_CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE

# Allowed headers (comma-separated)
TIDEWAY_CORS_ALLOWED_HEADERS=content-type,authorization,x-api-key

# Exposed headers (comma-separated)
TIDEWAY_CORS_EXPOSED_HEADERS=x-request-id

# Allow credentials
TIDEWAY_CORS_ALLOW_CREDENTIALS=true

# Max age in seconds
TIDEWAY_CORS_MAX_AGE=7200
```

Load environment configuration:

```rust
use tideway::{App, ConfigBuilder};

let config = ConfigBuilder::new()
    .from_env()  // Loads CORS config from environment
    .build();

let app = App::with_config(config);
```

## Configuration File

CORS can also be configured via TOML/JSON config files:

```toml
[cors]
enabled = true
allowed_origins = ["https://example.com", "https://www.example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE"]
allowed_headers = ["content-type", "authorization"]
exposed_headers = ["x-request-id"]
allow_credentials = true
max_age_seconds = 3600
```

## Common Patterns

### Development vs Production

```rust
use tideway::{App, CorsConfig};

let cors = if cfg!(debug_assertions) {
    // Development: allow any origin
    CorsConfig::permissive()
} else {
    // Production: restrict origins
    CorsConfig::restrictive(vec![
        std::env::var("ALLOWED_ORIGIN")
            .unwrap_or_else(|_| "https://example.com".to_string())
    ])
};

let app = App::builder().with_cors(cors).build();
```

### Multiple Environments

```rust
use tideway::{App, CorsConfig};

let cors = match std::env::var("ENV").as_deref() {
    Ok("production") => CorsConfig::restrictive(vec![
        "https://example.com".to_string(),
    ]),
    Ok("staging") => CorsConfig::restrictive(vec![
        "https://staging.example.com".to_string(),
    ]),
    _ => CorsConfig::permissive(), // Development
};

let app = App::builder().with_cors(cors).build();
```

### API with Credentials

For APIs that use cookies or authorization headers:

```rust
use tideway::CorsConfig;

let cors = CorsConfig::builder()
    .allow_origin("https://app.example.com")
    .allow_credentials(true)  // Required for cookies
    .allow_headers(vec![
        "content-type".to_string(),
        "authorization".to_string(),
    ])
    .build();
```

**Note**: When `allow_credentials` is `true`, you cannot use `allow_any_origin()`. You must specify exact origins.

## Disabling CORS

To disable CORS entirely:

```rust
use tideway::CorsConfig;

let cors = CorsConfig::builder()
    .enabled(false)
    .build();
```

Or via environment:

```bash
TIDEWAY_CORS_ENABLED=false
```

## Testing

Example test using the CORS configuration:

```rust
#[tokio::test]
async fn test_cors_configuration() {
    let cors = CorsConfig::builder()
        .allow_origin("https://example.com")
        .allow_credentials(true)
        .build();

    assert!(cors.enabled);
    assert_eq!(cors.allowed_origins, vec!["https://example.com"]);
    assert!(cors.allow_credentials);
}
```

## How It Works

Tideway's CORS implementation uses `tower-http`'s `CorsLayer` under the hood. The CORS layer is automatically added to the middleware stack when:

1. CORS is enabled (`enabled = true`)
2. The app is built with CORS configuration

The middleware handles:
- Preflight requests (OPTIONS)
- CORS headers on actual requests
- Origin validation
- Credentials handling

## Examples

See the full example in `examples/cors_example.rs`:

```bash
cargo run --example cors_example
```
