# Rate Limiting

Tideway provides built-in rate limiting middleware to protect your API from abuse and ensure fair usage.

## Quick Start

### Basic Configuration

```rust
use tideway::{App, RateLimitConfig};

let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .max_requests(100)
    .window_seconds(60)
    .per_ip()
    .build();

let app = App::builder()
    .with_rate_limit(rate_limit)
    .build();
```

**Note**: Health check endpoints (`/health` and `/health/*`) are automatically excluded from rate limiting to ensure monitoring systems can always check application health.

### Using Defaults

Rate limiting is **disabled by default**. Enable it via configuration:

```rust
use tideway::{App, ConfigBuilder, RateLimitConfig};

let config = ConfigBuilder::new()
    .from_env()  // Loads rate limit config from environment
    .build();

let app = App::with_config(config);
```

## Configuration Options

### RateLimitConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Whether rate limiting is enabled |
| `max_requests` | `u32` | `100` | Maximum requests allowed per window |
| `window_seconds` | `u64` | `60` | Time window in seconds |
| `strategy` | `String` | `"per_ip"` | Rate limiting strategy: `"per_ip"` or `"global"` |

### Builder Methods

```rust
RateLimitConfig::builder()
    .enabled(true)                    // Enable/disable rate limiting
    .max_requests(200)                // Set max requests per window
    .window_seconds(120)              // Set window duration in seconds
    .per_ip()                         // Use per-IP rate limiting
    .global()                         // Use global rate limiting
    .strategy("per_ip")               // Set strategy explicitly
    .build()
```

## Strategies

### Per-IP Rate Limiting

Limits requests per IP address. Useful for protecting against individual abusive clients.

```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .max_requests(100)
    .window_seconds(60)
    .per_ip()
    .build();
```

**Note**: IP extraction attempts:
1. `X-Forwarded-For` header (for reverse proxies)
2. `X-Real-IP` header (for nginx)
3. Direct connection IP (if available)

### Global Rate Limiting

Limits total requests across all clients. Useful for protecting shared resources.

```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .max_requests(1000)
    .window_seconds(60)
    .global()
    .build();
```

## Preset Configurations

### Permissive (Development)

```rust
let rate_limit = RateLimitConfig::permissive();
// 1000 requests per minute, global strategy
```

### Restrictive (Production)

```rust
let rate_limit = RateLimitConfig::restrictive();
// 100 requests per minute per IP
```

## Environment Variables

Configure rate limiting via environment variables:

```bash
# Enable/disable rate limiting
TIDEWAY_RATE_LIMIT_ENABLED=true

# Maximum requests per window
TIDEWAY_RATE_LIMIT_MAX_REQUESTS=200

# Window duration in seconds
TIDEWAY_RATE_LIMIT_WINDOW_SECONDS=60

# Strategy: "per_ip" or "global"
TIDEWAY_RATE_LIMIT_STRATEGY=per_ip
```

Alternative unprefixed variables are also supported:
- `RATE_LIMIT_ENABLED`
- `RATE_LIMIT_MAX_REQUESTS`
- `RATE_LIMIT_WINDOW_SECONDS`
- `RATE_LIMIT_STRATEGY`

## Rate Limit Responses

When rate limit is exceeded, Tideway returns:

- **Status Code**: `429 Too Many Requests`
- **Headers**: `Retry-After: <seconds>`
- **Body**: JSON error response

```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded. Please try again in 45 seconds",
  "retry_after": 45
}
```

## Examples

### Development Setup

```rust
use tideway::{App, RateLimitConfig};

#[tokio::main]
async fn main() {
    tideway::init_tracing();

    // Permissive rate limiting for development
    let rate_limit = RateLimitConfig::permissive();

    let app = App::builder()
        .with_rate_limit(rate_limit)
        .build();

    app.serve().await.unwrap();
}
```

### Production Setup

```rust
use tideway::{App, ConfigBuilder, RateLimitConfig};

#[tokio::main]
async fn main() {
    tideway::init_tracing();

    // Restrictive rate limiting for production
    let rate_limit = RateLimitConfig::restrictive();

    let config = ConfigBuilder::new()
        .from_env()
        .build();

    let app = App::with_config(config);
    // Rate limit config is included in Config

    app.serve().await.unwrap();
}
```

### Custom Configuration

```rust
use tideway::{App, RateLimitConfig};

let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .max_requests(50)        // 50 requests
    .window_seconds(30)      // per 30 seconds
    .per_ip()                // per IP address
    .build();

let app = App::builder()
    .with_rate_limit(rate_limit)
    .build();
```

## Implementation Details

### In-Memory Storage

Tideway's rate limiter uses in-memory storage by default, making it suitable for:
- Single-instance deployments
- Development and testing
- Small to medium applications

### Limitations

- **Not distributed**: Rate limits are per-instance, not shared across multiple servers
- **Memory usage**: IP-based limiting stores request timestamps in memory
- **No persistence**: Rate limit state is lost on server restart

### Production Considerations

For production deployments with multiple instances, consider:
- Using a distributed rate limiter (Redis, etc.)
- Implementing rate limiting at the load balancer level
- Using a dedicated rate limiting service

## Disabling Rate Limiting

To disable rate limiting:

```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(false)
    .build();
```

Or via environment:

```bash
TIDEWAY_RATE_LIMIT_ENABLED=false
```

## Testing

Rate limiting can be tested using Tideway's testing utilities:

```rust
use tideway::testing::get;

#[tokio::test]
async fn test_rate_limit() {
    let rate_limit = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(2)
        .window_seconds(60)
        .per_ip()
        .build();

    let app = create_app_with_rate_limit(rate_limit);

    // First two requests should succeed
    get(app.clone(), "/api/test")
        .execute()
        .await
        .assert_ok();

    get(app.clone(), "/api/test")
        .execute()
        .await
        .assert_ok();

    // Third request should be rate limited
    get(app, "/api/test")
        .execute()
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}
```

## Best Practices

1. **Start permissive**: Use permissive settings in development
2. **Monitor metrics**: Track rate limit hits to tune your limits
3. **Consider use cases**: Different endpoints may need different limits
4. **Document limits**: Let API consumers know your rate limits
5. **Use Retry-After**: Clients should respect the `Retry-After` header

## Troubleshooting

### Rate limits not working

- Check that `enabled` is `true`
- Verify the rate limit layer is applied before other middleware
- Check logs for rate limit activity

### IP detection issues

- Ensure reverse proxy headers are set correctly
- Check that `X-Forwarded-For` or `X-Real-IP` headers are present
- Verify direct connection IP is available if not behind a proxy

### Memory concerns

- Monitor memory usage with high request volumes
- Consider reducing window duration or max requests
- Use global strategy if per-IP memory usage is too high
