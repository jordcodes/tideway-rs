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
| `trust_proxy` | `bool` | `false` | Trust X-Forwarded-For header (see [Security](#security-proxy-headers)) |

### Builder Methods

```rust
RateLimitConfig::builder()
    .enabled(true)                    // Enable/disable rate limiting
    .max_requests(200)                // Set max requests per window
    .window_seconds(120)              // Set window duration in seconds
    .per_ip()                         // Use per-IP rate limiting
    .global()                         // Use global rate limiting
    .strategy("per_ip")               // Set strategy explicitly
    .trust_proxy(true)                // Trust proxy headers (see Security section)
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

## Security: Proxy Headers

### The Problem with X-Forwarded-For

When using per-IP rate limiting behind a reverse proxy (nginx, AWS ALB, Cloudflare, etc.), the server sees the proxy's IP instead of the client's real IP. Proxies typically add the client IP to the `X-Forwarded-For` header.

However, **blindly trusting X-Forwarded-For is dangerous**:

```bash
# An attacker can spoof their IP:
curl -H "X-Forwarded-For: 1.2.3.4" https://your-api.com/endpoint
```

If you trust this header without a proxy in front, attackers can:
- Bypass per-IP rate limits by sending different fake IPs
- Impersonate other users
- Evade IP-based blocking

### Safe Configuration

**Default behavior (trust_proxy: false):**
- Only uses the direct connection IP
- Safe but won't work correctly behind a proxy
- All requests appear from the proxy's IP

**Behind a trusted proxy (trust_proxy: true):**
```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .max_requests(100)
    .per_ip()
    .trust_proxy(true)  // Only if behind a trusted proxy!
    .build();
```

### When to Enable trust_proxy

Enable `trust_proxy: true` **only if**:
1. Your application is behind a reverse proxy you control
2. The proxy is configured to **overwrite** (not append to) X-Forwarded-For
3. External clients cannot directly reach your application

Common setups where trust_proxy should be enabled:
- Behind nginx/Apache configured correctly
- Behind AWS Application Load Balancer
- Behind Cloudflare
- Behind Kubernetes ingress

### Proxy Configuration Examples

**nginx:**
```nginx
# Ensure nginx sets X-Forwarded-For (not appends)
proxy_set_header X-Forwarded-For $remote_addr;
```

**AWS ALB:**
ALB automatically sets X-Forwarded-For. Enable trust_proxy.

## Preset Configurations

### Permissive (Development)

```rust
let rate_limit = RateLimitConfig::permissive();
// 1000 requests per minute, global strategy, trust_proxy: false
```

### Restrictive (Production)

```rust
let rate_limit = RateLimitConfig::restrictive();
// 100 requests per minute per IP, trust_proxy: false
```

## Environment Variables

Configure rate limiting via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `TIDEWAY_RATE_LIMIT_ENABLED` | Enable/disable rate limiting | `false` |
| `TIDEWAY_RATE_LIMIT_MAX_REQUESTS` | Maximum requests per window | `100` |
| `TIDEWAY_RATE_LIMIT_WINDOW_SECONDS` | Window duration in seconds | `60` |
| `TIDEWAY_RATE_LIMIT_STRATEGY` | Strategy: `per_ip` or `global` | `per_ip` |
| `TIDEWAY_RATE_LIMIT_TRUST_PROXY` | Trust proxy headers | `false` |

Alternative unprefixed variables are also supported (e.g., `RATE_LIMIT_ENABLED`).

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

### Production Setup (Behind Proxy)

```rust
use tideway::{App, RateLimitConfig};

#[tokio::main]
async fn main() {
    tideway::init_tracing();

    let rate_limit = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(100)
        .window_seconds(60)
        .per_ip()
        .trust_proxy(true)  // Behind nginx/ALB/Cloudflare
        .build();

    let app = App::builder()
        .with_rate_limit(rate_limit)
        .build();

    app.serve().await.unwrap();
}
```

### Production Setup (Direct Connection)

```rust
use tideway::{App, RateLimitConfig};

#[tokio::main]
async fn main() {
    tideway::init_tracing();

    let rate_limit = RateLimitConfig::builder()
        .enabled(true)
        .max_requests(100)
        .window_seconds(60)
        .per_ip()
        // trust_proxy defaults to false - safe for direct connections
        .build();

    let app = App::builder()
        .with_rate_limit(rate_limit)
        .build();

    app.serve().await.unwrap();
}
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
6. **Configure trust_proxy correctly**: Only enable behind trusted proxies

## Troubleshooting

### Rate limits not working

- Check that `enabled` is `true`
- Verify the rate limit layer is applied before other middleware
- Check logs for rate limit activity

### All requests counted as same IP

- You're likely behind a proxy but `trust_proxy` is `false`
- Enable `trust_proxy: true` if behind nginx/ALB/Cloudflare
- Verify your proxy sets `X-Forwarded-For` correctly

### Rate limits easily bypassed

- You may have `trust_proxy: true` without an actual proxy
- Attackers are spoofing X-Forwarded-For headers
- Set `trust_proxy: false` if clients connect directly

### Memory concerns

- Monitor memory usage with high request volumes
- Consider reducing window duration or max requests
- Use global strategy if per-IP memory usage is too high
