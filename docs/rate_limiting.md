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
| `trusted_proxies` | `Vec<String>` | empty | Proxy IP/CIDR allowlist for forwarded headers |
| `trust_proxy` | `bool` | `false` | Legacy switch; no longer enables header trust by itself |

### Builder Methods

```rust
RateLimitConfig::builder()
    .enabled(true)                    // Enable/disable rate limiting
    .max_requests(200)                // Set max requests per window
    .window_seconds(120)              // Set window duration in seconds
    .per_ip()                         // Use per-IP rate limiting
    .global()                         // Use global rate limiting
    .strategy("per_ip")               // Set strategy explicitly
    .trusted_proxy("10.0.0.0/8")      // Allow a proxy network to supply client IPs
    .trusted_proxies([                // Or replace the complete allowlist
        "10.0.0.0/8",
        "2001:db8:1234::/48",
    ])
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

If you manually serve Tideway with `axum::serve`, make sure connection info is attached so per-IP limiting sees the client address:

```rust
axum::serve(listener, app.into_make_service_with_connect_info()).await?;
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

**Default behavior (empty `trusted_proxies`):**
- Only uses the direct connection IP
- Safe but won't work correctly behind a proxy
- All requests appear from the proxy's IP

**Behind trusted proxies:**
```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .max_requests(100)
    .per_ip()
    .trusted_proxies([
        "10.20.0.0/16",       // Internal load balancer network
        "2001:db8:1234::/48", // IPv6 ingress network
    ])
    .build();
```

Tideway accepts `X-Forwarded-For` and `X-Real-IP` only when the direct
connection peer matches this allowlist. For multi-proxy deployments,
`X-Forwarded-For` is evaluated from right to left and trusted hops are removed.
Malformed chains fail closed to the direct peer address.

### Choosing the Allowlist

Configure trusted proxies **only if**:
1. Your application is behind a reverse proxy you control
2. You know the proxy's source IP address or network
3. External clients cannot directly reach your application

Use the narrowest stable network supplied by your infrastructure provider.
Tideway rejects `0.0.0.0/0` and `::/0` because they would restore blind header
trust.

Common setups where an allowlist should be configured:
- Behind nginx/Apache configured correctly
- Behind AWS Application Load Balancer
- Behind Cloudflare
- Behind Kubernetes ingress

### Proxy Configuration Examples

**nginx:**
```nginx
# Append the observed peer. Tideway safely walks the resulting chain from right to left.
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

**AWS ALB:**
ALB supplies `X-Forwarded-For`. Allowlist the private subnet or security-group
source ranges through which the ALB reaches the application, not arbitrary
public client ranges.

## Preset Configurations

### Permissive (Development)

```rust
let rate_limit = RateLimitConfig::permissive();
// 1000 requests per minute, global strategy, no trusted proxies
```

### Restrictive (Production)

```rust
let rate_limit = RateLimitConfig::restrictive();
// 100 requests per minute per IP, no trusted proxies
```

## Environment Variables

Configure rate limiting via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `TIDEWAY_RATE_LIMIT_ENABLED` | Enable/disable rate limiting | `false` |
| `TIDEWAY_RATE_LIMIT_MAX_REQUESTS` | Maximum requests per window | `100` |
| `TIDEWAY_RATE_LIMIT_WINDOW_SECONDS` | Window duration in seconds | `60` |
| `TIDEWAY_RATE_LIMIT_STRATEGY` | Strategy: `per_ip` or `global` | `per_ip` |
| `TIDEWAY_RATE_LIMIT_TRUSTED_PROXIES` | Comma-separated proxy IP/CIDR allowlist | empty |
| `TIDEWAY_RATE_LIMIT_TRUST_PROXY` | Legacy switch; requires the allowlist above | `false` |

Alternative unprefixed variables are also supported (e.g., `RATE_LIMIT_ENABLED`).

### Migrating from `trust_proxy`

Replace `.trust_proxy(true)` with `.trusted_proxy("<proxy-ip-or-cidr>")`, or set
`TIDEWAY_RATE_LIMIT_TRUSTED_PROXIES`. The legacy boolean is retained for config
deserialization but deliberately does not trust headers without an allowlist.
Code that constructs `RateLimitConfig` with a struct literal must add
`trusted_proxies: vec![]`; using the builder avoids this migration detail.

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
        .trusted_proxies(["10.20.0.0/16", "2001:db8:1234::/48"])
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
        // An empty trusted-proxy list is safe for direct connections.
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
6. **Keep proxy trust narrow**: Allowlist only the proxy networks that connect to the app

## Troubleshooting

### Rate limits not working

- Check that `enabled` is `true`
- Verify the rate limit layer is applied before other middleware
- Check logs for rate limit activity

### All requests counted as same IP

- You're likely behind a proxy but `trusted_proxies` is empty
- Add the proxy's source IP or CIDR to `trusted_proxies`
- Verify your proxy sets `X-Forwarded-For` correctly

### Rate limits easily bypassed

- Check that `trusted_proxies` does not contain client-facing ranges such as `0.0.0.0/0`
- Confirm direct application access is restricted to your proxy tier
- Remove the allowlist if clients connect directly

### Memory concerns

- Monitor memory usage with high request volumes
- Consider reducing window duration or max requests
- Use global strategy if per-IP memory usage is too high
