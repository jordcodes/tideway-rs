# Webhook Handling

Tideway provides secure webhook handling with signature verification and idempotency support.

## Quick Start

```rust
use tideway::webhooks::{HmacSha256Verifier, WebhookVerifier};

// Create verifier with your webhook secret
let verifier = HmacSha256Verifier::new("whsec_your_secret_here");

// Verify incoming webhook
let payload = request.body();
let signature = request.headers().get("X-Signature").unwrap();
let is_valid = verifier.verify_signature(payload, signature).await?;

if !is_valid {
    return Err(TidewayError::unauthorized("Invalid webhook signature"));
}
```

## Signature Verification

### Why Verify Signatures?

Webhook signatures prevent:
- **Replay attacks**: Attackers resending captured webhooks
- **Forgery**: Attackers sending fake webhook events
- **Man-in-the-middle**: Attackers modifying webhook payloads

### HMAC-SHA256 Verifier

The standard verification method used by most providers (Stripe, GitHub, Shopify, etc.):

```rust
use tideway::webhooks::HmacSha256Verifier;

// Basic hex-encoded signatures (most common)
let verifier = HmacSha256Verifier::new("your_webhook_secret");

// For GitHub-style "sha256=" prefixed signatures
let verifier = HmacSha256Verifier::new_with_prefix("your_secret", "sha256=");

// For base64-encoded signatures
let verifier = HmacSha256Verifier::new_base64("your_secret");
```

### Provider-Specific Examples

#### Stripe

```rust
use tideway::webhooks::HmacSha256Verifier;

let verifier = HmacSha256Verifier::new(
    std::env::var("STRIPE_WEBHOOK_SECRET").expect("STRIPE_WEBHOOK_SECRET required")
);

async fn handle_stripe_webhook(
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let signature = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| TidewayError::bad_request("Missing signature"))?;

    // Note: Stripe uses a more complex signature format with timestamp
    // This is a simplified example - see Stripe's documentation
    if !verifier.verify_signature(&body, signature).await? {
        return Err(TidewayError::unauthorized("Invalid signature"));
    }

    // Process webhook...
    Ok(StatusCode::OK)
}
```

#### GitHub

```rust
use tideway::webhooks::HmacSha256Verifier;

let verifier = HmacSha256Verifier::new_with_prefix(
    std::env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET required"),
    "sha256="
);

async fn handle_github_webhook(
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let signature = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| TidewayError::bad_request("Missing signature"))?;

    if !verifier.verify_signature(&body, signature).await? {
        return Err(TidewayError::unauthorized("Invalid signature"));
    }

    // Process webhook...
    Ok(StatusCode::OK)
}
```

### Custom Verifier

Implement `WebhookVerifier` for custom verification logic:

```rust
use tideway::webhooks::WebhookVerifier;
use async_trait::async_trait;

struct MyCustomVerifier {
    api_key: String,
}

#[async_trait]
impl WebhookVerifier for MyCustomVerifier {
    async fn verify_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
        // Your custom verification logic
        Ok(true)
    }
}
```

### NoVerification (Testing Only)

For development/testing when you don't have a webhook secret:

```rust
use tideway::webhooks::NoVerification;

// WARNING: Accepts ALL webhooks without verification!
let verifier = NoVerification;
```

**Never use `NoVerification` in production!**

## Idempotency

Webhook providers may retry failed deliveries, causing duplicate processing. Use idempotency to handle this:

```rust
use tideway::webhooks::{IdempotencyStore, MemoryIdempotencyStore};

let store = MemoryIdempotencyStore::new();

async fn handle_webhook(
    store: &dyn IdempotencyStore,
    event_id: &str,
    payload: &[u8],
) -> Result<()> {
    // Check if already processed
    if store.is_processed(event_id).await? {
        tracing::info!("Webhook {} already processed, skipping", event_id);
        return Ok(());
    }

    // Process the webhook...
    process_event(payload).await?;

    // Mark as processed
    store.mark_processed(event_id.to_string()).await?;

    Ok(())
}
```

### Idempotency Stores

#### In-Memory Store (Development)

```rust
use tideway::webhooks::MemoryIdempotencyStore;

let store = MemoryIdempotencyStore::new();
```

**Note**: In-memory store is lost on restart and doesn't work across multiple instances.

#### Database Store (Production)

```rust
use tideway::webhooks::DatabaseIdempotencyStore;

let store = DatabaseIdempotencyStore::new(db_connection);
```

#### Custom Store

Implement `IdempotencyStore` for custom backends (Redis, etc.):

```rust
use tideway::webhooks::IdempotencyStore;
use async_trait::async_trait;

struct RedisIdempotencyStore {
    client: redis::Client,
    ttl: Duration,
}

#[async_trait]
impl IdempotencyStore for RedisIdempotencyStore {
    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        // Check Redis
        todo!()
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        // Store in Redis with TTL
        todo!()
    }

    async fn cleanup_old_entries(&self) -> Result<()> {
        // Redis handles expiration automatically
        Ok(())
    }
}
```

## Complete Webhook Handler

Here's a complete example combining verification and idempotency:

```rust
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension,
};
use tideway::{
    webhooks::{HmacSha256Verifier, IdempotencyStore, WebhookVerifier},
    Result, TidewayError,
};
use std::sync::Arc;

async fn webhook_handler(
    Extension(verifier): Extension<Arc<dyn WebhookVerifier>>,
    Extension(idempotency): Extension<Arc<dyn IdempotencyStore>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // 1. Extract signature
    let signature = headers
        .get("X-Webhook-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| TidewayError::bad_request("Missing webhook signature"))?;

    // 2. Verify signature
    if !verifier.verify_signature(&body, signature).await? {
        tracing::warn!("Invalid webhook signature");
        return Err(TidewayError::unauthorized("Invalid webhook signature"));
    }

    // 3. Parse event
    let event: WebhookEvent = serde_json::from_slice(&body)
        .map_err(|e| TidewayError::bad_request(format!("Invalid JSON: {}", e)))?;

    // 4. Check idempotency
    if idempotency.is_processed(&event.id).await? {
        tracing::info!("Webhook {} already processed", event.id);
        return Ok(StatusCode::OK);
    }

    // 5. Process event
    match event.event_type.as_str() {
        "payment.completed" => handle_payment_completed(&event).await?,
        "subscription.cancelled" => handle_subscription_cancelled(&event).await?,
        _ => tracing::info!("Ignoring unknown event type: {}", event.event_type),
    }

    // 6. Mark as processed
    idempotency.mark_processed(event.id).await?;

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct WebhookEvent {
    id: String,
    event_type: String,
    data: serde_json::Value,
}
```

## Security Best Practices

1. **Always verify signatures** - Never process unverified webhooks
2. **Use HTTPS** - Webhook endpoints should only accept HTTPS
3. **Keep secrets secure** - Store webhook secrets in environment variables
4. **Implement idempotency** - Handle duplicate deliveries gracefully
5. **Log webhook events** - Track processed webhooks for debugging
6. **Respond quickly** - Return 200 OK quickly, process async if needed
7. **Validate event types** - Only process expected event types
8. **Use timing-safe comparison** - Tideway's verifier does this automatically

## Environment Variables

| Variable | Description |
|----------|-------------|
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `GITHUB_WEBHOOK_SECRET` | GitHub webhook secret |
| `WEBHOOK_SECRET` | Generic webhook secret |

## Troubleshooting

### Signature verification fails

1. **Check the secret** - Ensure you're using the correct webhook secret
2. **Check the payload** - Verify you're using the raw request body
3. **Check the header** - Ensure you're reading the correct signature header
4. **Check the encoding** - Use the correct verifier (hex vs base64)
5. **Check for prefixes** - Some providers add prefixes like "sha256="

### Duplicate events processed

1. **Implement idempotency** - Use an `IdempotencyStore`
2. **Use a persistent store** - In-memory stores reset on restart
3. **Set appropriate TTL** - Keep event IDs long enough for retries

### Webhooks timing out

1. **Return quickly** - Don't do heavy processing synchronously
2. **Use background jobs** - Queue events for async processing
3. **Acknowledge first** - Return 200 OK before processing
