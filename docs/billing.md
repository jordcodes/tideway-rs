# Billing

Tideway provides a comprehensive Stripe-based billing system for SaaS applications. The module handles subscriptions, payment methods, invoices, refunds, and feature entitlements with a trait-based design for testability.

## Quick Start

```rust
use tideway::billing::{
    Plans, CheckoutManager, CheckoutConfig, CheckoutRequest,
    SubscriptionManager, LiveStripeClient, LiveStripeClientConfig,
};

#[tokio::main]
async fn main() -> tideway::Result<()> {
    // 1. Define your plans
    let plans = Plans::builder()
        .plan("starter")
            .stripe_price("price_starter_monthly")
            .included_seats(3)
            .features(["reports", "export"])
            .trial_days(14)
            .done()
        .plan("pro")
            .stripe_price("price_pro_monthly")
            .extra_seat_price("price_seat_monthly")
            .included_seats(5)
            .features(["reports", "export", "api", "priority_support"])
            .done()
        .build();

    // 2. Create the Stripe client
    let client = LiveStripeClient::new(
        std::env::var("STRIPE_SECRET_KEY")?,
        LiveStripeClientConfig::default(),
    )?;

    // 3. Create managers
    let checkout_manager = CheckoutManager::new(
        store.clone(),
        client.clone(),
        plans.clone(),
        CheckoutConfig::default(),
    );

    // 4. Create a checkout session
    let session = checkout_manager.create_checkout_session(
        &org,
        CheckoutRequest::new(
            "starter",
            "https://app.example.com/success",
            "https://app.example.com/cancel",
        ),
    ).await?;

    println!("Redirect to: {}", session.url);
    Ok(())
}
```

## Architecture

The billing module uses a layered architecture:

```
┌─────────────────────────────────────────────────────┐
│                    Managers                          │
│  CheckoutManager, SubscriptionManager, etc.         │
├─────────────────────────────────────────────────────┤
│                Trait Abstractions                    │
│  StripeClient, StripeCheckoutClient, etc.           │
├─────────────────────────────────────────────────────┤
│   LiveStripeClient   │   Mock Clients (Testing)     │
└─────────────────────────────────────────────────────┘
```

**Key design principles:**
- **Trait-first** - All Stripe operations are behind traits for testability
- **Generic storage** - `BillingStore` trait lets you bring your own database
- **No business logic assumptions** - Uses `BillableEntity` trait instead of assuming user/org models

## Plans Configuration

Define your subscription plans with the builder pattern:

```rust
use tideway::billing::Plans;

let plans = Plans::builder()
    .plan("free")
        .stripe_price("price_free")
        .included_seats(1)
        .features(["basic"])
        .done()
    .plan("starter")
        .stripe_price("price_starter")
        .extra_seat_price("price_seat")  // Enable seat-based billing
        .included_seats(3)
        .features(["basic", "reports"])
        .trial_days(14)
        .limits(|l| l
            .max_projects(10)
            .max_storage_gb(5)
            .custom("api_calls", 1000))
        .done()
    .plan("pro")
        .stripe_price("price_pro")
        .extra_seat_price("price_seat")
        .included_seats(10)
        .features(["basic", "reports", "api", "priority_support"])
        .limits(|l| l
            .max_projects(100)
            .max_storage_gb(50)
            .custom("api_calls", 100_000))
        .done()
    .build();
```

## Checkout Sessions

Create Stripe Checkout sessions for new subscriptions:

```rust
use tideway::billing::{CheckoutManager, CheckoutConfig, CheckoutRequest};

// Configure checkout behavior
let config = CheckoutConfig::new()
    .allow_promotion_codes(true)
    .collect_tax_id(true)
    .collect_billing_address(true)
    .allowed_redirect_domains(["app.example.com", "staging.example.com"]);

let manager = CheckoutManager::new(store, client, plans, config);

// Basic checkout
let session = manager.create_checkout_session(
    &org,
    CheckoutRequest::new("pro", success_url, cancel_url),
).await?;

// With extra seats and coupon
let session = manager.create_checkout_session(
    &org,
    CheckoutRequest::new("pro", success_url, cancel_url)
        .with_extra_seats(5)
        .with_coupon("SAVE20")
        .with_promotion_codes(false)  // Required when using coupon
        .with_trial_days(30),         // Override plan default
).await?;

// Redirect user to Stripe
redirect_to(session.url);
```

## Subscription Management

```rust
use tideway::billing::SubscriptionManager;

let manager = SubscriptionManager::new(store, client, plans);

// Get subscription
let sub = manager.get_subscription("org_123").await?;
if let Some(sub) = sub {
    println!("Plan: {}", sub.plan_id);
    println!("Status: {:?}", sub.status);
    println!("Total seats: {}", sub.total_seats());
    println!("Has API feature: {}", sub.has_feature("api"));
}

// Cancel at period end
manager.cancel_subscription("org_123", false).await?;

// Cancel immediately
manager.cancel_subscription("org_123", true).await?;

// Resume cancelled subscription
manager.resume_subscription("org_123").await?;

// Extend trial (subscription must be in trialing state)
manager.extend_trial("org_123", 7).await?;  // Add 7 days

// Pause subscription
manager.pause_subscription("org_123").await?;

// Resume paused subscription
manager.resume_paused_subscription("org_123").await?;

// Check if paused
let is_paused = manager.is_paused("org_123").await?;

// Refresh from Stripe (bypass local cache)
manager.refresh_from_stripe("org_123").await?;

// Reconcile local state with Stripe
let result = manager.reconcile("org_123", true).await?;
match result {
    ReconcileResult::InSync => println!("All good"),
    ReconcileResult::Diverged { differences, .. } => {
        for diff in differences {
            println!("Difference: {:?}", diff);
        }
    }
    _ => {}
}
```

## Payment Methods

```rust
use tideway::billing::PaymentMethodManager;

let manager = PaymentMethodManager::new(store, client);

// List payment methods
let methods = manager.list_payment_methods("org_123").await?;
for method in methods.methods {
    println!("{}: {} ending in {} (default: {})",
        method.id,
        method.card_brand.unwrap_or_default(),
        method.card_last4.unwrap_or_default(),
        method.is_default,
    );
}

// Set default payment method
manager.set_default("org_123", "pm_xxx").await?;

// Remove payment method
manager.remove("org_123", "pm_xxx").await?;

// Attach new payment method (from Stripe.js/Elements)
let method = manager.attach("org_123", "pm_from_frontend").await?;

// Get default payment method
let default = manager.get_default("org_123").await?;
```

## Invoices

```rust
use tideway::billing::{InvoiceManager, InvoiceListParams, InvoiceStatus};

let manager = InvoiceManager::new(store, client);

// List invoices
let invoices = manager.list_invoices(
    "org_123",
    InvoiceListParams::default()
        .limit(10)
        .status(InvoiceStatus::Paid),
).await?;

for invoice in invoices.invoices {
    println!("{}: ${:.2} - {:?}",
        invoice.number.unwrap_or_default(),
        invoice.amount_paid as f64 / 100.0,
        invoice.status,
    );
}

// Get specific invoice
let invoice = manager.get_invoice("org_123", "in_xxx").await?;

// Get invoice line items
let items = manager.get_line_items("org_123", "in_xxx").await?;
```

## Refunds

The module provides two refund managers:

- `RefundManager` - Low-level, no authorization checks (admin use only)
- `SecureRefundManager` - Verifies charge ownership before refunding (customer-facing)

```rust
use tideway::billing::{SecureRefundManager, RefundReason};

// Use SecureRefundManager for customer-facing operations
let manager = SecureRefundManager::new(store, client);

// Full refund (verifies charge belongs to org_123)
let refund = manager.refund_charge("org_123", "ch_xxx", None).await?;

// Partial refund ($5.00)
let refund = manager.refund_charge("org_123", "ch_xxx", Some(500)).await?;

// Refund with reason
let refund = manager.refund_with_reason(
    "org_123",
    "ch_xxx",
    None,
    RefundReason::RequestedByCustomer,
).await?;

// Refund a payment intent
let refund = manager.refund_payment_intent("org_123", "pi_xxx", None).await?;

// List refunds for a charge
let refunds = manager.list_refunds_for_charge("org_123", "ch_xxx", 10).await?;
```

## Customer Portal

Redirect customers to Stripe's billing portal:

```rust
use tideway::billing::{PortalManager, PortalConfig, PortalFlow};

let config = PortalConfig::new()
    .configuration_id("bpc_xxx");  // Optional: custom portal configuration

let manager = PortalManager::new(store, client, config);

// Basic portal session
let session = manager.create_session(
    "org_123",
    "https://app.example.com/billing",
).await?;

// Portal with specific flow
let session = manager.create_session_with_flow(
    "org_123",
    "https://app.example.com/billing",
    PortalFlow::PaymentMethodUpdate,
).await?;

// Or subscription-specific flows
let session = manager.create_session_with_flow(
    "org_123",
    return_url,
    PortalFlow::SubscriptionCancel { subscription_id: "sub_xxx".to_string() },
).await?;

redirect_to(session.url);
```

## Seat Management

```rust
use tideway::billing::SeatManager;

let manager = SeatManager::new(store, client, plans);

// Get current seat info
let info = manager.get_seat_info("org_123").await?;
println!("Used: {}/{}", info.used_seats, info.total_seats);
println!("Available: {}", info.available_seats);

// Add seats
let result = manager.add_seats("org_123", 5).await?;

// Remove seats (proration applies)
let result = manager.remove_seats("org_123", 2).await?;

// Set exact seat count
let result = manager.set_seats("org_123", 10).await?;
```

## Entitlements

Check feature access and limits:

```rust
use tideway::billing::EntitlementsManager;

let manager = EntitlementsManager::new(store, plans);

// Check feature access
if !manager.has_feature("org_123", "api").await? {
    return Err(ApiError::UpgradeRequired);
}

// Check limits
let result = manager.check_limit("org_123", "projects", 15).await?;
match result {
    LimitCheckResult::Allowed => { /* proceed */ }
    LimitCheckResult::Exceeded { limit, current } => {
        return Err(ApiError::LimitExceeded(limit));
    }
    LimitCheckResult::NoLimit => { /* proceed */ }
}

// Get full entitlements
let entitlements = manager.get_entitlements("org_123").await?;
println!("Features: {:?}", entitlements.features);
println!("Limits: {:?}", entitlements.limits);
```

## Webhooks

Handle Stripe webhook events:

```rust
use tideway::billing::{WebhookHandler, WebhookEvent};
use axum::{extract::State, http::HeaderMap, body::Bytes};

async fn stripe_webhook(
    State(handler): State<WebhookHandler>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ApiError> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::BadRequest)?;

    let event = handler.verify_and_parse(&body, signature)?;

    match handler.handle(event).await? {
        WebhookOutcome::Processed => Ok(()),
        WebhookOutcome::Ignored => Ok(()),
        WebhookOutcome::Failed(e) => Err(e.into()),
    }
}
```

## Live Stripe Client

The production client with resilience features:

```rust
use tideway::billing::{LiveStripeClient, LiveStripeClientConfig, CircuitBreakerConfig};

// Default configuration
let client = LiveStripeClient::with_default_config(
    std::env::var("STRIPE_SECRET_KEY")?,
)?;

// Custom configuration
let config = LiveStripeClientConfig::new()
    .max_retries(5)
    .base_delay_ms(1000)
    .max_delay_ms(30_000)
    .timeout_seconds(60)
    .circuit_breaker(
        CircuitBreakerConfig::default()
            .failure_threshold(10)
            .open_duration_seconds(60)
    );

let client = LiveStripeClient::new(api_key, config)?;

// Check client mode
assert!(client.is_test_mode());  // sk_test_* keys
assert!(client.is_live_mode());  // sk_live_* keys

// Circuit breaker status
println!("Circuit state: {:?}", client.circuit_state());
client.reset_circuit_breaker();  // Manual reset if needed
```

## Storage Implementation

Implement `BillingStore` for your database:

```rust
use tideway::billing::{BillingStore, StoredSubscription};
use async_trait::async_trait;

#[async_trait]
impl BillingStore for MyDatabase {
    async fn get_subscription(&self, billable_id: &str)
        -> Result<Option<StoredSubscription>>;

    async fn save_subscription(&self, billable_id: &str, sub: &StoredSubscription)
        -> Result<()>;

    async fn delete_subscription(&self, billable_id: &str)
        -> Result<()>;

    async fn get_customer_id(&self, billable_id: &str)
        -> Result<Option<String>>;

    async fn save_customer_id(&self, billable_id: &str, customer_id: &str)
        -> Result<()>;

    // ... additional methods
}
```

For SeaORM users, enable the `billing-seaorm` feature for a ready-to-use implementation.

## Billable Entity

Implement `BillableEntity` for your user/organization model:

```rust
use tideway::billing::BillableEntity;

impl BillableEntity for Organization {
    fn billable_id(&self) -> &str {
        &self.id
    }

    fn billable_type(&self) -> &str {
        "org"
    }

    fn email(&self) -> &str {
        &self.billing_email
    }

    fn name(&self) -> Option<&str> {
        Some(&self.name)
    }
}
```

## Testing

Use mock clients for unit tests:

```rust
use tideway::billing::{
    InMemoryBillingStore, MockStripeClient, MockStripeCheckoutClient,
    ComprehensiveMockStripeClient, Plans,
};

#[tokio::test]
async fn test_checkout_flow() {
    let store = InMemoryBillingStore::new();
    let client = ComprehensiveMockStripeClient::new();
    let plans = Plans::builder()
        .plan("starter")
            .stripe_price("price_test")
            .done()
        .build();

    let manager = CheckoutManager::new(
        store,
        client,
        plans,
        CheckoutConfig::default(),
    );

    let session = manager.create_checkout_session(
        &test_org,
        CheckoutRequest::new("starter", success_url, cancel_url),
    ).await.unwrap();

    assert!(session.id.starts_with("cs_mock_"));
}
```

Enable the `test-billing` feature for access to mock implementations:

```toml
[dev-dependencies]
tideway = { version = "0.2", features = ["billing", "test-billing"] }
```

## Security Features

The billing module includes several security measures:

- **API key protection** - Keys stored in `SecretString`, never logged
- **Metadata sanitization** - Prevents injection attacks in Stripe metadata
- **Open redirect prevention** - Validates checkout redirect URLs against allowed domains
- **Ownership verification** - Payment methods and refunds verify ownership before operations
- **Circuit breaker** - Prevents cascading failures when Stripe is unavailable

## Environment Variables

```bash
# Required
STRIPE_SECRET_KEY=sk_live_xxx         # or sk_test_xxx for testing

# Optional (for webhooks)
STRIPE_WEBHOOK_SECRET=whsec_xxx
```

## Feature Flags

```toml
[dependencies]
tideway = { version = "0.2", features = ["billing"] }

# With SeaORM storage
tideway = { version = "0.2", features = ["billing", "billing-seaorm"] }

# For testing
[dev-dependencies]
tideway = { version = "0.2", features = ["billing", "test-billing"] }
```

## Limitations & Future Enhancements

Current limitations that may be addressed in future versions:

| Feature | Status | Notes |
|---------|--------|-------|
| Upcoming invoice preview | Not implemented | async-stripe limitation |
| Proration preview | Not implemented | Requires raw API call |
| Webhook signature verification | Partial | Often handled at HTTP layer |
| Usage-based billing | Not implemented | Metered subscription support |
| Multi-currency | Limited | Defaults to USD |
| Subscription schedules | Not implemented | For delayed plan changes |

These cover edge cases - the current implementation handles 95%+ of typical SaaS billing needs.

## Best Practices

1. **Use `SecureRefundManager`** for customer-facing refund operations
2. **Configure `allowed_redirect_domains`** in `CheckoutConfig` for production
3. **Use the circuit breaker** to handle Stripe outages gracefully
4. **Call `reconcile()`** periodically to detect missed webhooks
5. **Store Stripe customer IDs** - avoid creating duplicate customers
6. **Use `test-billing` feature** in tests to avoid hitting Stripe API
7. **Handle webhook events idempotently** - Stripe may retry delivery
