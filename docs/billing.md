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

## Currency Support

The billing module fully supports multiple currencies. Currency is determined by your Stripe Price configuration - when you create prices in Stripe, you specify the currency (GBP, USD, EUR, etc.).

```rust
// Define plans with explicit currency for documentation/display
let plans = Plans::builder()
    .plan("starter")
        .stripe_price("price_starter_gbp")  // GBP price in Stripe
        .currency("gbp")                     // Optional: for display purposes
        .included_seats(3)
        .done()
    .build();
```

The module defaults to GBP for mock clients in tests. For other currencies:

```rust
// Create mock client with specific currency
let client = ComprehensiveMockStripeClient::with_currency("usd");
let invoice_client = MockStripeInvoiceClient::with_currency("eur");
let refund_client = MockStripeRefundClient::with_currency("gbp");
```

## Plan Management

Tideway supports two approaches to plan management:

1. **Static Plans** - Code-configured, defined at compile time
2. **Dynamic Plans** - Database-backed, admin-editable at runtime

You can use either approach or combine them for a hybrid setup.

### Static Plans (Code-Configured)

Define plans using the builder pattern. Best for simple setups where plans rarely change:

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
        .max_projects(10)
        .max_storage_mb(5000)
        .custom_limit("api_calls", 1000)
        .done()
    .plan("pro")
        .stripe_price("price_pro")
        .extra_seat_price("price_seat")
        .included_seats(10)
        .features(["basic", "reports", "api", "priority_support"])
        .max_projects(100)
        .max_storage_mb(50000)
        .custom_limit("api_calls", 100_000)
        .done()
    .build();
```

### Dynamic Plans (Database-Backed)

For admin-managed plans that can be created, updated, or disabled without code changes.

#### The StoredPlan Type

```rust
use tideway::billing::{StoredPlan, PlanInterval};

let plan = StoredPlan {
    id: "starter".to_string(),
    name: "Starter Plan".to_string(),
    description: Some("Perfect for small teams".to_string()),
    stripe_price_id: "price_starter_monthly".to_string(),
    stripe_seat_price_id: Some("price_seat".to_string()),
    price_cents: 999,  // $9.99
    currency: "usd".to_string(),
    interval: PlanInterval::Monthly,
    included_seats: 3,
    features: serde_json::json!({
        "basic": true,
        "reports": true,
        "api_access": false
    }),
    limits: serde_json::json!({
        "projects": 10,
        "storage_mb": 5000,
        "api_calls": 1000
    }),
    trial_days: Some(14),
    is_active: true,
    sort_order: 1,
    created_at: 0,  // Unix timestamp
    updated_at: 0,
};
```

#### The PlanStore Trait

```rust
use tideway::billing::{PlanStore, StoredPlan};
use async_trait::async_trait;

#[async_trait]
pub trait PlanStore: Send + Sync {
    /// List active plans (for public pricing pages).
    async fn list_plans(&self) -> Result<Vec<StoredPlan>>;

    /// List all plans including inactive (for admin).
    async fn list_all_plans(&self) -> Result<Vec<StoredPlan>>;

    /// Get a plan by ID.
    async fn get_plan(&self, plan_id: &str) -> Result<Option<StoredPlan>>;

    /// Get a plan by its Stripe price ID.
    async fn get_plan_by_stripe_price(&self, stripe_price_id: &str) -> Result<Option<StoredPlan>>;

    /// Create a new plan.
    async fn create_plan(&self, plan: &StoredPlan) -> Result<()>;

    /// Update an existing plan.
    async fn update_plan(&self, plan: &StoredPlan) -> Result<()>;

    /// Delete a plan.
    async fn delete_plan(&self, plan_id: &str) -> Result<()>;

    /// Set a plan's active status.
    async fn set_plan_active(&self, plan_id: &str, is_active: bool) -> Result<()>;
}
```

#### SeaORM Implementation

Enable the `billing-seaorm` feature for a ready-to-use implementation:

```toml
[dependencies]
tideway = { version = "0.2", features = ["billing", "billing-seaorm"] }
```

```rust
use tideway::billing::SeaOrmBillingStore;

let store = SeaOrmBillingStore::new(db_connection);

// List plans for pricing page
let active_plans = store.list_plans().await?;

// Admin: list all plans
let all_plans = store.list_all_plans().await?;

// Create a new plan
store.create_plan(&plan).await?;

// Deactivate a plan (soft delete)
store.set_plan_active("legacy_plan", false).await?;
```

### Hybrid Approach: Combining Static and Dynamic Plans

Load plans from the database and merge with code-defined defaults:

```rust
use tideway::billing::{Plans, PlanStore};

// Load from database
let stored_plans = store.list_plans().await?;
let mut plans = Plans::from_stored(stored_plans);

// Merge with code-defined fallbacks
let defaults = Plans::builder()
    .plan("free")
        .stripe_price("price_free")
        .included_seats(1)
        .features(["basic"])
        .done()
    .build();

plans.merge(defaults);  // Database plans take precedence
```

### Converting Between Plan Types

Database plans can be converted to the code-configured `PlanConfig` type:

```rust
use tideway::billing::{Plans, PlanConfig, StoredPlan};

// Single plan conversion
let stored: StoredPlan = store.get_plan("starter").await?.unwrap();
let config: PlanConfig = stored.into();

// Batch conversion
let stored_plans = store.list_plans().await?;
let plans = Plans::from_stored(stored_plans);

// Use with existing managers
let checkout_manager = CheckoutManager::new(store, client, plans, config);
```

### Plan Validation

Validate plans before saving to the database:

```rust
use tideway::billing::{validate_plan, validate_plan_id, StoredPlan};

// Validate just the plan ID
validate_plan_id("starter")?;      // Ok
validate_plan_id("plan with spaces")?;  // Error

// Validate a complete plan
let plan = StoredPlan::new("starter", "price_abc123");
validate_plan(&plan)?;
```

Validation checks:
- **Plan ID**: Non-empty, max 64 chars, alphanumeric/underscore/hyphen only
- **Name**: Non-empty, max 128 chars
- **Description**: Max 1024 chars
- **Stripe Price ID**: Non-empty, must start with `price_`
- **Price**: Non-negative
- **Currency**: Valid ISO 4217 code (usd, eur, gbp, etc.)
- **Included Seats**: At least 1

### Database Migration

Add the billing_plans table with the provided migration template:

```rust
// migration/src/m008_create_billing_plans.rs
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(
            Table::create()
                .table(BillingPlans::Table)
                .col(ColumnDef::new(BillingPlans::Id).string().not_null().primary_key())
                .col(ColumnDef::new(BillingPlans::Name).string().not_null())
                .col(ColumnDef::new(BillingPlans::Description).string())
                .col(ColumnDef::new(BillingPlans::StripePriceId).string().not_null())
                .col(ColumnDef::new(BillingPlans::StripeSeatPriceId).string())
                .col(ColumnDef::new(BillingPlans::PriceCents).big_integer().not_null())
                .col(ColumnDef::new(BillingPlans::Currency).string().not_null().default("usd"))
                .col(ColumnDef::new(BillingPlans::Interval).string().not_null().default("monthly"))
                .col(ColumnDef::new(BillingPlans::IncludedSeats).integer().not_null().default(1))
                .col(ColumnDef::new(BillingPlans::Features).json_binary().not_null().default("{}"))
                .col(ColumnDef::new(BillingPlans::Limits).json_binary().not_null().default("{}"))
                .col(ColumnDef::new(BillingPlans::TrialDays).integer())
                .col(ColumnDef::new(BillingPlans::IsActive).boolean().not_null().default(true))
                .col(ColumnDef::new(BillingPlans::SortOrder).integer().not_null().default(0))
                .col(ColumnDef::new(BillingPlans::CreatedAt).timestamp_with_time_zone().not_null())
                .col(ColumnDef::new(BillingPlans::UpdatedAt).timestamp_with_time_zone().not_null())
                .to_owned(),
        ).await?;

        // Create indexes...
        Ok(())
    }
}
```

### API Routes for Plan Management

The `tideway generate backend` command creates these routes:

#### Public Routes (for pricing pages)

```
GET /billing/plans    → List active plans
```

#### Admin Routes (protected)

```
GET    /admin/plans           → List all plans (including inactive)
POST   /admin/plans           → Create a new plan
GET    /admin/plans/:id       → Get a single plan
PUT    /admin/plans/:id       → Update a plan
DELETE /admin/plans/:id       → Delete a plan
POST   /admin/plans/:id/active → Toggle active status
```

#### Example: Create Plan Request

```json
POST /admin/plans
{
  "id": "starter",
  "name": "Starter Plan",
  "description": "Perfect for small teams",
  "stripe_price_id": "price_starter_monthly",
  "price_cents": 999,
  "currency": "usd",
  "interval": "monthly",
  "included_seats": 3,
  "features": {
    "basic": true,
    "reports": true
  },
  "limits": {
    "projects": 10,
    "storage_mb": 5000
  },
  "trial_days": 14,
  "is_active": true,
  "sort_order": 1
}
```

#### Example: Plan Response

```json
{
  "id": "starter",
  "name": "Starter Plan",
  "description": "Perfect for small teams",
  "stripe_price_id": "price_starter_monthly",
  "stripe_seat_price_id": null,
  "price_cents": 999,
  "currency": "usd",
  "interval": "monthly",
  "included_seats": 3,
  "features": {"basic": true, "reports": true},
  "limits": {"projects": 10, "storage_mb": 5000},
  "trial_days": 14,
  "is_active": true,
  "sort_order": 1,
  "created_at": 1704067200,
  "updated_at": 1704067200
}
```

### Frontend Components (Vue + shadcn-vue)

The `tideway generate billing` command creates Vue components for plan management:

#### usePlans Composable

```typescript
import { usePlans } from '@/components/tideway/billing/composables/usePlans'

const {
  plans,
  isLoading,
  error,
  fetchPlans,
  createPlan,
  updatePlan,
  deletePlan,
  setActive
} = usePlans()

// Load plans
await fetchPlans()           // Active plans only
await fetchPlans(true)       // All plans (admin)

// Create a plan
await createPlan({
  id: 'starter',
  name: 'Starter Plan',
  stripe_price_id: 'price_abc123',
  price_cents: 999,
  // ...
})

// Toggle active status
await setActive('starter', false)
```

#### PlanList Component (Admin)

```vue
<template>
  <PlanList
    @create="showCreateForm = true"
    @edit="editPlan"
    @delete="confirmDelete"
  />
</template>
```

Features:
- Table view of all plans (active and inactive)
- Actions dropdown: Edit, Activate/Deactivate, Delete
- Delete confirmation dialog
- Loading and error states

#### PlanForm Component (Admin)

```vue
<template>
  <PlanForm
    :plan="selectedPlan"
    @saved="handleSaved"
    @cancel="closeForm"
  />
</template>
```

Features:
- Create and edit modes
- All plan fields with validation
- Features list (add/remove boolean features)
- Limits list (add/remove numeric limits)
- Price input with currency conversion

#### PricingTable Component (Public)

```vue
<template>
  <PricingTable
    :current-plan-id="subscription?.plan_id"
    :highlight-plan-id="'pro'"
    @select-plan="handleSelectPlan"
  />
</template>
```

Features:
- Monthly/Yearly billing toggle
- Feature comparison across plans
- "Most Popular" badge
- Current plan indicator
- Trial days display

### Testing Plan Management

Use `InMemoryBillingStore` for testing:

```rust
use tideway::billing::{InMemoryBillingStore, StoredPlan, PlanStore, PlanInterval};

#[tokio::test]
async fn test_plan_crud() {
    let store = InMemoryBillingStore::new();

    // Create a plan
    let plan = StoredPlan {
        id: "test".to_string(),
        name: "Test Plan".to_string(),
        stripe_price_id: "price_test".to_string(),
        price_cents: 999,
        currency: "usd".to_string(),
        interval: PlanInterval::Monthly,
        included_seats: 1,
        is_active: true,
        // ... other fields
    };
    store.create_plan(&plan).await.unwrap();

    // Verify
    let loaded = store.get_plan("test").await.unwrap().unwrap();
    assert_eq!(loaded.price_cents, 999);

    // List active plans
    let active = store.list_plans().await.unwrap();
    assert_eq!(active.len(), 1);

    // Deactivate
    store.set_plan_active("test", false).await.unwrap();
    let active = store.list_plans().await.unwrap();
    assert_eq!(active.len(), 0);  // Not in active list

    // Still in all plans
    let all = store.list_all_plans().await.unwrap();
    assert_eq!(all.len(), 1);
}
```

### StoredPlan Helper Methods

```rust
let plan = store.get_plan("starter").await?.unwrap();

// Check if a feature is enabled
if plan.has_feature("api_access") {
    // ...
}

// Get a limit value
let max_projects = plan.get_limit("projects");  // Option<i64>

// Check if under a limit
if plan.check_limit("projects", current_count) {
    // Under limit, allow creation
}

// Format price for display
let display = plan.formatted_price();  // "$9.99"
```

### Admin Authorization for Plan Routes

Protect plan management routes with the `RequireAdmin` extractor:

```rust
use tideway::auth::{AdminUser, RequireAdmin, AuthProvider};

// Implement AdminUser for your user type
impl AdminUser for User {
    fn is_admin(&self) -> bool {
        self.is_platform_admin
    }
}

// Use RequireAdmin in handlers
async fn admin_create_plan(
    RequireAdmin(admin): RequireAdmin<MyAuthProvider>,
    State(state): State<Arc<BillingState>>,
    Json(body): Json<CreatePlanRequest>,
) -> Result<Json<AdminPlanResponse>> {
    // Only admins can reach this handler
    // Non-admins receive 403 Forbidden
    // ...
}
```

The `RequireAdmin` extractor:
- First verifies the user is authenticated (401 if not)
- Then checks `is_admin()` returns true (403 if not)
- Provides access to the authenticated admin user

### Plan Deletion Constraints

Plans with active subscriptions cannot be deleted. This prevents orphaned subscriptions and billing inconsistencies.

```rust
use tideway::billing::{BillingStore, BillingError};

// Check subscription count before deletion
let count = store.count_subscriptions_by_plan("starter").await?;
if count > 0 {
    // Returns error with plan_id and subscription_count
    return Err(BillingError::PlanHasActiveSubscriptions {
        plan_id: "starter".to_string(),
        subscription_count: count,
    }.into());
}

// Safe to delete
store.delete_plan("starter").await?;
```

The `count_subscriptions_by_plan` method counts subscriptions with status `Active` or `Trialing`. Canceled or expired subscriptions don't block deletion.

**Best Practice**: Instead of deleting plans, deactivate them:

```rust
// Deactivate instead of delete
store.set_plan_active("legacy_plan", false).await?;

// Inactive plans:
// - Not shown in list_plans() (public pricing page)
// - Still visible in list_all_plans() (admin)
// - Existing subscriptions continue working
```

### Stripe Price Validation

Validate that Stripe price IDs exist and are correctly configured before creating plans:

```rust
use tideway::billing::{
    validate_plan, validate_plan_with_stripe,
    StripePriceValidator, StripePrice, LiveStripeClient,
};

// Basic validation (format only)
validate_plan(&plan)?;

// Full validation including Stripe API check
let client = LiveStripeClient::new(api_key, config)?;
validate_plan_with_stripe(&plan, &client).await?;
```

The `validate_plan_with_stripe` function checks:
- All `validate_plan` checks (format, required fields)
- Base price exists in Stripe
- Base price is active (not archived)
- Currency matches between plan and Stripe price
- Seat price exists and is active (if configured)
- Seat price currency matches

#### StripePriceValidator Trait

For testing, use `MockPriceValidator`:

```rust
use tideway::billing::MockPriceValidator;

let validator = MockPriceValidator::new();
validator.add_active_price("price_starter", "usd", 999);
validator.add_active_price("price_seat", "usd", 500);

// Now validation will pass
validate_plan_with_stripe(&plan, &validator).await?;
```

#### API Integration

The admin create plan endpoint supports optional Stripe validation:

```json
POST /admin/plans
{
  "id": "starter",
  "name": "Starter Plan",
  "stripe_price_id": "price_starter_monthly",
  "price_cents": 999,
  "currency": "usd",
  "validate_stripe": true  // Validates against Stripe API
}
```

When `validate_stripe` is true:
- API call to Stripe verifies price exists
- Returns 400 if price not found or inactive
- Returns 400 if currency doesn't match

### Audit Logging for Plan Operations

Track all plan changes for compliance and debugging:

```rust
use tideway::billing::{BillingAuditEvent, BillingAuditLogger, TracingAuditLogger};

// Use the built-in tracing logger
let audit_logger = TracingAuditLogger;

// Log plan creation
audit_logger.log(BillingAuditEvent::PlanCreated {
    plan_id: "starter".to_string(),
    name: "Starter Plan".to_string(),
    admin_id: Some("user_123".to_string()),
}).await;

// Log plan update with changes
audit_logger.log(BillingAuditEvent::PlanUpdated {
    plan_id: "starter".to_string(),
    admin_id: Some("user_123".to_string()),
    changes: vec![
        "price_cents: 999 -> 1499".to_string(),
        "included_seats: 3 -> 5".to_string(),
    ],
}).await;

// Log blocked deletion attempt
audit_logger.log(BillingAuditEvent::PlanDeletionBlocked {
    plan_id: "starter".to_string(),
    subscription_count: 42,
    admin_id: Some("user_123".to_string()),
}).await;
```

#### Plan Audit Events

| Event | Description |
|-------|-------------|
| `PlanCreated` | New plan created |
| `PlanUpdated` | Plan fields modified (includes list of changes) |
| `PlanDeleted` | Plan permanently deleted |
| `PlanActivated` | Plan set to active |
| `PlanDeactivated` | Plan set to inactive |
| `PlanDeletionBlocked` | Deletion attempted but blocked due to subscriptions |

#### Custom Audit Logger

Implement `BillingAuditLogger` to send events to your audit system:

```rust
use tideway::billing::{BillingAuditLogger, BillingAuditEvent};
use async_trait::async_trait;

struct DatabaseAuditLogger {
    db: DatabasePool,
}

#[async_trait]
impl BillingAuditLogger for DatabaseAuditLogger {
    async fn log(&self, event: BillingAuditEvent) {
        // Insert into audit_log table
        sqlx::query("INSERT INTO audit_log (event_type, payload, created_at) VALUES ($1, $2, NOW())")
            .bind(event.event_type())
            .bind(serde_json::to_value(&event).unwrap())
            .execute(&self.db)
            .await
            .ok(); // Don't fail billing operations on audit errors
    }
}
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
