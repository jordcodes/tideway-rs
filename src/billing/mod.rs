//! Billing module for Stripe-based subscriptions.
//!
//! Provides subscription management, seat handling, and feature entitlements
//! for SaaS applications using Stripe.
//!
//! # Features
//!
//! - `billing` - Enables Stripe integration
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::billing::{
//!     BillingManager, BillingConfig, Plans, CheckoutRequest,
//! };
//!
//! // Configure plans
//! let plans = Plans::builder()
//!     .plan("starter")
//!         .stripe_price("price_starter")
//!         .extra_seat_price("price_seat")
//!         .included_seats(3)
//!         .features(["reports"])
//!         .trial_days(14)
//!         .done()
//!     .plan("pro")
//!         .stripe_price("price_pro")
//!         .extra_seat_price("price_seat")
//!         .included_seats(5)
//!         .features(["reports", "api", "priority_support"])
//!         .done()
//!     .build();
//!
//! // Create manager
//! let billing = BillingManager::new(store, config, plans);
//!
//! // Create checkout session
//! let session = billing.create_checkout_session(CheckoutRequest {
//!     billable_id: org.id.to_string(),
//!     plan_id: "starter".to_string(),
//!     success_url: "https://app.example.com/success".to_string(),
//!     cancel_url: "https://app.example.com/cancel".to_string(),
//!     ..Default::default()
//! }).await?;
//!
//! // Check entitlements
//! if !billing.check_feature(&org.id, "api").await? {
//!     return Err(ApiError::UpgradeRequired);
//! }
//! ```

pub mod audit;
pub mod checkout;
pub mod client;
pub mod customer;
pub mod entitlements;
pub mod error;
pub mod live_client;
pub mod payment;
pub mod plans;
pub mod portal;
pub mod refund;
#[cfg(feature = "billing-seaorm")]
pub mod sea_orm_store;
pub mod seats;
pub mod storage;
pub mod subscription;
pub mod invoice;
pub mod validation;
pub mod webhook;

// Plan exports
pub use plans::{LimitCheckResult, PlanBuilder, PlanConfig, PlanLimits, Plans, PlansBuilder};

// Storage exports
pub use storage::{BillableEntity, BillingStore, StoredSubscription, SubscriptionStatus};

// Customer exports
pub use customer::{
    CreateCustomerRequest, CustomerManager, CustomerMetadata, StripeClient, UpdateCustomerRequest,
};

// Subscription exports
pub use subscription::{
    ProrationBehavior, ReconcileDifference, ReconcileResult, StripeSubscriptionClient,
    StripeSubscriptionData, Subscription, SubscriptionManager, SubscriptionMetadata,
    UpdateSubscriptionRequest,
};

// Checkout exports
pub use checkout::{
    CheckoutConfig, CheckoutLineItem, CheckoutManager, CheckoutMetadata, CheckoutMode,
    CheckoutRequest, CheckoutSession, CreateCheckoutSessionRequest, SeatCheckoutRequest,
    StripeCheckoutClient,
};

// Portal exports
pub use portal::{
    CreatePortalSessionRequest, PortalConfig, PortalFlow, PortalManager, PortalSession,
    StripePortalClient,
};

// Webhook exports
pub use webhook::{WebhookEvent, WebhookEventData, WebhookHandler, WebhookOutcome};

// Invoice exports
pub use invoice::{
    CachedInvoiceManager, Invoice, InvoiceConfig, InvoiceLineItem, InvoiceList, InvoiceListParams,
    InvoiceManager, InvoiceOperations, InvoiceStatus, InvoiceStatusParseError, StripeInvoiceClient,
};

// Seats exports
pub use seats::{SeatChangeResult, SeatInfo, SeatManager};

// Payment exports
pub use payment::{PaymentMethod, PaymentMethodList, PaymentMethodManager, StripePaymentMethodClient};

// Refund exports
pub use refund::{
    CreateRefundRequest, Refund, RefundManager, RefundReason, RefundStatus, StripeRefundClient,
};

// Entitlements exports
pub use entitlements::{
    CachedEntitlementsManager, EntitlementLimits, Entitlements, EntitlementsManager,
    FeatureCheckResult, require_feature, require_seat,
};

// Audit exports
pub use audit::{BillingAuditEvent, BillingAuditLogger, NoOpAuditLogger, TracingAuditLogger};

// Error exports
pub use error::BillingError;

// Client exports
pub use client::FullStripeClient;

// Live client exports (production Stripe client)
pub use live_client::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState, InvalidApiKeyError, LiveStripeClient,
    LiveStripeClientConfig,
};

// SeaORM storage exports
#[cfg(feature = "billing-seaorm")]
pub use sea_orm_store::SeaOrmBillingStore;

// Validation exports
pub use validation::{validate_billable_id, validate_plan_id};

// Test exports
#[cfg(any(test, feature = "test-billing"))]
pub use storage::test::InMemoryBillingStore;

#[cfg(any(test, feature = "test-billing"))]
pub use customer::test::MockStripeClient;

#[cfg(any(test, feature = "test-billing"))]
pub use subscription::test::MockStripeSubscriptionClient;

#[cfg(any(test, feature = "test-billing"))]
pub use checkout::test::{MockStripeCheckoutClient, MockFullStripeClient};

#[cfg(any(test, feature = "test-billing"))]
pub use portal::test::MockStripePortalClient;

#[cfg(any(test, feature = "test-billing"))]
pub use invoice::test::MockStripeInvoiceClient;

#[cfg(any(test, feature = "test-billing"))]
pub use payment::test::MockStripePaymentMethodClient;

#[cfg(any(test, feature = "test-billing"))]
pub use refund::test::MockStripeRefundClient;

#[cfg(any(test, feature = "test-billing"))]
pub use client::test::{ComprehensiveMockStripeClient, FullMockStripeClient};
