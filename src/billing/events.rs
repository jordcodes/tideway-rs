//! Application hooks for Stripe billing lifecycle events.

use async_trait::async_trait;

use crate::error::Result;

use super::subscription::StripeSubscriptionData;

/// Stripe metadata shared by every emitted billing lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingEventContext {
    /// Stripe's globally unique event ID.
    pub event_id: String,
    /// Unix timestamp supplied by Stripe when the event was created.
    pub created: u64,
}

/// Typed billing lifecycle event emitted after Tideway's core processing succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BillingEvent {
    /// A subscription-mode Checkout Session completed.
    CheckoutCompleted {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Stripe subscription ID created by Checkout.
        subscription_id: String,
        /// Stripe customer ID, when included in the event.
        customer_id: Option<String>,
        /// Application billable ID from Stripe metadata, when present.
        billable_id: Option<String>,
    },
    /// A one-time payment Checkout Session completed or later succeeded.
    OneTimeCheckoutCompleted {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Stripe Checkout Session ID.
        checkout_session_id: String,
        /// Stripe customer ID, when included in the event.
        customer_id: Option<String>,
        /// Application billable ID from Stripe metadata, when present.
        billable_id: Option<String>,
        /// Application billable type from Stripe metadata, when present.
        billable_type: Option<String>,
        /// Server-defined product or pack ID from Stripe metadata, when present.
        plan_id: Option<String>,
        /// Stripe payment status, such as `paid` or `unpaid`.
        payment_status: Option<String>,
    },
    /// Stripe created a subscription and Tideway synchronized it locally.
    SubscriptionCreated {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Normalized subscription state.
        subscription: StripeSubscriptionData,
    },
    /// Stripe updated a subscription and Tideway synchronized it locally.
    SubscriptionUpdated {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Normalized subscription state.
        subscription: StripeSubscriptionData,
    },
    /// Stripe deleted a subscription and Tideway removed its local state.
    SubscriptionDeleted {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Stripe subscription ID.
        subscription_id: String,
        /// Stripe customer ID, when included in the event.
        customer_id: Option<String>,
        /// Application billable ID from Stripe metadata, when present.
        billable_id: Option<String>,
    },
    /// Stripe marked an invoice as paid.
    InvoicePaid {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Stripe invoice ID, when included in the event.
        invoice_id: Option<String>,
        /// Related Stripe subscription ID, when included in the event.
        subscription_id: Option<String>,
        /// Related Stripe customer ID, when included in the event.
        customer_id: Option<String>,
    },
    /// Stripe reported that an invoice payment failed.
    InvoicePaymentFailed {
        /// Shared Stripe event metadata.
        context: BillingEventContext,
        /// Stripe invoice ID, when included in the event.
        invoice_id: Option<String>,
        /// Related Stripe subscription ID, when included in the event.
        subscription_id: Option<String>,
        /// Related Stripe customer ID, when included in the event.
        customer_id: Option<String>,
    },
}

impl BillingEvent {
    /// Return Stripe's event ID for idempotent application processing.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.context().event_id
    }

    /// Return the timestamp supplied by Stripe.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.context().created
    }

    /// Return the stable Tideway event name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CheckoutCompleted { .. } => "checkout_completed",
            Self::OneTimeCheckoutCompleted { .. } => "one_time_checkout_completed",
            Self::SubscriptionCreated { .. } => "subscription_created",
            Self::SubscriptionUpdated { .. } => "subscription_updated",
            Self::SubscriptionDeleted { .. } => "subscription_deleted",
            Self::InvoicePaid { .. } => "invoice_paid",
            Self::InvoicePaymentFailed { .. } => "invoice_payment_failed",
        }
    }

    fn context(&self) -> &BillingEventContext {
        match self {
            Self::CheckoutCompleted { context, .. }
            | Self::OneTimeCheckoutCompleted { context, .. }
            | Self::SubscriptionCreated { context, .. }
            | Self::SubscriptionUpdated { context, .. }
            | Self::SubscriptionDeleted { context, .. }
            | Self::InvoicePaid { context, .. }
            | Self::InvoicePaymentFailed { context, .. } => context,
        }
    }
}

/// Application hook for billing lifecycle events.
///
/// Tideway invokes the sink after its core local state mutation succeeds. Implementations must be
/// idempotent by [`BillingEvent::event_id`]: returning an error releases the webhook claim so Stripe
/// can retry, and the core mutation may therefore run again before the sink is called again.
#[async_trait]
pub trait BillingEventSink: Send + Sync {
    /// Handle a successfully processed billing lifecycle event.
    async fn handle(&self, event: &BillingEvent) -> Result<()>;
}

/// Default sink used when an application does not need lifecycle hooks.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpBillingEventSink;

#[async_trait]
impl BillingEventSink for NoOpBillingEventSink {
    async fn handle(&self, _event: &BillingEvent) -> Result<()> {
        Ok(())
    }
}
