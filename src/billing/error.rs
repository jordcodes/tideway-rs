//! Billing-specific error types.
//!
//! Provides granular error types for billing operations, enabling better
//! error handling and more informative error messages for API consumers.

use std::fmt;

/// Billing-specific errors.
///
/// These errors provide more context than generic errors and can be
/// converted to `TidewayError` for HTTP responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingError {
    // Validation errors
    /// The billable ID is invalid.
    InvalidBillableId { id: String, reason: String },
    /// The plan ID is invalid.
    InvalidPlanId { id: String, reason: String },

    // Plan errors
    /// The specified plan was not found.
    PlanNotFound { plan_id: String },
    /// The plan does not support extra seats.
    PlanDoesNotSupportSeats { plan_id: String },
    /// The requested feature is not available on this plan.
    FeatureNotIncluded { feature: String, plan_id: String },
    /// Cannot delete a plan that has active subscriptions.
    PlanHasActiveSubscriptions { plan_id: String, subscription_count: u32 },
    /// The Stripe price ID is invalid or does not exist.
    InvalidStripePrice { price_id: String, reason: String },

    // Subscription errors
    /// No subscription found for the billable entity.
    NoSubscription { billable_id: String },
    /// The subscription is not active.
    SubscriptionInactive { billable_id: String },
    /// The subscription is scheduled for cancellation but was expected to be active.
    SubscriptionCancelling { billable_id: String },
    /// Cannot find the Stripe subscription.
    StripeSubscriptionNotFound { subscription_id: String },

    // Customer errors
    /// No Stripe customer found for the billable entity.
    NoCustomer { billable_id: String },

    // Invoice errors
    /// Invoice not found or doesn't belong to the customer.
    InvoiceNotFound { invoice_id: String },

    // Payment method errors
    /// Payment method not found or doesn't belong to the customer.
    PaymentMethodNotFound { payment_method_id: String },

    // Refund errors
    /// Refund not found.
    RefundNotFound { refund_id: String },
    /// Refund operation failed.
    RefundFailed { reason: String },
    /// Charge not found for refund.
    ChargeNotFound { charge_id: String },

    // Seat errors
    /// Cannot remove more seats than are currently extra.
    InsufficientSeats { requested: u32, available: u32 },
    /// Seat count must be positive.
    InvalidSeatCount { message: String },
    /// Concurrent modification detected, retry the operation.
    ConcurrentModification { billable_id: String },

    // Trial errors
    /// Subscription is not in trialing state.
    SubscriptionNotTrialing { billable_id: String },

    // Pause errors
    /// Subscription is not paused.
    SubscriptionNotPaused { billable_id: String },
    /// Subscription is already paused.
    SubscriptionAlreadyPaused { billable_id: String },

    // Checkout errors
    /// Invalid redirect URL provided.
    InvalidRedirectUrl { url: String, reason: String },
    /// Redirect URL domain not in allowed list.
    RedirectDomainNotAllowed { domain: String },

    // Webhook errors
    /// Webhook signature is invalid.
    InvalidWebhookSignature,
    /// Webhook timestamp is too old (replay attack protection).
    WebhookTimestampExpired { age_seconds: i64 },
    /// Webhook event data is malformed.
    InvalidWebhookPayload { message: String },

    // Stripe API errors
    /// Stripe API returned an error.
    StripeApiError {
        operation: String,
        message: String,
        code: Option<String>,
        http_status: Option<u16>,
    },

    // General errors
    /// The operation failed after multiple retries.
    RetryLimitExceeded { operation: String },
    /// An unexpected internal error occurred.
    Internal { message: String },
}

impl fmt::Display for BillingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBillableId { id, reason } => {
                write!(f, "Invalid billable ID '{}': {}", id, reason)
            }
            Self::InvalidPlanId { id, reason } => {
                write!(f, "Invalid plan ID '{}': {}", id, reason)
            }
            Self::PlanNotFound { plan_id } => {
                write!(f, "Plan not found: {}", plan_id)
            }
            Self::PlanDoesNotSupportSeats { plan_id } => {
                write!(f, "Plan '{}' does not support extra seats", plan_id)
            }
            Self::FeatureNotIncluded { feature, plan_id } => {
                write!(f, "Feature '{}' is not included in plan '{}'", feature, plan_id)
            }
            Self::PlanHasActiveSubscriptions { plan_id, subscription_count } => {
                write!(f, "Cannot delete plan '{}': {} active subscription(s) exist", plan_id, subscription_count)
            }
            Self::InvalidStripePrice { price_id, reason } => {
                write!(f, "Invalid Stripe price '{}': {}", price_id, reason)
            }
            Self::NoSubscription { billable_id } => {
                write!(f, "No subscription found for '{}'", billable_id)
            }
            Self::SubscriptionInactive { billable_id } => {
                write!(f, "Subscription for '{}' is not active", billable_id)
            }
            Self::SubscriptionCancelling { billable_id } => {
                write!(f, "Subscription for '{}' is scheduled for cancellation", billable_id)
            }
            Self::StripeSubscriptionNotFound { subscription_id } => {
                write!(f, "Stripe subscription not found: {}", subscription_id)
            }
            Self::NoCustomer { billable_id } => {
                write!(f, "No Stripe customer found for '{}'", billable_id)
            }
            Self::InvoiceNotFound { invoice_id } => {
                write!(f, "Invoice not found: {}", invoice_id)
            }
            Self::PaymentMethodNotFound { payment_method_id } => {
                write!(f, "Payment method not found: {}", payment_method_id)
            }
            Self::RefundNotFound { refund_id } => {
                write!(f, "Refund not found: {}", refund_id)
            }
            Self::RefundFailed { reason } => {
                write!(f, "Refund failed: {}", reason)
            }
            Self::ChargeNotFound { charge_id } => {
                write!(f, "Charge not found: {}", charge_id)
            }
            Self::InsufficientSeats { requested, available } => {
                write!(f, "Cannot remove {} seats, only {} extra seats available", requested, available)
            }
            Self::InvalidSeatCount { message } => {
                write!(f, "Invalid seat count: {}", message)
            }
            Self::ConcurrentModification { billable_id } => {
                write!(f, "Concurrent modification detected for '{}', please retry", billable_id)
            }
            Self::SubscriptionNotTrialing { billable_id } => {
                write!(f, "Subscription for '{}' is not in trialing state", billable_id)
            }
            Self::SubscriptionNotPaused { billable_id } => {
                write!(f, "Subscription for '{}' is not paused", billable_id)
            }
            Self::SubscriptionAlreadyPaused { billable_id } => {
                write!(f, "Subscription for '{}' is already paused", billable_id)
            }
            Self::InvalidRedirectUrl { url, reason } => {
                write!(f, "Invalid redirect URL '{}': {}", url, reason)
            }
            Self::RedirectDomainNotAllowed { domain } => {
                write!(f, "Redirect domain '{}' is not allowed", domain)
            }
            Self::InvalidWebhookSignature => {
                write!(f, "Invalid webhook signature")
            }
            Self::WebhookTimestampExpired { age_seconds } => {
                write!(f, "Webhook timestamp expired ({} seconds old)", age_seconds)
            }
            Self::InvalidWebhookPayload { message } => {
                write!(f, "Invalid webhook payload: {}", message)
            }
            Self::StripeApiError { operation, message, code, http_status } => {
                write!(f, "Stripe API error during '{}': {}", operation, message)?;
                if let Some(code) = code {
                    write!(f, " (code: {})", code)?;
                }
                if let Some(status) = http_status {
                    write!(f, " [HTTP {}]", status)?;
                }
                Ok(())
            }
            Self::RetryLimitExceeded { operation } => {
                write!(f, "Operation '{}' failed after multiple retries", operation)
            }
            Self::Internal { message } => {
                write!(f, "Internal billing error: {}", message)
            }
        }
    }
}

impl std::error::Error for BillingError {}

impl From<BillingError> for crate::error::TidewayError {
    fn from(err: BillingError) -> Self {
        match &err {
            // Map to NotFound
            BillingError::PlanNotFound { .. }
            | BillingError::NoSubscription { .. }
            | BillingError::NoCustomer { .. }
            | BillingError::StripeSubscriptionNotFound { .. }
            | BillingError::InvoiceNotFound { .. }
            | BillingError::PaymentMethodNotFound { .. }
            | BillingError::RefundNotFound { .. }
            | BillingError::ChargeNotFound { .. } => {
                crate::error::TidewayError::NotFound(err.to_string())
            }

            // Map to Forbidden (subscription state issues)
            BillingError::SubscriptionInactive { .. }
            | BillingError::SubscriptionCancelling { .. }
            | BillingError::FeatureNotIncluded { .. } => {
                crate::error::TidewayError::Forbidden(err.to_string())
            }

            // Map to BadRequest (client errors)
            BillingError::InvalidBillableId { .. }
            | BillingError::InvalidPlanId { .. }
            | BillingError::PlanDoesNotSupportSeats { .. }
            | BillingError::PlanHasActiveSubscriptions { .. }
            | BillingError::InvalidStripePrice { .. }
            | BillingError::InsufficientSeats { .. }
            | BillingError::InvalidSeatCount { .. }
            | BillingError::InvalidRedirectUrl { .. }
            | BillingError::RedirectDomainNotAllowed { .. }
            | BillingError::InvalidWebhookSignature
            | BillingError::WebhookTimestampExpired { .. }
            | BillingError::InvalidWebhookPayload { .. }
            | BillingError::SubscriptionNotTrialing { .. }
            | BillingError::SubscriptionNotPaused { .. }
            | BillingError::SubscriptionAlreadyPaused { .. } => {
                crate::error::TidewayError::BadRequest(err.to_string())
            }

            // Map to Internal (server errors)
            BillingError::ConcurrentModification { .. }
            | BillingError::RetryLimitExceeded { .. }
            | BillingError::Internal { .. }
            | BillingError::RefundFailed { .. } => {
                crate::error::TidewayError::Internal(err.to_string())
            }

            // Map Stripe API errors based on HTTP status
            BillingError::StripeApiError { http_status, .. } => {
                match http_status {
                    Some(400..=499) => crate::error::TidewayError::BadRequest(err.to_string()),
                    _ => crate::error::TidewayError::Internal(err.to_string()),
                }
            }
        }
    }
}

impl BillingError {
    /// Check if this is a client error (4xx).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        match self {
            Self::InvalidBillableId { .. }
            | Self::InvalidPlanId { .. }
            | Self::PlanNotFound { .. }
            | Self::NoSubscription { .. }
            | Self::NoCustomer { .. }
            | Self::StripeSubscriptionNotFound { .. }
            | Self::InvoiceNotFound { .. }
            | Self::PaymentMethodNotFound { .. }
            | Self::RefundNotFound { .. }
            | Self::ChargeNotFound { .. }
            | Self::SubscriptionInactive { .. }
            | Self::SubscriptionCancelling { .. }
            | Self::FeatureNotIncluded { .. }
            | Self::PlanDoesNotSupportSeats { .. }
            | Self::PlanHasActiveSubscriptions { .. }
            | Self::InvalidStripePrice { .. }
            | Self::InsufficientSeats { .. }
            | Self::InvalidSeatCount { .. }
            | Self::InvalidRedirectUrl { .. }
            | Self::RedirectDomainNotAllowed { .. }
            | Self::InvalidWebhookSignature
            | Self::WebhookTimestampExpired { .. }
            | Self::InvalidWebhookPayload { .. }
            | Self::SubscriptionNotTrialing { .. }
            | Self::SubscriptionNotPaused { .. }
            | Self::SubscriptionAlreadyPaused { .. } => true,
            Self::StripeApiError { http_status, .. } => {
                matches!(http_status, Some(400..=499))
            }
            _ => false,
        }
    }

    /// Check if this is a server error (5xx).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        match self {
            Self::ConcurrentModification { .. }
            | Self::RetryLimitExceeded { .. }
            | Self::Internal { .. }
            | Self::RefundFailed { .. } => true,
            Self::StripeApiError { http_status, .. } => {
                matches!(http_status, Some(500..=599) | None)
            }
            _ => false,
        }
    }

    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConcurrentModification { .. } => true,
            Self::StripeApiError { http_status, .. } => {
                // Rate limit (429) and server errors (5xx) are retryable
                matches!(http_status, Some(429) | Some(500..=599))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BillingError::PlanNotFound {
            plan_id: "starter".to_string(),
        };
        assert_eq!(err.to_string(), "Plan not found: starter");

        let err = BillingError::InsufficientSeats {
            requested: 5,
            available: 2,
        };
        assert_eq!(
            err.to_string(),
            "Cannot remove 5 seats, only 2 extra seats available"
        );
    }

    #[test]
    fn test_error_classification() {
        let err = BillingError::PlanNotFound {
            plan_id: "test".to_string(),
        };
        assert!(err.is_client_error());
        assert!(!err.is_server_error());
        assert!(!err.is_retryable());

        let err = BillingError::ConcurrentModification {
            billable_id: "org_123".to_string(),
        };
        assert!(!err.is_client_error());
        assert!(err.is_server_error());
        assert!(err.is_retryable());
    }

    #[test]
    fn test_convert_to_tideway_error() {
        let err = BillingError::NoSubscription {
            billable_id: "org_123".to_string(),
        };
        let tideway_err: crate::error::TidewayError = err.into();
        assert!(matches!(tideway_err, crate::error::TidewayError::NotFound(_)));

        let err = BillingError::InvalidWebhookSignature;
        let tideway_err: crate::error::TidewayError = err.into();
        assert!(matches!(tideway_err, crate::error::TidewayError::BadRequest(_)));

        let err = BillingError::SubscriptionInactive {
            billable_id: "org_123".to_string(),
        };
        let tideway_err: crate::error::TidewayError = err.into();
        assert!(matches!(tideway_err, crate::error::TidewayError::Forbidden(_)));
    }
}
