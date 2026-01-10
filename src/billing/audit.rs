//! Audit logging for billing operations.
//!
//! Provides a trait-based audit logging system for tracking billing events.
//! This is useful for compliance, debugging, and security monitoring.

use std::fmt;

/// Audit event types for billing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingAuditEvent {
    /// Checkout session created.
    CheckoutCreated {
        billable_id: String,
        plan_id: String,
        session_id: String,
    },
    /// Subscription created.
    SubscriptionCreated {
        billable_id: String,
        subscription_id: String,
        plan_id: String,
    },
    /// Subscription updated.
    SubscriptionUpdated {
        billable_id: String,
        subscription_id: String,
        plan_id: String,
        status: String,
    },
    /// Subscription cancelled.
    SubscriptionCancelled {
        billable_id: String,
        subscription_id: String,
        immediate: bool,
    },
    /// Subscription resumed.
    SubscriptionResumed {
        billable_id: String,
        subscription_id: String,
    },
    /// Subscription deleted.
    SubscriptionDeleted {
        billable_id: String,
        subscription_id: String,
    },
    /// Seats added.
    SeatsAdded {
        billable_id: String,
        count: u32,
        new_total: u32,
    },
    /// Seats removed.
    SeatsRemoved {
        billable_id: String,
        count: u32,
        new_total: u32,
    },
    /// Portal session created.
    PortalSessionCreated {
        billable_id: String,
        session_id: String,
    },
    /// Webhook received.
    WebhookReceived {
        event_id: String,
        event_type: String,
    },
    /// Webhook processed.
    WebhookProcessed {
        event_id: String,
        event_type: String,
        outcome: String,
    },
    /// Customer created.
    CustomerCreated {
        billable_id: String,
        customer_id: String,
    },
}

impl fmt::Display for BillingAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckoutCreated { billable_id, plan_id, session_id } => {
                write!(f, "Checkout created: billable={}, plan={}, session={}", billable_id, plan_id, session_id)
            }
            Self::SubscriptionCreated { billable_id, subscription_id, plan_id } => {
                write!(f, "Subscription created: billable={}, sub={}, plan={}", billable_id, subscription_id, plan_id)
            }
            Self::SubscriptionUpdated { billable_id, subscription_id, plan_id, status } => {
                write!(f, "Subscription updated: billable={}, sub={}, plan={}, status={}", billable_id, subscription_id, plan_id, status)
            }
            Self::SubscriptionCancelled { billable_id, subscription_id, immediate } => {
                write!(f, "Subscription cancelled: billable={}, sub={}, immediate={}", billable_id, subscription_id, immediate)
            }
            Self::SubscriptionResumed { billable_id, subscription_id } => {
                write!(f, "Subscription resumed: billable={}, sub={}", billable_id, subscription_id)
            }
            Self::SubscriptionDeleted { billable_id, subscription_id } => {
                write!(f, "Subscription deleted: billable={}, sub={}", billable_id, subscription_id)
            }
            Self::SeatsAdded { billable_id, count, new_total } => {
                write!(f, "Seats added: billable={}, count={}, new_total={}", billable_id, count, new_total)
            }
            Self::SeatsRemoved { billable_id, count, new_total } => {
                write!(f, "Seats removed: billable={}, count={}, new_total={}", billable_id, count, new_total)
            }
            Self::PortalSessionCreated { billable_id, session_id } => {
                write!(f, "Portal session created: billable={}, session={}", billable_id, session_id)
            }
            Self::WebhookReceived { event_id, event_type } => {
                write!(f, "Webhook received: event={}, type={}", event_id, event_type)
            }
            Self::WebhookProcessed { event_id, event_type, outcome } => {
                write!(f, "Webhook processed: event={}, type={}, outcome={}", event_id, event_type, outcome)
            }
            Self::CustomerCreated { billable_id, customer_id } => {
                write!(f, "Customer created: billable={}, customer={}", billable_id, customer_id)
            }
        }
    }
}

/// Trait for audit logging backends.
///
/// Implement this trait to integrate with your logging system (e.g., database,
/// external service, file-based logging).
#[allow(async_fn_in_trait)]
pub trait BillingAuditLogger: Send + Sync {
    /// Log a billing audit event.
    ///
    /// Implementations should handle failures gracefully (e.g., log to stderr)
    /// to avoid disrupting billing operations.
    async fn log(&self, event: BillingAuditEvent);
}

/// No-op audit logger that does nothing.
///
/// Use this when audit logging is not needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpAuditLogger;

impl BillingAuditLogger for NoOpAuditLogger {
    async fn log(&self, _event: BillingAuditEvent) {
        // No-op
    }
}

/// Tracing-based audit logger.
///
/// Logs audit events using the `tracing` crate at INFO level.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingAuditLogger;

impl BillingAuditLogger for TracingAuditLogger {
    async fn log(&self, event: BillingAuditEvent) {
        tracing::info!(
            target: "billing::audit",
            event_type = %event_kind(&event),
            "{}", event
        );
    }
}

/// Get the event kind as a string for structured logging.
fn event_kind(event: &BillingAuditEvent) -> &'static str {
    match event {
        BillingAuditEvent::CheckoutCreated { .. } => "checkout_created",
        BillingAuditEvent::SubscriptionCreated { .. } => "subscription_created",
        BillingAuditEvent::SubscriptionUpdated { .. } => "subscription_updated",
        BillingAuditEvent::SubscriptionCancelled { .. } => "subscription_cancelled",
        BillingAuditEvent::SubscriptionResumed { .. } => "subscription_resumed",
        BillingAuditEvent::SubscriptionDeleted { .. } => "subscription_deleted",
        BillingAuditEvent::SeatsAdded { .. } => "seats_added",
        BillingAuditEvent::SeatsRemoved { .. } => "seats_removed",
        BillingAuditEvent::PortalSessionCreated { .. } => "portal_session_created",
        BillingAuditEvent::WebhookReceived { .. } => "webhook_received",
        BillingAuditEvent::WebhookProcessed { .. } => "webhook_processed",
        BillingAuditEvent::CustomerCreated { .. } => "customer_created",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Test audit logger that captures events.
    #[derive(Default)]
    pub struct TestAuditLogger {
        pub events: Arc<Mutex<Vec<BillingAuditEvent>>>,
    }

    impl TestAuditLogger {
        pub fn new() -> Self {
            Self::default()
        }

        pub async fn events(&self) -> Vec<BillingAuditEvent> {
            self.events.lock().await.clone()
        }
    }

    impl BillingAuditLogger for TestAuditLogger {
        async fn log(&self, event: BillingAuditEvent) {
            self.events.lock().await.push(event);
        }
    }

    #[tokio::test]
    async fn test_noop_logger() {
        let logger = NoOpAuditLogger;
        logger.log(BillingAuditEvent::CheckoutCreated {
            billable_id: "org_123".to_string(),
            plan_id: "starter".to_string(),
            session_id: "cs_123".to_string(),
        }).await;
        // Just verifies it doesn't panic
    }

    #[tokio::test]
    async fn test_test_logger() {
        let logger = TestAuditLogger::new();

        logger.log(BillingAuditEvent::CheckoutCreated {
            billable_id: "org_123".to_string(),
            plan_id: "starter".to_string(),
            session_id: "cs_123".to_string(),
        }).await;

        logger.log(BillingAuditEvent::SubscriptionCreated {
            billable_id: "org_123".to_string(),
            subscription_id: "sub_123".to_string(),
            plan_id: "starter".to_string(),
        }).await;

        let events = logger.events().await;
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], BillingAuditEvent::CheckoutCreated { .. }));
        assert!(matches!(events[1], BillingAuditEvent::SubscriptionCreated { .. }));
    }

    #[test]
    fn test_event_display() {
        let event = BillingAuditEvent::SeatsAdded {
            billable_id: "org_123".to_string(),
            count: 5,
            new_total: 10,
        };
        let display = format!("{}", event);
        assert!(display.contains("org_123"));
        assert!(display.contains("5"));
        assert!(display.contains("10"));
    }

    #[test]
    fn test_event_kind() {
        assert_eq!(event_kind(&BillingAuditEvent::CheckoutCreated {
            billable_id: String::new(),
            plan_id: String::new(),
            session_id: String::new(),
        }), "checkout_created");

        assert_eq!(event_kind(&BillingAuditEvent::WebhookProcessed {
            event_id: String::new(),
            event_type: String::new(),
            outcome: String::new(),
        }), "webhook_processed");
    }
}
