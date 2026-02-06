use crate::error::Result;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Trait representing a webhook event
pub trait WebhookEvent: DeserializeOwned + Send + Sync {
    /// Get the unique event ID for idempotency checking
    fn event_id(&self) -> &str;

    /// Get the event type/name
    fn event_type(&self) -> &str;
}

/// Trait for handling webhook events
///
/// Implement this for each type of webhook event you want to handle.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::webhooks::{WebhookEvent, WebhookHandler};
///
/// #[derive(Deserialize)]
/// struct UserCreatedEvent {
///     id: String,
///     event_type: String,
///     data: UserData,
/// }
///
/// impl WebhookEvent for UserCreatedEvent {
///     fn event_id(&self) -> &str {
///         &self.id
///     }
///
///     fn event_type(&self) -> &str {
///         &self.event_type
///     }
/// }
///
/// struct UserCreatedHandler {
///     db: DatabaseConnection,
/// }
///
/// #[async_trait]
/// impl WebhookHandler<UserCreatedEvent> for UserCreatedHandler {
///     async fn handle(&self, event: &UserCreatedEvent) -> Result<()> {
///         // Create user in database
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait WebhookHandler<E: WebhookEvent>: Send + Sync {
    /// Handle the webhook event
    async fn handle(&self, event: &E) -> Result<()>;

    /// Optional: Validate the event before handling
    async fn validate(&self, _event: &E) -> Result<()> {
        Ok(())
    }

    /// Optional: Handle errors that occur during processing
    async fn on_error(&self, event: &E, error: &crate::error::TidewayError) {
        tracing::error!(
            event_id = event.event_id(),
            event_type = event.event_type(),
            error = %error,
            "Webhook processing failed"
        );
    }
}

/// Webhook router that dispatches events to appropriate handlers
pub struct WebhookRouter {
    // Process-local in-flight dedupe to prevent concurrent double-processing
    // of the same event ID within a single service instance.
    in_flight: Arc<Mutex<HashSet<String>>>,
}

impl WebhookRouter {
    pub fn new() -> Self {
        Self {
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Process a webhook event with the given handler
    pub async fn process<E, H>(
        &self,
        event: &E,
        handler: &H,
        idempotency_store: &dyn crate::webhooks::IdempotencyStore,
    ) -> Result<()>
    where
        E: WebhookEvent,
        H: WebhookHandler<E>,
    {
        let event_id = event.event_id().to_string();

        // Prevent concurrent duplicate processing in this process.
        let inserted = {
            let mut in_flight = self
                .in_flight
                .lock()
                .map_err(|_| crate::error::TidewayError::internal("Webhook in-flight lock poisoned"))?;
            in_flight.insert(event_id.clone())
        };
        if !inserted {
            tracing::debug!(
                event_id = event.event_id(),
                "Skipping duplicate in-flight webhook event"
            );
            return Ok(());
        }

        // Atomically claim event processing in the backing store.
        let claimed = idempotency_store.claim_event(&event_id).await?;
        if !claimed {
            if let Ok(mut in_flight) = self.in_flight.lock() {
                in_flight.remove(&event_id);
            }
            tracing::debug!(
                event_id = event.event_id(),
                "Skipping already processed/claimed event"
            );
            return Ok(());
        }

        // Validate event
        if let Err(e) = handler.validate(event).await {
            if let Err(release_err) = idempotency_store.release_claim(&event_id).await {
                tracing::warn!(
                    event_id = event.event_id(),
                    error = %release_err,
                    "Failed to release webhook claim after validation error"
                );
            }
            if let Ok(mut in_flight) = self.in_flight.lock() {
                in_flight.remove(&event_id);
            }
            return Err(e);
        }

        // Handle event
        match handler.handle(event).await {
            Ok(()) => {
                if let Ok(mut in_flight) = self.in_flight.lock() {
                    in_flight.remove(&event_id);
                }

                tracing::info!(
                    event_id = event.event_id(),
                    event_type = event.event_type(),
                    "Webhook processed successfully"
                );

                Ok(())
            }
            Err(e) => {
                if let Err(release_err) = idempotency_store.release_claim(&event_id).await {
                    tracing::warn!(
                        event_id = event.event_id(),
                        error = %release_err,
                        "Failed to release webhook claim after handler error"
                    );
                }
                if let Ok(mut in_flight) = self.in_flight.lock() {
                    in_flight.remove(&event_id);
                }
                handler.on_error(event, &e).await;
                Err(e)
            }
        }
    }
}

impl Default for WebhookRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::idempotency::MemoryIdempotencyStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(serde::Deserialize)]
    struct TestEvent {
        id: String,
        event_type: String,
    }

    impl WebhookEvent for TestEvent {
        fn event_id(&self) -> &str {
            &self.id
        }

        fn event_type(&self) -> &str {
            &self.event_type
        }
    }

    struct CountingHandler {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl WebhookHandler<TestEvent> for CountingHandler {
        async fn handle(&self, _event: &TestEvent) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_concurrent_duplicate_event_processed_once_per_instance() {
        let router = WebhookRouter::new();
        let store = MemoryIdempotencyStore::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = CountingHandler {
            calls: Arc::clone(&calls),
        };
        let event = TestEvent {
            id: "evt_same".to_string(),
            event_type: "test.event".to_string(),
        };

        let (r1, r2) = tokio::join!(
            router.process(&event, &handler, &store),
            router.process(&event, &handler, &store)
        );

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
