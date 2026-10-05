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

        // Prevent concurrent duplicate processing in this process. The duplicate must not be
        // acknowledged: if the in-flight attempt later fails, the provider's retry is the only
        // remaining delivery of the event.
        let inserted = {
            let mut in_flight = self.in_flight.lock().map_err(|_| {
                crate::error::TidewayError::internal("Webhook in-flight lock poisoned")
            })?;
            in_flight.insert(event_id.clone())
        };
        if !inserted {
            tracing::debug!(
                event_id = event.event_id(),
                "Rejecting duplicate in-flight webhook event"
            );
            return Err(crate::error::TidewayError::service_unavailable(
                "Webhook event is already being processed; retry shortly",
            ));
        }
        // Removes the event ID on every exit, including when this future is cancelled.
        let _in_flight = InFlightGuard {
            in_flight: Arc::clone(&self.in_flight),
            event_id: event_id.clone(),
        };

        // Atomically claim event processing in the backing store.
        let claim = match idempotency_store.acquire_claim(&event_id).await? {
            crate::webhooks::ClaimOutcome::Acquired(claim) => claim,
            crate::webhooks::ClaimOutcome::AlreadyProcessed => {
                tracing::debug!(
                    event_id = event.event_id(),
                    "Skipping processed webhook event"
                );
                return Ok(());
            }
            crate::webhooks::ClaimOutcome::InProgress { retry_after } => {
                return Err(crate::error::TidewayError::service_unavailable(format!(
                    "Webhook event is already being processed; retry in {} seconds",
                    retry_after.as_secs().max(1)
                )));
            }
        };
        // Validate event
        if let Err(e) = handler.validate(event).await {
            if let Err(release_err) = idempotency_store.release_owned_claim(&claim).await {
                tracing::warn!(
                    event_id = event.event_id(),
                    error = %release_err,
                    "Failed to release webhook claim after validation error"
                );
            }
            return Err(e);
        }

        // Handle event
        match handler.handle(event).await {
            Ok(()) => {
                idempotency_store.complete_claim(&claim).await?;

                tracing::info!(
                    event_id = event.event_id(),
                    event_type = event.event_type(),
                    "Webhook processed successfully"
                );

                Ok(())
            }
            Err(e) => {
                if let Err(release_err) = idempotency_store.release_owned_claim(&claim).await {
                    tracing::warn!(
                        event_id = event.event_id(),
                        error = %release_err,
                        "Failed to release webhook claim after handler error"
                    );
                }
                handler.on_error(event, &e).await;
                Err(e)
            }
        }
    }
}

/// Releases an event ID from the router's in-flight set when dropped.
struct InFlightGuard {
    in_flight: Arc<Mutex<HashSet<String>>>,
    event_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // Recover from poisoning so a panicked handler cannot block future deliveries.
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        in_flight.remove(&self.event_id);
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
    use crate::webhooks::idempotency::{IdempotencyStore, MemoryIdempotencyStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;

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

    /// Signals `started` on every call, then blocks the first call until `release` fires.
    /// The first call fails when `fail_first` is set; the first call never completes when
    /// `hang_first` is set. Later calls succeed immediately.
    struct GatedHandler {
        calls: Arc<AtomicUsize>,
        started: Arc<Notify>,
        release: Arc<Notify>,
        fail_first: bool,
        hang_first: bool,
    }

    impl GatedHandler {
        fn new(calls: &Arc<AtomicUsize>) -> Self {
            Self {
                calls: Arc::clone(calls),
                started: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                fail_first: false,
                hang_first: false,
            }
        }
    }

    #[async_trait]
    impl WebhookHandler<TestEvent> for GatedHandler {
        async fn handle(&self, _event: &TestEvent) -> Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            if call > 0 {
                return Ok(());
            }
            if self.hang_first {
                std::future::pending::<()>().await;
            }
            self.release.notified().await;
            if self.fail_first {
                return Err(crate::error::TidewayError::internal("first attempt failed"));
            }
            Ok(())
        }
    }

    fn test_event(id: &str) -> TestEvent {
        TestEvent {
            id: id.to_string(),
            event_type: "test.event".to_string(),
        }
    }

    #[tokio::test]
    async fn test_concurrent_duplicate_event_processed_once_per_instance() {
        let router = WebhookRouter::new();
        let store = MemoryIdempotencyStore::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = GatedHandler::new(&calls);
        let event = test_event("evt_same");

        let (r1, r2) = tokio::join!(router.process(&event, &handler, &store), async {
            handler.started.notified().await;
            let duplicate = router.process(&event, &handler, &store).await;
            handler.release.notify_one();
            duplicate
        });

        assert!(r1.is_ok());
        // The duplicate must be retryable (503), not acknowledged (200).
        assert!(matches!(
            r2,
            Err(crate::error::TidewayError::ServiceUnavailable(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_duplicate_of_failed_delivery_is_not_lost() {
        let router = WebhookRouter::new();
        let store = MemoryIdempotencyStore::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = GatedHandler {
            fail_first: true,
            ..GatedHandler::new(&calls)
        };
        let event = test_event("evt_fails_first");

        let (first, duplicate) = tokio::join!(router.process(&event, &handler, &store), async {
            handler.started.notified().await;
            let duplicate = router.process(&event, &handler, &store).await;
            handler.release.notify_one();
            duplicate
        });

        assert!(first.is_err());
        assert!(
            duplicate.is_err(),
            "duplicate acknowledged while the first attempt was still running"
        );

        // The provider's retry is processed because nothing acknowledged the event.
        router.process(&event, &handler, &store).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(store.is_processed("evt_fails_first").await.unwrap());
    }

    #[tokio::test]
    async fn test_cancelled_delivery_releases_in_flight_event() {
        let router = WebhookRouter::new();
        // A zero TTL lets the abandoned store claim be reclaimed immediately, isolating the
        // router's in-flight bookkeeping.
        let store = MemoryIdempotencyStore::new().with_claim_ttl(Duration::ZERO);
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = GatedHandler {
            hang_first: true,
            ..GatedHandler::new(&calls)
        };
        let event = test_event("evt_cancelled");

        // Drop the delivery future once the handler is running, as a client disconnect would.
        tokio::select! {
            _ = router.process(&event, &handler, &store) => panic!("handler should not complete"),
            _ = handler.started.notified() => {}
        }

        assert!(router.in_flight.lock().unwrap().is_empty());
        router.process(&event, &handler, &store).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
