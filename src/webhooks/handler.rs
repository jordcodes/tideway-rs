use crate::error::Result;
use async_trait::async_trait;
use serde::de::DeserializeOwned;

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
    // In a real implementation, this would store a map of event types to handlers
    // For now, keeping it simple
}

impl WebhookRouter {
    pub fn new() -> Self {
        Self {}
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
        // Check if already processed
        if idempotency_store.is_processed(event.event_id()).await? {
            tracing::debug!(
                event_id = event.event_id(),
                "Skipping already processed event"
            );
            return Ok(());
        }

        // Validate event
        handler.validate(event).await?;

        // Handle event
        match handler.handle(event).await {
            Ok(()) => {
                // Mark as processed
                idempotency_store
                    .mark_processed(event.event_id().to_string())
                    .await?;

                tracing::info!(
                    event_id = event.event_id(),
                    event_type = event.event_type(),
                    "Webhook processed successfully"
                );

                Ok(())
            }
            Err(e) => {
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
