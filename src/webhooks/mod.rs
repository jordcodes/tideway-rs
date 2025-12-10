//! Webhook handling utilities.
//!
//! Provides signature verification, idempotency checking, and event handling
//! for incoming webhooks from external services.

pub mod handler;
pub mod idempotency;
pub mod verification;

pub use handler::{WebhookEvent, WebhookHandler};
pub use idempotency::IdempotencyStore;
pub use verification::WebhookVerifier;
