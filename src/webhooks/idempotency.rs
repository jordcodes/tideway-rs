use crate::error::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for storing processed webhook event IDs to prevent duplicate processing
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Check if an event has already been processed
    async fn is_processed(&self, event_id: &str) -> Result<bool>;

    /// Mark an event as processed
    async fn mark_processed(&self, event_id: String) -> Result<()>;

    /// Clean up old entries (optional)
    async fn cleanup_old_entries(&self) -> Result<()> {
        Ok(())
    }
}

/// In-memory idempotency store (for development/testing)
///
/// In production, use a database-backed store or Redis
pub struct MemoryIdempotencyStore {
    processed: Arc<RwLock<HashSet<String>>>,
}

impl MemoryIdempotencyStore {
    pub fn new() -> Self {
        Self {
            processed: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

impl Default for MemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdempotencyStore for MemoryIdempotencyStore {
    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        let processed = self.processed.read().await;
        Ok(processed.contains(event_id))
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        let mut processed = self.processed.write().await;
        processed.insert(event_id);
        Ok(())
    }
}

/// Database-backed idempotency store (when using SeaORM)
#[cfg(feature = "database")]
pub struct DatabaseIdempotencyStore {
    #[allow(dead_code)]
    db: sea_orm::DatabaseConnection,
}

#[cfg(feature = "database")]
impl DatabaseIdempotencyStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl IdempotencyStore for DatabaseIdempotencyStore {
    async fn is_processed(&self, _event_id: &str) -> Result<bool> {
        // In a real implementation, query the webhook_events table
        // For now, this is a placeholder
        Ok(false)
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        // In a real implementation, insert into webhook_events table
        // For now, this is a placeholder
        tracing::debug!("Marking event {} as processed", event_id);
        Ok(())
    }

    async fn cleanup_old_entries(&self) -> Result<()> {
        // Delete events older than X days
        tracing::debug!("Cleaning up old webhook events");
        Ok(())
    }
}
