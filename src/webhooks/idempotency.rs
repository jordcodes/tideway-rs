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

#[cfg(test)]
mod tests {
    use super::*;

    // ============ MemoryIdempotencyStore tests ============

    #[test]
    fn test_memory_store_new() {
        let store = MemoryIdempotencyStore::new();
        // Just verify it can be created
        assert!(std::mem::size_of_val(&store) > 0);
    }

    #[test]
    fn test_memory_store_default() {
        let store = MemoryIdempotencyStore::default();
        assert!(std::mem::size_of_val(&store) > 0);
    }

    #[tokio::test]
    async fn test_memory_store_is_processed_new_event() {
        let store = MemoryIdempotencyStore::new();

        // New event should not be processed
        let result = store.is_processed("event-123").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_memory_store_mark_processed() {
        let store = MemoryIdempotencyStore::new();

        // Mark event as processed
        let result = store.mark_processed("event-456".to_string()).await;
        assert!(result.is_ok());

        // Now it should be marked as processed
        let is_processed = store.is_processed("event-456").await.unwrap();
        assert!(is_processed);
    }

    #[tokio::test]
    async fn test_memory_store_multiple_events() {
        let store = MemoryIdempotencyStore::new();

        // Mark multiple events
        store.mark_processed("event-1".to_string()).await.unwrap();
        store.mark_processed("event-2".to_string()).await.unwrap();
        store.mark_processed("event-3".to_string()).await.unwrap();

        // All should be processed
        assert!(store.is_processed("event-1").await.unwrap());
        assert!(store.is_processed("event-2").await.unwrap());
        assert!(store.is_processed("event-3").await.unwrap());

        // Unprocessed event should return false
        assert!(!store.is_processed("event-4").await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_store_idempotent_mark() {
        let store = MemoryIdempotencyStore::new();

        // Mark same event multiple times
        store.mark_processed("event-xyz".to_string()).await.unwrap();
        store.mark_processed("event-xyz".to_string()).await.unwrap();
        store.mark_processed("event-xyz".to_string()).await.unwrap();

        // Should still be processed
        assert!(store.is_processed("event-xyz").await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_store_cleanup_noop() {
        let store = MemoryIdempotencyStore::new();

        // Cleanup should succeed (default no-op implementation)
        let result = store.cleanup_old_entries().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_memory_store_concurrent_access() {
        use std::sync::Arc;

        let store = Arc::new(MemoryIdempotencyStore::new());

        // Spawn multiple tasks that access the store concurrently
        let mut handles = vec![];

        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = tokio::spawn(async move {
                let event_id = format!("concurrent-event-{}", i);
                store_clone.mark_processed(event_id.clone()).await.unwrap();
                store_clone.is_processed(&event_id).await.unwrap()
            });
            handles.push(handle);
        }

        // All should complete successfully
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result);
        }
    }

    #[tokio::test]
    async fn test_memory_store_different_event_ids() {
        let store = MemoryIdempotencyStore::new();
        let long_id = "a".repeat(1000);

        let event_ids = [
            "evt_1234567890",
            "webhook_abc_def",
            "stripe:pi_xyz",
            "123",
            "event-with-special-chars-!@#$%",
            "",  // Empty string is valid
            long_id.as_str(),  // Long event ID
        ];

        for event_id in event_ids {
            assert!(!store.is_processed(event_id).await.unwrap());
            store.mark_processed(event_id.to_string()).await.unwrap();
            assert!(store.is_processed(event_id).await.unwrap());
        }
    }

    // ============ IdempotencyStore trait tests ============

    struct CustomIdempotencyStore {
        always_processed: bool,
    }

    #[async_trait]
    impl IdempotencyStore for CustomIdempotencyStore {
        async fn is_processed(&self, _event_id: &str) -> Result<bool> {
            Ok(self.always_processed)
        }

        async fn mark_processed(&self, _event_id: String) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_custom_store_trait_impl() {
        let always_true = CustomIdempotencyStore { always_processed: true };
        let always_false = CustomIdempotencyStore { always_processed: false };

        assert!(always_true.is_processed("any").await.unwrap());
        assert!(!always_false.is_processed("any").await.unwrap());
    }

    #[tokio::test]
    async fn test_store_as_dyn_trait() {
        let store: Box<dyn IdempotencyStore> = Box::new(MemoryIdempotencyStore::new());

        assert!(!store.is_processed("test").await.unwrap());
        store.mark_processed("test".to_string()).await.unwrap();
        assert!(store.is_processed("test").await.unwrap());
    }

    #[tokio::test]
    async fn test_store_in_arc() {
        let store: Arc<dyn IdempotencyStore> = Arc::new(MemoryIdempotencyStore::new());

        // Clone arc and use from multiple "tasks"
        let store2 = Arc::clone(&store);

        store.mark_processed("shared-event".to_string()).await.unwrap();
        assert!(store2.is_processed("shared-event").await.unwrap());
    }

    // ============ Default cleanup behavior test ============

    struct StoreWithoutCleanup;

    #[async_trait]
    impl IdempotencyStore for StoreWithoutCleanup {
        async fn is_processed(&self, _event_id: &str) -> Result<bool> {
            Ok(false)
        }

        async fn mark_processed(&self, _event_id: String) -> Result<()> {
            Ok(())
        }
        // cleanup_old_entries uses default implementation
    }

    #[tokio::test]
    async fn test_default_cleanup_implementation() {
        let store = StoreWithoutCleanup;

        // Default cleanup should be a no-op that succeeds
        let result = store.cleanup_old_entries().await;
        assert!(result.is_ok());
    }
}
