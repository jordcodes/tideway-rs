use crate::error::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for storing webhook processing claims to prevent duplicate work.
///
/// Recommended flow for handlers:
/// 1. Call `claim_event(event_id)` before any side effects.
/// 2. If it returns `false`, treat as duplicate and return success (idempotent skip).
/// 3. If processing fails with a retryable/transient error, call `release_claim(event_id)`.
/// 4. If processing succeeds (or permanently failed and should not retry), keep claim recorded.
///
/// Implementations should make `claim_event` atomic when possible.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Atomically claim an event for processing.
    ///
    /// Returns:
    /// - `Ok(true)` if this caller successfully claimed the event
    /// - `Ok(false)` if the event is already claimed/processed elsewhere
    ///
    /// Default implementation falls back to check-then-mark for compatibility.
    async fn claim_event(&self, event_id: &str) -> Result<bool> {
        if self.is_processed(event_id).await? {
            return Ok(false);
        }
        self.mark_processed(event_id.to_string()).await?;
        Ok(true)
    }

    /// Check whether an event is already claimed/processed.
    ///
    /// Primarily useful for diagnostics and compatibility paths.
    /// Prefer `claim_event` for the processing gate.
    async fn is_processed(&self, event_id: &str) -> Result<bool>;

    /// Mark an event as processed
    async fn mark_processed(&self, event_id: String) -> Result<()>;

    /// Release a previously claimed event so it can be retried.
    ///
    /// Default implementation is a no-op.
    async fn release_claim(&self, _event_id: &str) -> Result<()> {
        Ok(())
    }

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
    async fn claim_event(&self, event_id: &str) -> Result<bool> {
        let mut processed = self.processed.write().await;
        Ok(processed.insert(event_id.to_string()))
    }

    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        let processed = self.processed.read().await;
        Ok(processed.contains(event_id))
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        let mut processed = self.processed.write().await;
        processed.insert(event_id);
        Ok(())
    }

    async fn release_claim(&self, event_id: &str) -> Result<()> {
        let mut processed = self.processed.write().await;
        processed.remove(event_id);
        Ok(())
    }
}

/// Database-backed idempotency store (when using SeaORM)
#[cfg(feature = "database")]
pub struct DatabaseIdempotencyStore {
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
    async fn claim_event(&self, event_id: &str) -> Result<bool> {
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{EntityTrait, Set};

        let model = db_entity::ActiveModel {
            event_id: Set(event_id.to_string()),
            processed_at: Set(chrono::Utc::now().into()),
        };

        let result = db_entity::Entity::insert(model)
            .on_conflict(
                OnConflict::column(db_entity::Column::EventId)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&self.db)
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(false),
            Err(e) => Err(crate::error::TidewayError::internal(format!(
                "Failed to claim webhook event for processing: {}",
                e
            ))),
        }
    }

    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        use sea_orm::EntityTrait;

        let model = db_entity::Entity::find_by_id(event_id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| {
                crate::error::TidewayError::internal(format!(
                    "Failed to check webhook idempotency state: {}",
                    e
                ))
            })?;

        Ok(model.is_some())
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{EntityTrait, Set};

        let model = db_entity::ActiveModel {
            event_id: Set(event_id),
            processed_at: Set(chrono::Utc::now().into()),
        };

        let result = db_entity::Entity::insert(model)
            .on_conflict(
                OnConflict::column(db_entity::Column::EventId)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&self.db)
            .await;

        match result {
            Ok(_) => Ok(()),
            // Conflict + DO NOTHING path: already marked as processed.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(e) => Err(crate::error::TidewayError::internal(format!(
                "Failed to mark webhook event as processed: {}",
                e
            ))),
        }?;

        Ok(())
    }

    async fn release_claim(&self, event_id: &str) -> Result<()> {
        use sea_orm::EntityTrait;

        db_entity::Entity::delete_by_id(event_id.to_string())
            .exec(&self.db)
            .await
            .map_err(|e| {
                crate::error::TidewayError::internal(format!(
                    "Failed to release webhook event claim: {}",
                    e
                ))
            })?;

        Ok(())
    }

    async fn cleanup_old_entries(&self) -> Result<()> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        const RETENTION_DAYS: i64 = 30;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(RETENTION_DAYS);

        db_entity::Entity::delete_many()
            .filter(db_entity::Column::ProcessedAt.lt(cutoff))
            .exec(&self.db)
            .await
            .map_err(|e| {
                crate::error::TidewayError::internal(format!(
                    "Failed to cleanup old webhook idempotency entries: {}",
                    e
                ))
            })?;

        Ok(())
    }
}

#[cfg(feature = "database")]
mod db_entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "webhook_processed_events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub event_id: String,
        pub processed_at: DateTimeWithTimeZone,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
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
    async fn test_memory_store_claim_event() {
        let store = MemoryIdempotencyStore::new();

        assert!(store.claim_event("event-claim").await.unwrap());
        assert!(!store.claim_event("event-claim").await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_store_release_claim() {
        let store = MemoryIdempotencyStore::new();

        assert!(store.claim_event("event-release").await.unwrap());
        store.release_claim("event-release").await.unwrap();
        assert!(store.claim_event("event-release").await.unwrap());
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
            "",               // Empty string is valid
            long_id.as_str(), // Long event ID
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
        let always_true = CustomIdempotencyStore {
            always_processed: true,
        };
        let always_false = CustomIdempotencyStore {
            always_processed: false,
        };

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

        store
            .mark_processed("shared-event".to_string())
            .await
            .unwrap();
        assert!(store2.is_processed("shared-event").await.unwrap());
    }

    #[cfg(feature = "database")]
    mod database_tests {
        use super::super::*;
        use sea_orm::{ConnectionTrait, Database, Statement};

        async fn setup_db() -> sea_orm::DatabaseConnection {
            let db = Database::connect("sqlite::memory:")
                .await
                .expect("sqlite in-memory db should connect");

            db.execute(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "CREATE TABLE webhook_processed_events (
                    event_id TEXT PRIMARY KEY NOT NULL,
                    processed_at TEXT NOT NULL
                )"
                .to_string(),
            ))
            .await
            .expect("should create webhook_processed_events table");

            db
        }

        #[tokio::test]
        async fn test_database_store_mark_and_check_processed() {
            let db = setup_db().await;
            let store = DatabaseIdempotencyStore::new(db);

            assert!(!store.is_processed("evt_1").await.unwrap());
            store.mark_processed("evt_1".to_string()).await.unwrap();
            assert!(store.is_processed("evt_1").await.unwrap());
        }

        #[tokio::test]
        async fn test_database_store_mark_is_idempotent() {
            let db = setup_db().await;
            let store = DatabaseIdempotencyStore::new(db);

            store.mark_processed("evt_dup".to_string()).await.unwrap();
            store.mark_processed("evt_dup".to_string()).await.unwrap();

            assert!(store.is_processed("evt_dup").await.unwrap());
        }

        #[tokio::test]
        async fn test_database_store_claim_event_is_atomic() {
            let db = setup_db().await;
            let store = DatabaseIdempotencyStore::new(db);

            assert!(store.claim_event("evt_claim").await.unwrap());
            assert!(!store.claim_event("evt_claim").await.unwrap());
        }

        #[tokio::test]
        async fn test_database_store_release_claim() {
            let db = setup_db().await;
            let store = DatabaseIdempotencyStore::new(db);

            assert!(store.claim_event("evt_release").await.unwrap());
            store.release_claim("evt_release").await.unwrap();
            assert!(store.claim_event("evt_release").await.unwrap());
        }
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
