use crate::error::Result;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Default time before an abandoned webhook claim may be recovered.
pub const DEFAULT_CLAIM_TTL: Duration = Duration::from_secs(5 * 60);

/// An owned lease for processing one webhook event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventClaim {
    event_id: String,
    token: String,
}

impl EventClaim {
    /// Create a claim with a fresh opaque ownership token.
    ///
    /// Custom stores should persist `token()` in the same atomic operation that acquires or
    /// reclaims the event.
    pub fn new(event_id: impl Into<String>) -> Self {
        Self {
            event_id: event_id.into(),
            token: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// The provider event identifier protected by this claim.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// The opaque ownership token used for conditional completion and release.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Result of attempting to acquire an event-processing lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// This caller owns the claim and may run side effects.
    Acquired(EventClaim),
    /// Another worker owns a fresh claim. The delivery should be retried later.
    InProgress { retry_after: Duration },
    /// Processing previously completed successfully.
    AlreadyProcessed,
}

/// Trait for storing webhook processing claims to prevent duplicate work.
///
/// Recommended flow for handlers:
/// 1. Call `acquire_claim(event_id)` before any side effects.
/// 2. Skip only `AlreadyProcessed`; return a retryable response for `InProgress`.
/// 3. If processing fails, call `release_owned_claim` with the acquired token.
/// 4. If processing succeeds, call `complete_claim` with the acquired token.
///
/// Production implementations should make acquisition, stale reclaim, completion, and release
/// atomic and conditional on the ownership token.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Acquire an owned processing lease.
    ///
    /// The compatibility default cannot distinguish a legacy active claim from a completed
    /// event. Production stores should override this method with atomic, expiring leases.
    async fn acquire_claim(&self, event_id: &str) -> Result<ClaimOutcome> {
        if self.claim_event(event_id).await? {
            Ok(ClaimOutcome::Acquired(EventClaim::new(event_id)))
        } else {
            Ok(ClaimOutcome::AlreadyProcessed)
        }
    }

    /// Complete a claim only when this caller still owns it.
    async fn complete_claim(&self, claim: &EventClaim) -> Result<()> {
        self.mark_processed(claim.event_id().to_string()).await
    }

    /// Release a claim only when this caller still owns it.
    async fn release_owned_claim(&self, claim: &EventClaim) -> Result<()> {
        self.release_claim(claim.event_id()).await
    }

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
    /// Prefer `acquire_claim` for the processing gate.
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
    claims: Arc<RwLock<HashMap<String, MemoryClaim>>>,
    claim_ttl: Duration,
}

#[derive(Clone)]
struct MemoryClaim {
    token: String,
    claimed_at: SystemTime,
}

impl MemoryIdempotencyStore {
    pub fn new() -> Self {
        Self {
            processed: Arc::new(RwLock::new(HashSet::new())),
            claims: Arc::new(RwLock::new(HashMap::new())),
            claim_ttl: DEFAULT_CLAIM_TTL,
        }
    }

    /// Configure abandoned-claim recovery. Keep this longer than normal handler execution.
    pub fn with_claim_ttl(mut self, claim_ttl: Duration) -> Self {
        self.claim_ttl = claim_ttl;
        self
    }
}

impl Default for MemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdempotencyStore for MemoryIdempotencyStore {
    async fn acquire_claim(&self, event_id: &str) -> Result<ClaimOutcome> {
        if self.processed.read().await.contains(event_id) {
            return Ok(ClaimOutcome::AlreadyProcessed);
        }

        let now = SystemTime::now();
        let mut claims = self.claims.write().await;
        // Completion holds this same lock while recording `processed`. Recheck after acquiring it
        // so a delivery that raced with completion cannot create a new claim in between states.
        if self.processed.read().await.contains(event_id) {
            return Ok(ClaimOutcome::AlreadyProcessed);
        }
        if let Some(existing) = claims.get(event_id) {
            let age = now.duration_since(existing.claimed_at).unwrap_or_default();
            if age < self.claim_ttl {
                return Ok(ClaimOutcome::InProgress {
                    retry_after: self.claim_ttl.saturating_sub(age),
                });
            }
        }

        let claim = EventClaim::new(event_id);
        claims.insert(
            event_id.to_string(),
            MemoryClaim {
                token: claim.token().to_string(),
                claimed_at: now,
            },
        );
        Ok(ClaimOutcome::Acquired(claim))
    }

    async fn complete_claim(&self, claim: &EventClaim) -> Result<()> {
        let mut claims = self.claims.write().await;
        let owned = claims
            .get(claim.event_id())
            .is_some_and(|active| active.token == claim.token());
        if !owned {
            return Err(crate::error::TidewayError::internal(
                "Webhook event claim is no longer owned by this worker",
            ));
        }
        self.processed
            .write()
            .await
            .insert(claim.event_id().to_string());
        claims.remove(claim.event_id());
        Ok(())
    }

    async fn release_owned_claim(&self, claim: &EventClaim) -> Result<()> {
        let mut claims = self.claims.write().await;
        if claims
            .get(claim.event_id())
            .is_some_and(|active| active.token == claim.token())
        {
            claims.remove(claim.event_id());
        }
        Ok(())
    }

    async fn claim_event(&self, event_id: &str) -> Result<bool> {
        Ok(matches!(
            self.acquire_claim(event_id).await?,
            ClaimOutcome::Acquired(_)
        ))
    }

    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        let processed = self.processed.read().await;
        Ok(processed.contains(event_id))
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        self.claims.write().await.remove(&event_id);
        let mut processed = self.processed.write().await;
        processed.insert(event_id);
        Ok(())
    }

    async fn release_claim(&self, event_id: &str) -> Result<()> {
        self.claims.write().await.remove(event_id);
        Ok(())
    }
}

/// Database-backed idempotency store (when using SeaORM)
#[cfg(feature = "database")]
pub struct DatabaseIdempotencyStore {
    db: sea_orm::DatabaseConnection,
    claim_ttl: Duration,
}

#[cfg(feature = "database")]
impl DatabaseIdempotencyStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self {
            db,
            claim_ttl: DEFAULT_CLAIM_TTL,
        }
    }

    /// Configure abandoned-claim recovery. Keep this longer than normal handler execution.
    pub fn with_claim_ttl(mut self, claim_ttl: Duration) -> Self {
        self.claim_ttl = claim_ttl;
        self
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl IdempotencyStore for DatabaseIdempotencyStore {
    async fn acquire_claim(&self, event_id: &str) -> Result<ClaimOutcome> {
        use sea_orm::sea_query::{Expr, OnConflict};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

        let claim = EventClaim::new(event_id);
        let now = chrono::Utc::now().fixed_offset();
        let model = db_entity::ActiveModel {
            event_id: Set(event_id.to_string()),
            status: Set("processing".to_string()),
            claim_token: Set(Some(claim.token().to_string())),
            claimed_at: Set(Some(now)),
            // Kept non-null for compatibility with the original table shape. It is replaced
            // with the actual completion time when the claim completes.
            processed_at: Set(now),
        };

        let inserted = db_entity::Entity::insert(model)
            .on_conflict(
                OnConflict::column(db_entity::Column::EventId)
                    .do_nothing()
                    .to_owned(),
            )
            .do_nothing()
            .exec(&self.db)
            .await;

        match inserted {
            Ok(sea_orm::TryInsertResult::Inserted(_)) => {
                return Ok(ClaimOutcome::Acquired(claim));
            }
            Ok(sea_orm::TryInsertResult::Conflicted) | Err(sea_orm::DbErr::RecordNotInserted) => {}
            Ok(sea_orm::TryInsertResult::Empty) => {
                return Err(crate::error::TidewayError::internal(
                    "Webhook claim insert unexpectedly produced no result",
                ));
            }
            Err(error) => {
                return Err(crate::error::TidewayError::Database(error.to_string()));
            }
        }

        let ttl = chrono::Duration::from_std(self.claim_ttl).map_err(|_| {
            crate::error::TidewayError::internal("Webhook event claim TTL is too large")
        })?;
        let cutoff = now - ttl;
        let reclaimed = db_entity::Entity::update_many()
            .col_expr(
                db_entity::Column::ClaimToken,
                Expr::value(Some(claim.token().to_string())),
            )
            .col_expr(db_entity::Column::ClaimedAt, Expr::value(Some(now)))
            .filter(db_entity::Column::EventId.eq(event_id))
            .filter(db_entity::Column::Status.eq("processing"))
            .filter(db_entity::Column::ClaimedAt.lte(cutoff))
            .exec(&self.db)
            .await
            .map_err(|error| crate::error::TidewayError::Database(error.to_string()))?;

        if reclaimed.rows_affected == 1 {
            return Ok(ClaimOutcome::Acquired(claim));
        }

        let current = db_entity::Entity::find_by_id(event_id.to_string())
            .one(&self.db)
            .await
            .map_err(|error| crate::error::TidewayError::Database(error.to_string()))?
            .ok_or_else(|| crate::error::TidewayError::internal("Webhook claim disappeared"))?;

        if current.status == "processed" {
            return Ok(ClaimOutcome::AlreadyProcessed);
        }

        let age = current
            .claimed_at
            .and_then(|claimed_at| (now - claimed_at).to_std().ok())
            .unwrap_or_default();
        Ok(ClaimOutcome::InProgress {
            retry_after: self.claim_ttl.saturating_sub(age),
        })
    }

    async fn complete_claim(&self, claim: &EventClaim) -> Result<()> {
        use sea_orm::sea_query::Expr;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let result = db_entity::Entity::update_many()
            .col_expr(db_entity::Column::Status, Expr::value("processed"))
            .col_expr(
                db_entity::Column::ClaimToken,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                db_entity::Column::ProcessedAt,
                Expr::value(chrono::Utc::now().fixed_offset()),
            )
            .filter(db_entity::Column::EventId.eq(claim.event_id()))
            .filter(db_entity::Column::Status.eq("processing"))
            .filter(db_entity::Column::ClaimToken.eq(claim.token()))
            .exec(&self.db)
            .await
            .map_err(|error| crate::error::TidewayError::Database(error.to_string()))?;

        if result.rows_affected != 1 {
            return Err(crate::error::TidewayError::internal(
                "Webhook event claim is no longer owned by this worker",
            ));
        }
        Ok(())
    }

    async fn release_owned_claim(&self, claim: &EventClaim) -> Result<()> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        db_entity::Entity::delete_many()
            .filter(db_entity::Column::EventId.eq(claim.event_id()))
            .filter(db_entity::Column::Status.eq("processing"))
            .filter(db_entity::Column::ClaimToken.eq(claim.token()))
            .exec(&self.db)
            .await
            .map_err(|error| crate::error::TidewayError::Database(error.to_string()))?;
        Ok(())
    }

    async fn claim_event(&self, event_id: &str) -> Result<bool> {
        Ok(matches!(
            self.acquire_claim(event_id).await?,
            ClaimOutcome::Acquired(_)
        ))
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

        Ok(model.is_some_and(|event| event.status == "processed"))
    }

    async fn mark_processed(&self, event_id: String) -> Result<()> {
        use sea_orm::sea_query::{Expr, OnConflict};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

        let now = chrono::Utc::now().fixed_offset();
        let updated = db_entity::Entity::update_many()
            .col_expr(db_entity::Column::Status, Expr::value("processed"))
            .col_expr(
                db_entity::Column::ClaimToken,
                Expr::value(Option::<String>::None),
            )
            .col_expr(db_entity::Column::ProcessedAt, Expr::value(now))
            .filter(db_entity::Column::EventId.eq(&event_id))
            .filter(db_entity::Column::Status.eq("processing"))
            .exec(&self.db)
            .await
            .map_err(|error| crate::error::TidewayError::Database(error.to_string()))?;
        if updated.rows_affected == 1 {
            return Ok(());
        }

        let model = db_entity::ActiveModel {
            event_id: Set(event_id),
            status: Set("processed".to_string()),
            claim_token: Set(None),
            claimed_at: Set(None),
            processed_at: Set(now),
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
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        db_entity::Entity::delete_many()
            .filter(db_entity::Column::EventId.eq(event_id))
            .filter(db_entity::Column::Status.eq("processing"))
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
            .filter(db_entity::Column::Status.eq("processed"))
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
        pub status: String,
        pub claim_token: Option<String>,
        pub claimed_at: Option<DateTimeWithTimeZone>,
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
    async fn memory_claim_lifecycle_is_owned_and_completed_explicitly() {
        let store = MemoryIdempotencyStore::new();
        let claim = match store.acquire_claim("event-owned").await.unwrap() {
            ClaimOutcome::Acquired(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        assert!(!store.is_processed("event-owned").await.unwrap());
        assert!(matches!(
            store.acquire_claim("event-owned").await.unwrap(),
            ClaimOutcome::InProgress { .. }
        ));
        store.complete_claim(&claim).await.unwrap();
        assert!(store.is_processed("event-owned").await.unwrap());
        assert!(matches!(
            store.acquire_claim("event-owned").await.unwrap(),
            ClaimOutcome::AlreadyProcessed
        ));
    }

    #[tokio::test]
    async fn expired_worker_cannot_release_or_complete_newer_claim() {
        let store = MemoryIdempotencyStore::new().with_claim_ttl(Duration::ZERO);
        let old = match store.acquire_claim("event-reclaimed").await.unwrap() {
            ClaimOutcome::Acquired(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        let current = match store.acquire_claim("event-reclaimed").await.unwrap() {
            ClaimOutcome::Acquired(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };

        store.release_owned_claim(&old).await.unwrap();
        assert!(store.complete_claim(&old).await.is_err());
        store.complete_claim(&current).await.unwrap();
        assert!(store.is_processed("event-reclaimed").await.unwrap());
    }

    #[tokio::test]
    async fn completion_race_never_reopens_a_processed_event() {
        for index in 0..256 {
            let store = Arc::new(MemoryIdempotencyStore::new());
            let event_id = format!("event-completion-race-{index}");
            let claim = match store.acquire_claim(&event_id).await.unwrap() {
                ClaimOutcome::Acquired(claim) => claim,
                outcome => panic!("unexpected initial claim outcome: {outcome:?}"),
            };

            let completing_store = Arc::clone(&store);
            let acquiring_store = Arc::clone(&store);
            let event_id_for_acquire = event_id.clone();
            let (completed, raced) = tokio::join!(
                async move { completing_store.complete_claim(&claim).await },
                async move { acquiring_store.acquire_claim(&event_id_for_acquire).await }
            );

            completed.unwrap();
            assert!(matches!(
                raced.unwrap(),
                ClaimOutcome::InProgress { .. } | ClaimOutcome::AlreadyProcessed
            ));
            assert!(store.is_processed(&event_id).await.unwrap());
        }
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
                    status TEXT NOT NULL DEFAULT 'processed',
                    claim_token TEXT NULL,
                    claimed_at TEXT NULL,
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
