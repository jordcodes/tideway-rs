//! SeaORM-backed credit ledger.

use async_trait::async_trait;
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{Alias, Expr, JoinType, Query, UnionType};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};

use crate::{Result, TidewayError};

use super::{
    ConsumptionOrder, CreditAllocation, CreditBalance, CreditBucket, CreditHistoryQuery,
    CreditReservation, CreditRevocation, CreditSource, CreditStore, CreditTransaction,
    CreditTransactionKind, GrantCredits, ReservationStatus, ReserveCredits, RevokeCredits,
    SourceBalance,
};

mod entity {
    use sea_orm::entity::prelude::*;

    pub mod bucket {
        use super::*;

        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "credit_buckets")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub account_id: String,
            pub credit_type: String,
            pub source: String,
            pub original_amount: i64,
            pub remaining_amount: i64,
            pub expires_at: Option<i64>,
            pub idempotency_key: String,
            #[sea_orm(column_type = "JsonBinary")]
            pub metadata: serde_json::Value,
            pub created_at: i64,
            /// Cumulative credits revoked from the grant.
            pub revoked_amount: i64,
            /// Revoked credits still held by reservations or already spent.
            pub pending_revocation: i64,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod reservation {
        use super::*;

        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "credit_reservations")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub account_id: String,
            pub credit_type: String,
            pub amount: i64,
            pub status: String,
            pub idempotency_key: String,
            pub consumption_order: String,
            pub expires_at: i64,
            pub created_at: i64,
            pub updated_at: i64,
            #[sea_orm(column_type = "JsonBinary")]
            pub metadata: serde_json::Value,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod allocation {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "credit_reservation_allocations")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub reservation_id: String,
            #[sea_orm(primary_key, auto_increment = false)]
            pub bucket_id: String,
            pub amount: i64,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod transaction {
        use super::*;

        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "credit_transactions")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub account_id: String,
            pub credit_type: String,
            pub kind: String,
            pub amount: i64,
            pub bucket_id: Option<String>,
            pub reservation_id: Option<String>,
            pub idempotency_key: String,
            pub created_at: i64,
            #[sea_orm(column_type = "JsonBinary")]
            pub metadata: serde_json::Value,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
}

use entity::{allocation, bucket, reservation, transaction};

/// Production credit ledger backed by SeaORM.
#[derive(Clone, Debug)]
pub struct SeaOrmCreditStore {
    db: DatabaseConnection,
}

impl SeaOrmCreditStore {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    #[must_use]
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    async fn existing_grant(&self, request: &GrantCredits) -> Result<Option<CreditBucket>> {
        let model = bucket::Entity::find()
            .filter(bucket::Column::AccountId.eq(&request.account_id))
            .filter(bucket::Column::CreditType.eq(&request.credit_type))
            .filter(bucket::Column::IdempotencyKey.eq(&request.idempotency_key))
            .one(&self.db)
            .await
            .map_err(db_error)?;
        model.map(model_to_bucket).transpose()
    }

    async fn existing_reservation(
        &self,
        request: &ReserveCredits,
    ) -> Result<Option<CreditReservation>> {
        let model = reservation::Entity::find()
            .filter(reservation::Column::AccountId.eq(&request.account_id))
            .filter(reservation::Column::CreditType.eq(&request.credit_type))
            .filter(reservation::Column::IdempotencyKey.eq(&request.idempotency_key))
            .one(&self.db)
            .await
            .map_err(db_error)?;
        match model {
            Some(model) => Ok(Some(load_reservation(&self.db, model).await?)),
            None => Ok(None),
        }
    }

    async fn release_expired_for(
        &self,
        account_id: &str,
        credit_type: &str,
        now: i64,
    ) -> Result<()> {
        const BATCH_SIZE: u64 = 1_000;
        let expired = reservation::Entity::find()
            .filter(reservation::Column::AccountId.eq(account_id))
            .filter(reservation::Column::CreditType.eq(credit_type))
            .filter(reservation::Column::Status.eq("reserved"))
            .filter(reservation::Column::ExpiresAt.lte(now))
            .order_by_asc(reservation::Column::ExpiresAt)
            .limit(BATCH_SIZE)
            .all(&self.db)
            .await
            .map_err(db_error)?;
        for model in expired {
            match release_reservation(&self.db, &model.account_id, &model.id, now, "expired").await
            {
                Ok(_) | Err(TidewayError::Conflict(_)) | Err(TidewayError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CreditStore for SeaOrmCreditStore {
    async fn grant(&self, request: &GrantCredits, now: i64) -> Result<CreditBucket> {
        if let Some(existing) = self.existing_grant(request).await? {
            ensure_matching_grant(&existing, request)?;
            return Ok(existing);
        }
        if request.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(TidewayError::bad_request(
                "Credit grant expiry must be in the future",
            ));
        }

        let bucket = CreditBucket {
            id: uuid::Uuid::new_v4().to_string(),
            account_id: request.account_id.clone(),
            credit_type: request.credit_type.clone(),
            source: request.source,
            original_amount: request.amount,
            remaining_amount: request.amount,
            expires_at: request.expires_at,
            idempotency_key: request.idempotency_key.clone(),
            created_at: now,
        };
        let txn = self.db.begin().await.map_err(db_error)?;
        let insert_result =
            bucket::Entity::insert(bucket_active_model(&bucket, &request.metadata)?)
                .exec(&txn)
                .await;
        if let Err(error) = insert_result {
            txn.rollback().await.map_err(db_error)?;
            if let Some(existing) = self.existing_grant(request).await? {
                ensure_matching_grant(&existing, request)?;
                return Ok(existing);
            }
            return Err(db_error(error));
        }
        transaction::Entity::insert(transaction_active_model(CreditTransaction {
            id: uuid::Uuid::new_v4().to_string(),
            account_id: request.account_id.clone(),
            credit_type: request.credit_type.clone(),
            kind: CreditTransactionKind::Grant,
            amount: request.amount,
            bucket_id: Some(bucket.id.clone()),
            reservation_id: None,
            idempotency_key: request.idempotency_key.clone(),
            created_at: now,
            metadata: request.metadata.clone(),
        })?)
        .exec(&txn)
        .await
        .map_err(db_error)?;
        txn.commit().await.map_err(db_error)?;
        Ok(bucket)
    }

    async fn reserve(
        &self,
        request: &ReserveCredits,
        reservation_expires_at: i64,
        now: i64,
    ) -> Result<CreditReservation> {
        self.release_expired_for(&request.account_id, &request.credit_type, now)
            .await?;
        if let Some(existing) = self.existing_reservation(request).await? {
            ensure_matching_reservation(&existing, request)?;
            return Ok(existing);
        }

        let txn = self.db.begin().await.map_err(db_error)?;
        let mut candidates = bucket::Entity::find()
            .filter(bucket::Column::AccountId.eq(&request.account_id))
            .filter(bucket::Column::CreditType.eq(&request.credit_type))
            .filter(bucket::Column::RemainingAmount.gt(0))
            .filter(
                sea_orm::Condition::any()
                    .add(bucket::Column::ExpiresAt.is_null())
                    .add(bucket::Column::ExpiresAt.gt(now)),
            )
            .all(&txn)
            .await
            .map_err(db_error)?;
        candidates.sort_by(|left, right| compare_bucket_models(left, right, request.order));
        let available = candidates.iter().try_fold(0u64, |total, model| {
            total
                .checked_add(to_u64(model.remaining_amount)?)
                .ok_or_else(|| TidewayError::internal("Credit balance overflow"))
        })?;
        if available < request.amount {
            txn.rollback().await.map_err(db_error)?;
            if let Some(existing) = self.existing_reservation(request).await? {
                ensure_matching_reservation(&existing, request)?;
                return Ok(existing);
            }
            return Err(insufficient(request, available));
        }

        let reservation_id = uuid::Uuid::new_v4().to_string();
        let mut needed = request.amount;
        let mut allocations = Vec::new();
        for candidate in candidates {
            if needed == 0 {
                break;
            }
            let amount = to_u64(candidate.remaining_amount)?.min(needed);
            let updated = bucket::Entity::update_many()
                .col_expr(
                    bucket::Column::RemainingAmount,
                    Expr::col(bucket::Column::RemainingAmount).sub(to_i64(amount)?),
                )
                .filter(bucket::Column::Id.eq(&candidate.id))
                .filter(bucket::Column::RemainingAmount.gte(to_i64(amount)?))
                .exec(&txn)
                .await
                .map_err(db_error)?;
            if updated.rows_affected != 1 {
                txn.rollback().await.map_err(db_error)?;
                if let Some(existing) = self.existing_reservation(request).await? {
                    ensure_matching_reservation(&existing, request)?;
                    return Ok(existing);
                }
                return Err(TidewayError::conflict(
                    "Credit balance changed concurrently; retry with the same idempotency key",
                ));
            }
            allocations.push(CreditAllocation {
                bucket_id: candidate.id,
                amount,
            });
            needed -= amount;
        }

        let reservation = CreditReservation {
            id: reservation_id.clone(),
            account_id: request.account_id.clone(),
            credit_type: request.credit_type.clone(),
            amount: request.amount,
            status: ReservationStatus::Reserved,
            idempotency_key: request.idempotency_key.clone(),
            order: request.order,
            allocations: allocations.clone(),
            expires_at: reservation_expires_at,
            created_at: now,
            updated_at: now,
            metadata: request.metadata.clone(),
        };
        let inserted =
            reservation::Entity::insert(reservation_active_model(&reservation, request.order)?)
                .exec(&txn)
                .await;
        if let Err(error) = inserted {
            txn.rollback().await.map_err(db_error)?;
            if let Some(existing) = self.existing_reservation(request).await? {
                ensure_matching_reservation(&existing, request)?;
                return Ok(existing);
            }
            return Err(db_error(error));
        }
        for item in &allocations {
            allocation::Entity::insert(allocation::ActiveModel {
                reservation_id: Set(reservation_id.clone()),
                bucket_id: Set(item.bucket_id.clone()),
                amount: Set(to_i64(item.amount)?),
            })
            .exec(&txn)
            .await
            .map_err(db_error)?;
            transaction::Entity::insert(transaction_active_model(CreditTransaction {
                id: uuid::Uuid::new_v4().to_string(),
                account_id: request.account_id.clone(),
                credit_type: request.credit_type.clone(),
                kind: CreditTransactionKind::Reserve,
                amount: item.amount,
                bucket_id: Some(item.bucket_id.clone()),
                reservation_id: Some(reservation_id.clone()),
                idempotency_key: request.idempotency_key.clone(),
                created_at: now,
                metadata: request.metadata.clone(),
            })?)
            .exec(&txn)
            .await
            .map_err(db_error)?;
        }
        txn.commit().await.map_err(db_error)?;
        Ok(reservation)
    }

    async fn commit(
        &self,
        account_id: &str,
        reservation_id: &str,
        now: i64,
    ) -> Result<CreditReservation> {
        let txn = self.db.begin().await.map_err(db_error)?;
        let Some(model) = find_owned_reservation(&txn, account_id, reservation_id).await? else {
            txn.rollback().await.map_err(db_error)?;
            return Err(TidewayError::not_found("Credit reservation not found"));
        };
        let status = parse_status(&model.status)?;
        if status == ReservationStatus::Reserved && model.expires_at <= now {
            txn.rollback().await.map_err(db_error)?;
            release_reservation(&self.db, account_id, reservation_id, now, "expired").await?;
            return Err(TidewayError::conflict(
                "Expired credit reservation cannot be committed",
            ));
        }
        match status {
            ReservationStatus::Committed => {
                let result = load_reservation(&txn, model).await?;
                txn.commit().await.map_err(db_error)?;
                return Ok(result);
            }
            ReservationStatus::Released => {
                txn.rollback().await.map_err(db_error)?;
                return Err(TidewayError::conflict(
                    "Released credit reservation cannot be committed",
                ));
            }
            ReservationStatus::Reserved => {}
        }
        let updated = reservation::Entity::update_many()
            .col_expr(reservation::Column::Status, Expr::value("committed"))
            .col_expr(reservation::Column::UpdatedAt, Expr::value(now))
            .filter(reservation::Column::Id.eq(reservation_id))
            .filter(reservation::Column::AccountId.eq(account_id))
            .filter(reservation::Column::Status.eq("reserved"))
            .exec(&txn)
            .await
            .map_err(db_error)?;
        if updated.rows_affected != 1 {
            txn.rollback().await.map_err(db_error)?;
            let Some(current) =
                find_owned_reservation(&self.db, account_id, reservation_id).await?
            else {
                return Err(TidewayError::not_found("Credit reservation not found"));
            };
            return match parse_status(&current.status)? {
                ReservationStatus::Committed => load_reservation(&self.db, current).await,
                ReservationStatus::Released => Err(TidewayError::conflict(
                    "Released credit reservation cannot be committed",
                )),
                ReservationStatus::Reserved => Err(TidewayError::conflict(
                    "Credit reservation changed concurrently; retry the commit",
                )),
            };
        }
        insert_lifecycle_transaction(&txn, &model, CreditTransactionKind::Commit, now, "commit")
            .await?;
        let mut result = load_reservation(&txn, model).await?;
        result.status = ReservationStatus::Committed;
        result.updated_at = now;
        txn.commit().await.map_err(db_error)?;
        Ok(result)
    }

    async fn release(
        &self,
        account_id: &str,
        reservation_id: &str,
        now: i64,
    ) -> Result<CreditReservation> {
        release_reservation(&self.db, account_id, reservation_id, now, "release").await
    }

    async fn revoke(&self, request: &RevokeCredits, now: i64) -> Result<Option<CreditRevocation>> {
        let txn = self.db.begin().await.map_err(db_error)?;
        let mut models = bucket::Entity::find()
            .filter(bucket::Column::IdempotencyKey.eq(&request.grant_idempotency_key))
            .limit(2)
            .all(&txn)
            .await
            .map_err(db_error)?;
        if models.len() > 1 {
            txn.rollback().await.map_err(db_error)?;
            return Err(TidewayError::conflict(
                "Credit grant idempotency key matches more than one grant",
            ));
        }
        let Some(model) = models.pop() else {
            txn.rollback().await.map_err(db_error)?;
            return Ok(None);
        };
        let current_revoked = to_u64(model.revoked_amount)?;
        let current_pending = to_u64(model.pending_revocation)?;
        let remaining = to_u64(model.remaining_amount)?;
        let target = request.amount.resolve(to_u64(model.original_amount)?);
        let delta = target.saturating_sub(current_revoked);
        if delta == 0 {
            txn.commit().await.map_err(db_error)?;
            return Ok(Some(CreditRevocation {
                bucket: model_to_bucket(model)?,
                revoked_amount: current_revoked,
                unrecovered_amount: current_pending,
            }));
        }
        let taken = remaining.min(delta);
        let pending = current_pending
            .checked_add(delta - taken)
            .ok_or_else(|| TidewayError::internal("Credit revocation overflow"))?;
        let updated = bucket::Entity::update_many()
            .col_expr(
                bucket::Column::RemainingAmount,
                Expr::value(to_i64(remaining - taken)?),
            )
            .col_expr(bucket::Column::RevokedAmount, Expr::value(to_i64(target)?))
            .col_expr(
                bucket::Column::PendingRevocation,
                Expr::value(to_i64(pending)?),
            )
            .filter(bucket::Column::Id.eq(&model.id))
            .filter(bucket::Column::RemainingAmount.eq(model.remaining_amount))
            .filter(bucket::Column::RevokedAmount.eq(model.revoked_amount))
            .filter(bucket::Column::PendingRevocation.eq(model.pending_revocation))
            .exec(&txn)
            .await
            .map_err(db_error)?;
        if updated.rows_affected != 1 {
            txn.rollback().await.map_err(db_error)?;
            return Err(TidewayError::conflict(
                "Credit grant changed concurrently; retry the revocation",
            ));
        }
        let mut bucket = model_to_bucket(model)?;
        bucket.remaining_amount = remaining - taken;
        transaction::Entity::insert(transaction_active_model(CreditTransaction {
            id: uuid::Uuid::new_v4().to_string(),
            account_id: bucket.account_id.clone(),
            credit_type: bucket.credit_type.clone(),
            kind: CreditTransactionKind::Revoke,
            amount: delta,
            bucket_id: Some(bucket.id.clone()),
            reservation_id: None,
            idempotency_key: request.idempotency_key.clone(),
            created_at: now,
            metadata: request.metadata.clone(),
        })?)
        .exec(&txn)
        .await
        .map_err(db_error)?;
        txn.commit().await.map_err(db_error)?;
        Ok(Some(CreditRevocation {
            bucket,
            revoked_amount: target,
            unrecovered_amount: pending,
        }))
    }

    async fn balance(
        &self,
        account_id: &str,
        credit_type: &str,
        now: i64,
    ) -> Result<CreditBalance> {
        let active_buckets = sea_orm::Condition::all()
            .add(bucket::Column::AccountId.eq(account_id))
            .add(bucket::Column::CreditType.eq(credit_type))
            .add(
                sea_orm::Condition::any()
                    .add(bucket::Column::ExpiresAt.is_null())
                    .add(bucket::Column::ExpiresAt.gt(now)),
            );
        let held_reservations = sea_orm::Condition::all()
            .add(reservation::Column::AccountId.eq(account_id))
            .add(reservation::Column::CreditType.eq(credit_type))
            .add(reservation::Column::Status.eq("reserved"));

        // Read the stored amounts, recoverable expired allocations, and live holds in one
        // snapshot. Only mutations / maintenance persist reservation expiry. UNION ALL keeps
        // separate amounts so Rust can retain checked u64 totals without SQL SUM overflow.
        // Expired allocations carry their bucket because releasing them first repays revoked
        // credits.
        let expired_allocations = Query::select()
            .column((bucket::Entity, bucket::Column::Source))
            .column((allocation::Entity, allocation::Column::Amount))
            .column((bucket::Entity, bucket::Column::Id))
            .column((bucket::Entity, bucket::Column::PendingRevocation))
            .from(allocation::Entity)
            .join(
                JoinType::InnerJoin,
                bucket::Entity,
                Expr::col((allocation::Entity, allocation::Column::BucketId))
                    .equals((bucket::Entity, bucket::Column::Id)),
            )
            .join(
                JoinType::InnerJoin,
                reservation::Entity,
                Expr::col((allocation::Entity, allocation::Column::ReservationId))
                    .equals((reservation::Entity, reservation::Column::Id)),
            )
            .cond_where(active_buckets.clone())
            .cond_where(held_reservations.clone())
            .and_where(reservation::Column::ExpiresAt.lte(now))
            .to_owned();
        let live_holds = Query::select()
            .expr(Expr::val(Option::<String>::None))
            .column(reservation::Column::Amount)
            .expr(Expr::val(Option::<String>::None))
            .expr(Expr::val(0i64))
            .from(reservation::Entity)
            .cond_where(held_reservations)
            .and_where(reservation::Column::ExpiresAt.gt(now))
            .to_owned();
        let query = Query::select()
            .column(bucket::Column::Source)
            .expr_as(
                Expr::col(bucket::Column::RemainingAmount),
                Alias::new("amount"),
            )
            .expr_as(Expr::val(Option::<String>::None), Alias::new("bucket_id"))
            .expr_as(Expr::val(0i64), Alias::new("pending"))
            .from(bucket::Entity)
            .cond_where(active_buckets)
            .union(UnionType::All, expired_allocations)
            .union(UnionType::All, live_holds)
            .to_owned();
        let rows = self
            .db
            .query_all(self.db.get_database_backend().build(&query))
            .await
            .map_err(db_error)?;
        let mut by_source = std::collections::HashMap::<CreditSource, u64>::new();
        let mut expired_holds =
            std::collections::HashMap::<String, (CreditSource, u64, u64)>::new();
        let mut reserved = 0u64;
        for row in rows {
            let amount = to_u64(row.try_get("", "amount").map_err(db_error)?)?;
            let source: Option<String> = row.try_get("", "source").map_err(db_error)?;
            let bucket_id: Option<String> = row.try_get("", "bucket_id").map_err(db_error)?;
            if let (Some(source), Some(bucket_id)) = (&source, bucket_id) {
                let pending = to_u64(row.try_get("", "pending").map_err(db_error)?)?;
                let entry =
                    expired_holds
                        .entry(bucket_id)
                        .or_insert((parse_source(source)?, 0, pending));
                entry.1 = entry
                    .1
                    .checked_add(amount)
                    .ok_or_else(|| TidewayError::internal("Credit balance overflow"))?;
            } else if let Some(source) = source {
                let entry = by_source.entry(parse_source(&source)?).or_default();
                *entry = entry
                    .checked_add(amount)
                    .ok_or_else(|| TidewayError::internal("Credit balance overflow"))?;
            } else {
                reserved = reserved
                    .checked_add(amount)
                    .ok_or_else(|| TidewayError::internal("Reserved credit balance overflow"))?;
            }
        }
        for (source, held, pending) in expired_holds.into_values() {
            let entry = by_source.entry(source).or_default();
            *entry = entry
                .checked_add(held.saturating_sub(pending))
                .ok_or_else(|| TidewayError::internal("Credit balance overflow"))?;
        }
        let available = by_source.values().try_fold(0u64, |total, amount| {
            total
                .checked_add(*amount)
                .ok_or_else(|| TidewayError::internal("Credit balance overflow"))
        })?;
        Ok(CreditBalance {
            account_id: account_id.to_string(),
            credit_type: credit_type.to_string(),
            available,
            reserved,
            by_source: [
                CreditSource::Allowance,
                CreditSource::Promotional,
                CreditSource::Purchased,
            ]
            .into_iter()
            .map(|source| SourceBalance {
                source,
                available: by_source.get(&source).copied().unwrap_or(0),
            })
            .collect(),
        })
    }

    async fn history(
        &self,
        account_id: &str,
        credit_type: &str,
        query: CreditHistoryQuery,
    ) -> Result<Vec<CreditTransaction>> {
        transaction::Entity::find()
            .filter(transaction::Column::AccountId.eq(account_id))
            .filter(transaction::Column::CreditType.eq(credit_type))
            .order_by_desc(transaction::Column::CreatedAt)
            .order_by_desc(transaction::Column::Id)
            .offset(query.offset)
            .limit(query.limit)
            .all(&self.db)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(model_to_transaction)
            .collect()
    }

    async fn release_expired(&self, now: i64, limit: u64) -> Result<u64> {
        let expired = reservation::Entity::find()
            .filter(reservation::Column::Status.eq("reserved"))
            .filter(reservation::Column::ExpiresAt.lte(now))
            .order_by_asc(reservation::Column::ExpiresAt)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(db_error)?;
        let mut released = 0u64;
        for model in expired {
            match release_reservation(&self.db, &model.account_id, &model.id, now, "expired").await
            {
                Ok(_) => released = released.saturating_add(1),
                Err(TidewayError::Conflict(_)) | Err(TidewayError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(released)
    }
}

fn bucket_active_model(
    bucket: &CreditBucket,
    metadata: &serde_json::Value,
) -> Result<bucket::ActiveModel> {
    Ok(bucket::ActiveModel {
        id: Set(bucket.id.clone()),
        account_id: Set(bucket.account_id.clone()),
        credit_type: Set(bucket.credit_type.clone()),
        source: Set(bucket.source.as_str().to_string()),
        original_amount: Set(to_i64(bucket.original_amount)?),
        remaining_amount: Set(to_i64(bucket.remaining_amount)?),
        expires_at: Set(bucket.expires_at),
        idempotency_key: Set(bucket.idempotency_key.clone()),
        metadata: Set(metadata.clone()),
        created_at: Set(bucket.created_at),
        revoked_amount: Set(0),
        pending_revocation: Set(0),
    })
}

fn reservation_active_model(
    value: &CreditReservation,
    order: ConsumptionOrder,
) -> Result<reservation::ActiveModel> {
    Ok(reservation::ActiveModel {
        id: Set(value.id.clone()),
        account_id: Set(value.account_id.clone()),
        credit_type: Set(value.credit_type.clone()),
        amount: Set(to_i64(value.amount)?),
        status: Set(value.status.as_str().to_string()),
        idempotency_key: Set(value.idempotency_key.clone()),
        consumption_order: Set(order.as_str().to_string()),
        expires_at: Set(value.expires_at),
        created_at: Set(value.created_at),
        updated_at: Set(value.updated_at),
        metadata: Set(value.metadata.clone()),
    })
}

fn transaction_active_model(value: CreditTransaction) -> Result<transaction::ActiveModel> {
    Ok(transaction::ActiveModel {
        id: Set(value.id),
        account_id: Set(value.account_id),
        credit_type: Set(value.credit_type),
        kind: Set(value.kind.as_str().to_string()),
        amount: Set(to_i64(value.amount)?),
        bucket_id: Set(value.bucket_id),
        reservation_id: Set(value.reservation_id),
        idempotency_key: Set(value.idempotency_key),
        created_at: Set(value.created_at),
        metadata: Set(value.metadata),
    })
}

fn model_to_bucket(model: bucket::Model) -> Result<CreditBucket> {
    Ok(CreditBucket {
        id: model.id,
        account_id: model.account_id,
        credit_type: model.credit_type,
        source: parse_source(&model.source)?,
        original_amount: to_u64(model.original_amount)?,
        remaining_amount: to_u64(model.remaining_amount)?,
        expires_at: model.expires_at,
        idempotency_key: model.idempotency_key,
        created_at: model.created_at,
    })
}

fn model_to_transaction(model: transaction::Model) -> Result<CreditTransaction> {
    Ok(CreditTransaction {
        id: model.id,
        account_id: model.account_id,
        credit_type: model.credit_type,
        kind: CreditTransactionKind::parse(&model.kind).ok_or_else(|| {
            TidewayError::internal(format!("Unknown credit transaction kind: {}", model.kind))
        })?,
        amount: to_u64(model.amount)?,
        bucket_id: model.bucket_id,
        reservation_id: model.reservation_id,
        idempotency_key: model.idempotency_key,
        created_at: model.created_at,
        metadata: model.metadata,
    })
}

async fn load_reservation<C: sea_orm::ConnectionTrait>(
    db: &C,
    model: reservation::Model,
) -> Result<CreditReservation> {
    let allocations = allocation::Entity::find()
        .filter(allocation::Column::ReservationId.eq(&model.id))
        .all(db)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|item| {
            Ok(CreditAllocation {
                bucket_id: item.bucket_id,
                amount: to_u64(item.amount)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CreditReservation {
        id: model.id,
        account_id: model.account_id,
        credit_type: model.credit_type,
        amount: to_u64(model.amount)?,
        status: parse_status(&model.status)?,
        idempotency_key: model.idempotency_key,
        order: ConsumptionOrder::parse(&model.consumption_order).ok_or_else(|| {
            TidewayError::internal(format!(
                "Unknown credit consumption order: {}",
                model.consumption_order
            ))
        })?,
        allocations,
        expires_at: model.expires_at,
        created_at: model.created_at,
        updated_at: model.updated_at,
        metadata: model.metadata,
    })
}

async fn find_owned_reservation<C: sea_orm::ConnectionTrait>(
    db: &C,
    account_id: &str,
    reservation_id: &str,
) -> Result<Option<reservation::Model>> {
    reservation::Entity::find_by_id(reservation_id)
        .filter(reservation::Column::AccountId.eq(account_id))
        .one(db)
        .await
        .map_err(db_error)
}

async fn release_reservation(
    db: &DatabaseConnection,
    account_id: &str,
    reservation_id: &str,
    now: i64,
    reason: &str,
) -> Result<CreditReservation> {
    let txn = db.begin().await.map_err(db_error)?;
    let Some(model) = find_owned_reservation(&txn, account_id, reservation_id).await? else {
        txn.rollback().await.map_err(db_error)?;
        return Err(TidewayError::not_found("Credit reservation not found"));
    };
    match parse_status(&model.status)? {
        ReservationStatus::Released => {
            let result = load_reservation(&txn, model).await?;
            txn.commit().await.map_err(db_error)?;
            return Ok(result);
        }
        ReservationStatus::Committed => {
            txn.rollback().await.map_err(db_error)?;
            return Err(TidewayError::conflict(
                "Committed credit reservation cannot be released",
            ));
        }
        ReservationStatus::Reserved => {}
    }
    let updated = reservation::Entity::update_many()
        .col_expr(reservation::Column::Status, Expr::value("released"))
        .col_expr(reservation::Column::UpdatedAt, Expr::value(now))
        .filter(reservation::Column::Id.eq(reservation_id))
        .filter(reservation::Column::AccountId.eq(account_id))
        .filter(reservation::Column::Status.eq("reserved"))
        .exec(&txn)
        .await
        .map_err(db_error)?;
    if updated.rows_affected != 1 {
        txn.rollback().await.map_err(db_error)?;
        let Some(current) = find_owned_reservation(db, account_id, reservation_id).await? else {
            return Err(TidewayError::not_found("Credit reservation not found"));
        };
        return match parse_status(&current.status)? {
            ReservationStatus::Released => load_reservation(db, current).await,
            ReservationStatus::Committed => Err(TidewayError::conflict(
                "Committed credit reservation cannot be released",
            )),
            ReservationStatus::Reserved => Err(TidewayError::conflict(
                "Credit reservation changed concurrently; retry the release",
            )),
        };
    }
    let allocations = allocation::Entity::find()
        .filter(allocation::Column::ReservationId.eq(reservation_id))
        .all(&txn)
        .await
        .map_err(db_error)?;
    for item in &allocations {
        // Credits revoked while held repay the revocation first and only the rest returns to the
        // balance. Both assignments read the pre-update row.
        let pending = Expr::col(bucket::Column::PendingRevocation);
        let restored = bucket::Entity::update_many()
            .col_expr(
                bucket::Column::RemainingAmount,
                Expr::case(
                    pending.clone().gte(item.amount),
                    Expr::col(bucket::Column::RemainingAmount),
                )
                .finally(
                    Expr::col(bucket::Column::RemainingAmount)
                        .add(item.amount)
                        .sub(pending.clone()),
                )
                .into(),
            )
            .col_expr(
                bucket::Column::PendingRevocation,
                Expr::case(pending.clone().gte(item.amount), pending.sub(item.amount))
                    .finally(0i64)
                    .into(),
            )
            .filter(bucket::Column::Id.eq(&item.bucket_id))
            .exec(&txn)
            .await
            .map_err(db_error)?;
        if restored.rows_affected != 1 {
            txn.rollback().await.map_err(db_error)?;
            return Err(TidewayError::internal(
                "Credit release could not safely restore its bucket",
            ));
        }
    }
    insert_lifecycle_transaction(&txn, &model, CreditTransactionKind::Release, now, reason).await?;
    let mut result = load_reservation(&txn, model).await?;
    result.status = ReservationStatus::Released;
    result.updated_at = now;
    txn.commit().await.map_err(db_error)?;
    Ok(result)
}

async fn insert_lifecycle_transaction<C: sea_orm::ConnectionTrait>(
    db: &C,
    model: &reservation::Model,
    kind: CreditTransactionKind,
    now: i64,
    suffix: &str,
) -> Result<()> {
    transaction::Entity::insert(transaction_active_model(CreditTransaction {
        id: uuid::Uuid::new_v4().to_string(),
        account_id: model.account_id.clone(),
        credit_type: model.credit_type.clone(),
        kind,
        amount: to_u64(model.amount)?,
        bucket_id: None,
        reservation_id: Some(model.id.clone()),
        idempotency_key: format!("{}:{suffix}", model.idempotency_key),
        created_at: now,
        metadata: model.metadata.clone(),
    })?)
    .exec(db)
    .await
    .map_err(db_error)?;
    Ok(())
}

fn ensure_matching_grant(existing: &CreditBucket, request: &GrantCredits) -> Result<()> {
    if existing.original_amount != request.amount
        || existing.source != request.source
        || existing.expires_at != request.expires_at
    {
        return Err(TidewayError::conflict(
            "Credit grant idempotency key was reused with different parameters",
        ));
    }
    Ok(())
}

fn ensure_matching_reservation(
    existing: &CreditReservation,
    request: &ReserveCredits,
) -> Result<()> {
    if existing.amount != request.amount || existing.order != request.order {
        return Err(TidewayError::conflict(
            "Credit reservation idempotency key was reused with different parameters",
        ));
    }
    Ok(())
}

fn compare_bucket_models(
    left: &bucket::Model,
    right: &bucket::Model,
    order: ConsumptionOrder,
) -> std::cmp::Ordering {
    let expiry = |model: &bucket::Model| model.expires_at.unwrap_or(i64::MAX);
    let rank = |value: &str| match value {
        "allowance" => 0,
        "promotional" => 1,
        "purchased" => 2,
        _ => 3,
    };
    match order {
        ConsumptionOrder::AllowanceFirst => rank(&left.source)
            .cmp(&rank(&right.source))
            .then_with(|| expiry(left).cmp(&expiry(right))),
        ConsumptionOrder::EarliestExpiry => expiry(left)
            .cmp(&expiry(right))
            .then_with(|| rank(&left.source).cmp(&rank(&right.source))),
    }
    .then_with(|| left.created_at.cmp(&right.created_at))
    .then_with(|| left.id.cmp(&right.id))
}

fn insufficient(request: &ReserveCredits, available: u64) -> TidewayError {
    TidewayError::conflict(format!(
        "Insufficient {} credits: requested {}, available {}",
        request.credit_type, request.amount, available
    ))
}

fn parse_source(value: &str) -> Result<CreditSource> {
    CreditSource::parse(value)
        .ok_or_else(|| TidewayError::internal(format!("Unknown credit source: {value}")))
}

fn parse_status(value: &str) -> Result<ReservationStatus> {
    ReservationStatus::parse(value)
        .ok_or_else(|| TidewayError::internal(format!("Unknown reservation status: {value}")))
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| TidewayError::bad_request("Credit amount exceeds i64::MAX"))
}

fn to_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| TidewayError::internal("Stored credit amount is negative"))
}

fn db_error(error: sea_orm::DbErr) -> TidewayError {
    TidewayError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database};

    use super::*;

    async fn store() -> SeaOrmCreditStore {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        db.execute_unprepared(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE credit_buckets (
                id TEXT PRIMARY KEY NOT NULL,
                account_id TEXT NOT NULL,
                credit_type TEXT NOT NULL,
                source TEXT NOT NULL,
                original_amount BIGINT NOT NULL CHECK (original_amount > 0),
                remaining_amount BIGINT NOT NULL CHECK (remaining_amount >= 0 AND remaining_amount <= original_amount),
                expires_at BIGINT NULL,
                idempotency_key TEXT NOT NULL,
                metadata JSON NOT NULL,
                created_at BIGINT NOT NULL,
                revoked_amount BIGINT NOT NULL DEFAULT 0,
                pending_revocation BIGINT NOT NULL DEFAULT 0,
                UNIQUE (account_id, credit_type, idempotency_key)
            );
            CREATE TABLE credit_reservations (
                id TEXT PRIMARY KEY NOT NULL,
                account_id TEXT NOT NULL,
                credit_type TEXT NOT NULL,
                amount BIGINT NOT NULL CHECK (amount > 0),
                status TEXT NOT NULL CHECK (status IN ('reserved', 'committed', 'released')),
                idempotency_key TEXT NOT NULL,
                consumption_order TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL,
                metadata JSON NOT NULL,
                UNIQUE (account_id, credit_type, idempotency_key)
            );
            CREATE TABLE credit_reservation_allocations (
                reservation_id TEXT NOT NULL,
                bucket_id TEXT NOT NULL,
                amount BIGINT NOT NULL CHECK (amount > 0),
                PRIMARY KEY (reservation_id, bucket_id),
                FOREIGN KEY (reservation_id) REFERENCES credit_reservations(id) ON DELETE CASCADE,
                FOREIGN KEY (bucket_id) REFERENCES credit_buckets(id) ON DELETE RESTRICT
            );
            CREATE TABLE credit_transactions (
                id TEXT PRIMARY KEY NOT NULL,
                account_id TEXT NOT NULL,
                credit_type TEXT NOT NULL,
                kind TEXT NOT NULL,
                amount BIGINT NOT NULL CHECK (amount > 0),
                bucket_id TEXT NULL,
                reservation_id TEXT NULL,
                idempotency_key TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                metadata JSON NOT NULL
            );
            "#,
        )
        .await
        .expect("create credit schema");
        SeaOrmCreditStore::new(db)
    }

    fn grant(account: &str, amount: u64, source: CreditSource, key: &str) -> GrantCredits {
        GrantCredits {
            account_id: account.to_string(),
            credit_type: "sms".to_string(),
            amount,
            source,
            expires_at: None,
            idempotency_key: key.to_string(),
            metadata: serde_json::json!({"test": true}),
        }
    }

    fn reserve(account: &str, amount: u64, key: &str) -> ReserveCredits {
        ReserveCredits {
            account_id: account.to_string(),
            credit_type: "sms".to_string(),
            amount,
            idempotency_key: key.to_string(),
            order: ConsumptionOrder::AllowanceFirst,
            metadata: serde_json::json!({"message_id": key}),
        }
    }

    #[tokio::test]
    async fn balance_succeeds_when_expiry_writes_are_forbidden() {
        let store = store().await;
        store
            .grant(&grant("org-1", 10, CreditSource::Purchased, "purchase"), 10)
            .await
            .unwrap();
        store
            .reserve(&reserve("org-1", 10, "hold"), 25, 20)
            .await
            .unwrap();
        // These guards reject the bucket/reservation updates and ledger insertion that
        // expiry used to perform, even if an implementation were to swallow the error.
        store
            .db
            .execute_unprepared(
                r#"
            CREATE TRIGGER forbid_bucket_update BEFORE UPDATE ON credit_buckets
            BEGIN SELECT RAISE(ABORT, 'balance must not update buckets'); END;
            CREATE TRIGGER forbid_reservation_update BEFORE UPDATE ON credit_reservations
            BEGIN SELECT RAISE(ABORT, 'balance must not update reservations'); END;
            CREATE TRIGGER forbid_transaction_insert BEFORE INSERT ON credit_transactions
            BEGIN SELECT RAISE(ABORT, 'balance must not insert transactions'); END;
        "#,
            )
            .await
            .unwrap();
        for _ in 0..2 {
            let balance = store.balance("org-1", "sms", 25).await.unwrap();
            assert_eq!((balance.available, balance.reserved), (10, 0));
        }
        assert_eq!(
            bucket::Entity::find()
                .one(&store.db)
                .await
                .unwrap()
                .unwrap()
                .remaining_amount,
            0
        );
        assert_eq!(
            reservation::Entity::find()
                .one(&store.db)
                .await
                .unwrap()
                .unwrap()
                .status,
            "reserved"
        );
    }

    #[tokio::test]
    async fn balance_is_read_only_and_accounts_for_expired_holds() {
        super::super::balance_tests::assert_read_only_balance(&store().await).await;
    }

    #[tokio::test]
    async fn revocation_takes_back_remaining_and_held_credits() {
        super::super::revocation_tests::assert_revocation(&store().await).await;
    }

    #[tokio::test]
    async fn grant_and_reservation_are_idempotent() {
        let store = store().await;
        let first = store
            .grant(
                &grant("org-1", 100, CreditSource::Allowance, "period-1"),
                10,
            )
            .await
            .expect("grant");
        let retried = store
            .grant(
                &grant("org-1", 100, CreditSource::Allowance, "period-1"),
                11,
            )
            .await
            .expect("retry grant");
        assert_eq!(first.id, retried.id);

        let reserved = store
            .reserve(&reserve("org-1", 20, "send-1"), 100, 20)
            .await
            .expect("reserve");
        let retried = store
            .reserve(&reserve("org-1", 20, "send-1"), 101, 21)
            .await
            .expect("retry reserve");
        assert_eq!(reserved.id, retried.id);
        assert_eq!(
            store.balance("org-1", "sms", 21).await.unwrap().available,
            80
        );
    }

    #[tokio::test]
    async fn release_restores_exact_buckets_and_commit_is_final() {
        let store = store().await;
        store
            .grant(&grant("org-1", 40, CreditSource::Allowance, "period-1"), 10)
            .await
            .unwrap();
        let held = store
            .reserve(&reserve("org-1", 25, "send-1"), 100, 20)
            .await
            .unwrap();
        let released = store.release("org-1", &held.id, 30).await.unwrap();
        assert_eq!(released.status, ReservationStatus::Released);
        assert_eq!(
            store.balance("org-1", "sms", 30).await.unwrap().available,
            40
        );

        let held = store
            .reserve(&reserve("org-1", 15, "send-2"), 100, 31)
            .await
            .unwrap();
        store.commit("org-1", &held.id, 32).await.unwrap();
        let error = store.release("org-1", &held.id, 33).await.unwrap_err();
        assert!(matches!(error, TidewayError::Conflict(_)));
    }

    #[tokio::test]
    async fn tenant_boundary_is_fail_closed() {
        let store = store().await;
        store
            .grant(&grant("org-1", 10, CreditSource::Purchased, "topup-1"), 10)
            .await
            .unwrap();
        let held = store
            .reserve(&reserve("org-1", 5, "send-1"), 100, 20)
            .await
            .unwrap();
        let error = store.commit("org-2", &held.id, 30).await.unwrap_err();
        assert!(matches!(error, TidewayError::NotFound(_)));
        assert_eq!(
            store.balance("org-2", "sms", 30).await.unwrap().available,
            0
        );
    }

    #[tokio::test]
    async fn expired_holds_are_available_before_cleanup() {
        let store = store().await;
        store
            .grant(&grant("org-1", 10, CreditSource::Allowance, "period-1"), 10)
            .await
            .unwrap();
        let expired = store
            .reserve(&reserve("org-1", 10, "send-1"), 25, 20)
            .await
            .unwrap();
        assert_eq!(
            store.balance("org-1", "sms", 30).await.unwrap().available,
            10
        );
        let current = store
            .release("org-1", &expired.id, 31)
            .await
            .expect("release is idempotent");
        assert_eq!(current.status, ReservationStatus::Released);
    }

    #[tokio::test]
    async fn request_cleanup_is_scoped_to_the_requested_account() {
        let store = store().await;
        for account in ["org-1", "org-2"] {
            store
                .grant(&grant(account, 10, CreditSource::Allowance, "period-1"), 10)
                .await
                .unwrap();
        }
        let first = store
            .reserve(&reserve("org-1", 10, "send-1"), 25, 20)
            .await
            .unwrap();
        let second = store
            .reserve(&reserve("org-2", 10, "send-2"), 25, 20)
            .await
            .unwrap();

        store
            .reserve(&reserve("org-1", 1, "new-hold"), 100, 30)
            .await
            .unwrap();

        let first_status = reservation::Entity::find_by_id(&first.id)
            .one(&store.db)
            .await
            .unwrap()
            .unwrap()
            .status;
        let second_status = reservation::Entity::find_by_id(&second.id)
            .one(&store.db)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(first_status, "released");
        assert_eq!(second_status, "reserved");
    }

    #[tokio::test]
    async fn commit_releases_an_expired_reservation_without_a_global_sweep() {
        let store = store().await;
        store
            .grant(&grant("org-1", 10, CreditSource::Allowance, "period-1"), 10)
            .await
            .unwrap();
        let held = store
            .reserve(&reserve("org-1", 10, "send-1"), 25, 20)
            .await
            .unwrap();

        assert!(matches!(
            store.commit("org-1", &held.id, 30).await,
            Err(TidewayError::Conflict(_))
        ));
        assert_eq!(
            store.balance("org-1", "sms", 30).await.unwrap().available,
            10
        );
    }

    #[tokio::test]
    async fn an_expired_grant_retry_returns_the_original_bucket() {
        let store = store().await;
        let mut request = grant("org-1", 10, CreditSource::Allowance, "period-1");
        request.expires_at = Some(20);
        let original = store.grant(&request, 10).await.unwrap();
        let retry = store.grant(&request, 30).await.unwrap();
        assert_eq!(retry.id, original.id);

        request.idempotency_key = "period-2".to_string();
        assert!(matches!(
            store.grant(&request, 30).await,
            Err(TidewayError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn allowance_is_consumed_before_persistent_purchased_credits() {
        let store = store().await;
        let purchased = store
            .grant(&grant("org-1", 50, CreditSource::Purchased, "topup-1"), 10)
            .await
            .unwrap();
        let allowance = store
            .grant(&grant("org-1", 10, CreditSource::Allowance, "period-1"), 11)
            .await
            .unwrap();
        let held = store
            .reserve(&reserve("org-1", 15, "send-1"), 100, 20)
            .await
            .unwrap();
        assert_eq!(held.allocations[0].bucket_id, allowance.id);
        assert_eq!(held.allocations[0].amount, 10);
        assert_eq!(held.allocations[1].bucket_id, purchased.id);
        assert_eq!(held.allocations[1].amount, 5);
    }

    #[tokio::test]
    async fn concurrent_reservations_have_one_winner() {
        let store = store().await;
        store
            .grant(&grant("org-1", 10, CreditSource::Allowance, "period-1"), 10)
            .await
            .unwrap();

        let first_store = store.clone();
        let second_store = store.clone();
        let first_request = reserve("org-1", 10, "send-1");
        let second_request = reserve("org-1", 10, "send-2");
        let (first, second) = tokio::join!(
            first_store.reserve(&first_request, 100, 20),
            second_store.reserve(&second_request, 100, 20),
        );

        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(
            store.balance("org-1", "sms", 20).await.unwrap().available,
            0
        );
    }

    #[tokio::test]
    async fn concurrent_retries_with_the_same_key_return_the_same_reservation() {
        let store = store().await;
        store
            .grant(&grant("org-1", 10, CreditSource::Allowance, "period-1"), 10)
            .await
            .unwrap();
        let request = reserve("org-1", 10, "send-1");
        let first_store = store.clone();
        let second_store = store.clone();
        let (first, second) = tokio::join!(
            first_store.reserve(&request, 100, 20),
            second_store.reserve(&request, 100, 20),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(
            store.balance("org-1", "sms", 20).await.unwrap().available,
            0
        );

        let first_store = store.clone();
        let second_store = store.clone();
        let (first_release, second_release) = tokio::join!(
            first_store.release("org-1", &first.id, 30),
            second_store.release("org-1", &first.id, 30),
        );
        assert_eq!(first_release.unwrap().status, ReservationStatus::Released);
        assert_eq!(second_release.unwrap().status, ReservationStatus::Released);
        assert_eq!(
            store.balance("org-1", "sms", 30).await.unwrap().available,
            10
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
    async fn postgres_concurrent_reservations_have_one_winner() {
        let test_db = crate::testing::TestDb::new_postgres()
            .await
            .expect("create PostgreSQL test database");
        test_db
            .connection
            .execute_unprepared(
                r#"
                CREATE TABLE credit_buckets (
                    id TEXT PRIMARY KEY, account_id TEXT NOT NULL, credit_type TEXT NOT NULL,
                    source TEXT NOT NULL, original_amount BIGINT NOT NULL,
                    remaining_amount BIGINT NOT NULL, expires_at BIGINT,
                    idempotency_key TEXT NOT NULL, metadata JSONB NOT NULL, created_at BIGINT NOT NULL,
                    revoked_amount BIGINT NOT NULL DEFAULT 0,
                    pending_revocation BIGINT NOT NULL DEFAULT 0,
                    UNIQUE (account_id, credit_type, idempotency_key)
                );
                CREATE TABLE credit_reservations (
                    id TEXT PRIMARY KEY, account_id TEXT NOT NULL, credit_type TEXT NOT NULL,
                    amount BIGINT NOT NULL, status TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                    consumption_order TEXT NOT NULL, expires_at BIGINT NOT NULL,
                    created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, metadata JSONB NOT NULL,
                    UNIQUE (account_id, credit_type, idempotency_key)
                );
                CREATE TABLE credit_reservation_allocations (
                    reservation_id TEXT NOT NULL REFERENCES credit_reservations(id) ON DELETE CASCADE,
                    bucket_id TEXT NOT NULL REFERENCES credit_buckets(id) ON DELETE RESTRICT,
                    amount BIGINT NOT NULL, PRIMARY KEY (reservation_id, bucket_id)
                );
                CREATE TABLE credit_transactions (
                    id TEXT PRIMARY KEY, account_id TEXT NOT NULL, credit_type TEXT NOT NULL,
                    kind TEXT NOT NULL, amount BIGINT NOT NULL, bucket_id TEXT,
                    reservation_id TEXT, idempotency_key TEXT NOT NULL,
                    created_at BIGINT NOT NULL, metadata JSONB NOT NULL
                );
                "#,
            )
            .await
            .expect("create PostgreSQL credit schema");
        let store = SeaOrmCreditStore::new(test_db.connection());
        store
            .grant(&grant("org-1", 10, CreditSource::Allowance, "period-1"), 10)
            .await
            .unwrap();
        let first_store = store.clone();
        let second_store = store.clone();
        let first_request = reserve("org-1", 10, "send-1");
        let second_request = reserve("org-1", 10, "send-2");
        let (first, second) = tokio::join!(
            first_store.reserve(&first_request, 100, 20),
            second_store.reserve(&second_request, 100, 20),
        );

        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    }
}
