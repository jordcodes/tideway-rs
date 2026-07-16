use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use crate::{Result, TidewayError};

use super::{
    ConsumptionOrder, CreditAllocation, CreditBalance, CreditBucket, CreditHistoryQuery,
    CreditReservation, CreditSource, CreditStore, CreditTransaction, CreditTransactionKind,
    GrantCredits, ReservationStatus, ReserveCredits, SourceBalance,
};

/// Concurrency-safe reference store for development and tests.
#[derive(Clone, Default)]
pub struct MemoryCreditStore {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    buckets: HashMap<String, CreditBucket>,
    grants_by_key: HashMap<OperationKey, String>,
    reservations: HashMap<String, CreditReservation>,
    reservations_by_key: HashMap<OperationKey, String>,
    transactions: Vec<CreditTransaction>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OperationKey {
    account_id: String,
    credit_type: String,
    idempotency_key: String,
}

impl OperationKey {
    fn grant(request: &GrantCredits) -> Self {
        Self {
            account_id: request.account_id.clone(),
            credit_type: request.credit_type.clone(),
            idempotency_key: request.idempotency_key.clone(),
        }
    }

    fn reserve(request: &ReserveCredits) -> Self {
        Self {
            account_id: request.account_id.clone(),
            credit_type: request.credit_type.clone(),
            idempotency_key: request.idempotency_key.clone(),
        }
    }
}

impl MemoryCreditStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| TidewayError::internal("Credit store lock poisoned"))
    }
}

#[async_trait]
impl CreditStore for MemoryCreditStore {
    async fn grant(&self, request: &GrantCredits, now: i64) -> Result<CreditBucket> {
        let mut state = self.lock()?;
        release_expired_locked(&mut state, now, u64::MAX)?;
        let key = OperationKey::grant(request);
        if let Some(bucket_id) = state.grants_by_key.get(&key) {
            let existing = state
                .buckets
                .get(bucket_id)
                .ok_or_else(|| TidewayError::internal("Idempotent credit grant is missing"))?;
            if existing.original_amount != request.amount
                || existing.source != request.source
                || existing.expires_at != request.expires_at
            {
                return Err(TidewayError::conflict(
                    "Credit grant idempotency key was reused with different parameters",
                ));
            }
            return Ok(existing.clone());
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
        state.grants_by_key.insert(key, bucket.id.clone());
        state.buckets.insert(bucket.id.clone(), bucket.clone());
        state.transactions.push(CreditTransaction {
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
        });
        Ok(bucket)
    }

    async fn reserve(
        &self,
        request: &ReserveCredits,
        reservation_expires_at: i64,
        now: i64,
    ) -> Result<CreditReservation> {
        let mut state = self.lock()?;
        release_expired_locked(&mut state, now, u64::MAX)?;
        let key = OperationKey::reserve(request);
        if let Some(reservation_id) = state.reservations_by_key.get(&key) {
            let existing = state.reservations.get(reservation_id).ok_or_else(|| {
                TidewayError::internal("Idempotent credit reservation is missing")
            })?;
            if existing.amount != request.amount || existing.order != request.order {
                return Err(TidewayError::conflict(
                    "Credit reservation idempotency key was reused with different parameters",
                ));
            }
            return Ok(existing.clone());
        }

        let mut candidates = state
            .buckets
            .values()
            .filter(|bucket| {
                bucket.account_id == request.account_id
                    && bucket.credit_type == request.credit_type
                    && bucket.remaining_amount > 0
                    && bucket.expires_at.is_none_or(|expiry| expiry > now)
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| compare_buckets(left, right, request.order));

        let available = candidates.iter().try_fold(0u64, |total, bucket| {
            total
                .checked_add(bucket.remaining_amount)
                .ok_or_else(|| TidewayError::internal("Credit balance overflow"))
        })?;
        if available < request.amount {
            return Err(TidewayError::conflict(format!(
                "Insufficient {} credits: requested {}, available {}",
                request.credit_type, request.amount, available
            )));
        }

        let reservation_id = uuid::Uuid::new_v4().to_string();
        let mut needed = request.amount;
        let mut allocations = Vec::new();
        for candidate in candidates {
            if needed == 0 {
                break;
            }
            let amount = candidate.remaining_amount.min(needed);
            let bucket = state
                .buckets
                .get_mut(&candidate.id)
                .ok_or_else(|| TidewayError::internal("Credit bucket disappeared"))?;
            bucket.remaining_amount =
                bucket.remaining_amount.checked_sub(amount).ok_or_else(|| {
                    TidewayError::internal("Credit bucket underflow during reservation")
                })?;
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
        state
            .reservations_by_key
            .insert(key, reservation_id.clone());
        state
            .reservations
            .insert(reservation_id.clone(), reservation.clone());
        for allocation in allocations {
            state.transactions.push(CreditTransaction {
                id: uuid::Uuid::new_v4().to_string(),
                account_id: request.account_id.clone(),
                credit_type: request.credit_type.clone(),
                kind: CreditTransactionKind::Reserve,
                amount: allocation.amount,
                bucket_id: Some(allocation.bucket_id),
                reservation_id: Some(reservation_id.clone()),
                idempotency_key: request.idempotency_key.clone(),
                created_at: now,
                metadata: request.metadata.clone(),
            });
        }
        Ok(reservation)
    }

    async fn commit(
        &self,
        account_id: &str,
        reservation_id: &str,
        now: i64,
    ) -> Result<CreditReservation> {
        let mut state = self.lock()?;
        release_expired_locked(&mut state, now, u64::MAX)?;
        let reservation = state
            .reservations
            .get(reservation_id)
            .ok_or_else(|| TidewayError::not_found("Credit reservation not found"))?;
        ensure_account(reservation, account_id)?;
        match reservation.status {
            ReservationStatus::Committed => return Ok(reservation.clone()),
            ReservationStatus::Released => {
                return Err(TidewayError::conflict(
                    "Released credit reservation cannot be committed",
                ));
            }
            ReservationStatus::Reserved => {}
        }
        let transaction = lifecycle_transaction(reservation, CreditTransactionKind::Commit, now);
        let reservation = state
            .reservations
            .get_mut(reservation_id)
            .expect("reservation checked above");
        reservation.status = ReservationStatus::Committed;
        reservation.updated_at = now;
        let result = reservation.clone();
        state.transactions.push(transaction);
        Ok(result)
    }

    async fn release(
        &self,
        account_id: &str,
        reservation_id: &str,
        now: i64,
    ) -> Result<CreditReservation> {
        let mut state = self.lock()?;
        release_expired_locked(&mut state, now, u64::MAX)?;
        release_locked(&mut state, account_id, reservation_id, now, "release")
    }

    async fn balance(
        &self,
        account_id: &str,
        credit_type: &str,
        now: i64,
    ) -> Result<CreditBalance> {
        let mut state = self.lock()?;
        release_expired_locked(&mut state, now, u64::MAX)?;
        let mut by_source = HashMap::<CreditSource, u64>::new();
        for bucket in state.buckets.values().filter(|bucket| {
            bucket.account_id == account_id
                && bucket.credit_type == credit_type
                && bucket.expires_at.is_none_or(|expiry| expiry > now)
        }) {
            let source_total = by_source.entry(bucket.source).or_default();
            *source_total = source_total
                .checked_add(bucket.remaining_amount)
                .ok_or_else(|| TidewayError::internal("Credit balance overflow"))?;
        }
        let available = by_source.values().try_fold(0u64, |total, amount| {
            total
                .checked_add(*amount)
                .ok_or_else(|| TidewayError::internal("Credit balance overflow"))
        })?;
        let reserved = state
            .reservations
            .values()
            .filter(|reservation| {
                reservation.account_id == account_id
                    && reservation.credit_type == credit_type
                    && reservation.status == ReservationStatus::Reserved
            })
            .try_fold(0u64, |total, reservation| {
                total
                    .checked_add(reservation.amount)
                    .ok_or_else(|| TidewayError::internal("Reserved credit balance overflow"))
            })?;
        let sources = [
            CreditSource::Allowance,
            CreditSource::Promotional,
            CreditSource::Purchased,
        ]
        .into_iter()
        .map(|source| SourceBalance {
            source,
            available: by_source.get(&source).copied().unwrap_or(0),
        })
        .collect();
        Ok(CreditBalance {
            account_id: account_id.to_string(),
            credit_type: credit_type.to_string(),
            available,
            reserved,
            by_source: sources,
        })
    }

    async fn history(
        &self,
        account_id: &str,
        credit_type: &str,
        query: CreditHistoryQuery,
    ) -> Result<Vec<CreditTransaction>> {
        let state = self.lock()?;
        let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        let mut transactions = state
            .transactions
            .iter()
            .filter(|transaction| {
                transaction.account_id == account_id && transaction.credit_type == credit_type
            })
            .cloned()
            .collect::<Vec<_>>();
        transactions.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        Ok(transactions.into_iter().skip(offset).take(limit).collect())
    }

    async fn release_expired(&self, now: i64, limit: u64) -> Result<u64> {
        let mut state = self.lock()?;
        release_expired_locked(&mut state, now, limit)
    }
}

fn compare_buckets(left: &CreditBucket, right: &CreditBucket, order: ConsumptionOrder) -> Ordering {
    let expiry = |bucket: &CreditBucket| bucket.expires_at.unwrap_or(i64::MAX);
    let source_rank = |source: CreditSource| match source {
        CreditSource::Allowance => 0,
        CreditSource::Promotional => 1,
        CreditSource::Purchased => 2,
    };
    match order {
        ConsumptionOrder::AllowanceFirst => source_rank(left.source)
            .cmp(&source_rank(right.source))
            .then_with(|| expiry(left).cmp(&expiry(right))),
        ConsumptionOrder::EarliestExpiry => expiry(left)
            .cmp(&expiry(right))
            .then_with(|| source_rank(left.source).cmp(&source_rank(right.source))),
    }
    .then_with(|| left.created_at.cmp(&right.created_at))
    .then_with(|| left.id.cmp(&right.id))
}

fn ensure_account(reservation: &CreditReservation, account_id: &str) -> Result<()> {
    if reservation.account_id != account_id {
        // Deliberately hide whether another account owns the identifier.
        return Err(TidewayError::not_found("Credit reservation not found"));
    }
    Ok(())
}

fn lifecycle_transaction(
    reservation: &CreditReservation,
    kind: CreditTransactionKind,
    now: i64,
) -> CreditTransaction {
    CreditTransaction {
        id: uuid::Uuid::new_v4().to_string(),
        account_id: reservation.account_id.clone(),
        credit_type: reservation.credit_type.clone(),
        kind,
        amount: reservation.amount,
        bucket_id: None,
        reservation_id: Some(reservation.id.clone()),
        idempotency_key: reservation.idempotency_key.clone(),
        created_at: now,
        metadata: reservation.metadata.clone(),
    }
}

fn release_locked(
    state: &mut State,
    account_id: &str,
    reservation_id: &str,
    now: i64,
    reason: &str,
) -> Result<CreditReservation> {
    let reservation = state
        .reservations
        .get(reservation_id)
        .ok_or_else(|| TidewayError::not_found("Credit reservation not found"))?;
    ensure_account(reservation, account_id)?;
    match reservation.status {
        ReservationStatus::Released => return Ok(reservation.clone()),
        ReservationStatus::Committed => {
            return Err(TidewayError::conflict(
                "Committed credit reservation cannot be released",
            ));
        }
        ReservationStatus::Reserved => {}
    }
    let allocations = reservation.allocations.clone();
    let transaction = lifecycle_transaction(reservation, CreditTransactionKind::Release, now);
    for allocation in &allocations {
        let bucket = state
            .buckets
            .get(&allocation.bucket_id)
            .ok_or_else(|| TidewayError::internal("Reserved credit bucket is missing"))?;
        let restored = bucket
            .remaining_amount
            .checked_add(allocation.amount)
            .ok_or_else(|| TidewayError::internal("Credit bucket overflow during release"))?;
        if restored > bucket.original_amount {
            return Err(TidewayError::internal(
                "Credit release would exceed the original grant",
            ));
        }
    }
    for allocation in allocations {
        let bucket = state
            .buckets
            .get_mut(&allocation.bucket_id)
            .expect("release allocations validated above");
        bucket.remaining_amount = bucket
            .remaining_amount
            .checked_add(allocation.amount)
            .expect("release amount validated above");
    }
    let reservation = state
        .reservations
        .get_mut(reservation_id)
        .expect("reservation checked above");
    reservation.status = ReservationStatus::Released;
    reservation.updated_at = now;
    let result = reservation.clone();
    let mut transaction = transaction;
    transaction.idempotency_key = format!("{}:{reason}", transaction.idempotency_key);
    state.transactions.push(transaction);
    Ok(result)
}

fn release_expired_locked(state: &mut State, now: i64, limit: u64) -> Result<u64> {
    let reservation_ids = state
        .reservations
        .values()
        .filter(|reservation| {
            reservation.status == ReservationStatus::Reserved && reservation.expires_at <= now
        })
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|reservation| reservation.id.clone())
        .collect::<Vec<_>>();
    let released = reservation_ids.len() as u64;
    for reservation_id in reservation_ids {
        let account_id = state
            .reservations
            .get(&reservation_id)
            .expect("expired reservation selected above")
            .account_id
            .clone();
        release_locked(state, &account_id, &reservation_id, now, "expired")?;
    }
    Ok(released)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::CreditManager;

    fn grant(account: &str, source: CreditSource, amount: u64, key: &str) -> GrantCredits {
        GrantCredits {
            account_id: account.to_string(),
            credit_type: "sms".to_string(),
            amount,
            source,
            expires_at: None,
            idempotency_key: key.to_string(),
            metadata: serde_json::json!({}),
        }
    }

    fn reserve(account: &str, amount: u64, key: &str) -> ReserveCredits {
        ReserveCredits {
            account_id: account.to_string(),
            credit_type: "sms".to_string(),
            amount,
            idempotency_key: key.to_string(),
            order: ConsumptionOrder::AllowanceFirst,
            metadata: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn grant_reserve_commit_is_idempotent() {
        let manager = CreditManager::new(MemoryCreditStore::new());
        let first = manager
            .grant(grant("org_1", CreditSource::Allowance, 100, "period:1"))
            .await
            .unwrap();
        let retry = manager
            .grant(grant("org_1", CreditSource::Allowance, 100, "period:1"))
            .await
            .unwrap();
        assert_eq!(first.id, retry.id);

        let reservation = manager
            .reserve(reserve("org_1", 3, "send:1"))
            .await
            .unwrap();
        let retry = manager
            .reserve(reserve("org_1", 3, "send:1"))
            .await
            .unwrap();
        assert_eq!(reservation.id, retry.id);
        manager.commit("org_1", &reservation.id).await.unwrap();
        let committed = manager.commit("org_1", &reservation.id).await.unwrap();
        assert_eq!(committed.status, ReservationStatus::Committed);
        assert_eq!(manager.balance("org_1", "sms").await.unwrap().available, 97);
    }

    #[tokio::test]
    async fn failed_operation_release_restores_the_same_buckets() {
        let manager = CreditManager::new(MemoryCreditStore::new());
        manager
            .grant(grant("org_1", CreditSource::Allowance, 5, "period:1"))
            .await
            .unwrap();
        let reservation = manager
            .reserve(reserve("org_1", 4, "send:1"))
            .await
            .unwrap();
        assert_eq!(manager.balance("org_1", "sms").await.unwrap().available, 1);
        manager.release("org_1", &reservation.id).await.unwrap();
        manager.release("org_1", &reservation.id).await.unwrap();
        assert_eq!(manager.balance("org_1", "sms").await.unwrap().available, 5);
    }

    #[tokio::test]
    async fn concurrent_reservations_cannot_overspend() {
        let manager = CreditManager::new(MemoryCreditStore::new());
        manager
            .grant(grant("org_1", CreditSource::Allowance, 1, "period:1"))
            .await
            .unwrap();
        let (first, second) = tokio::join!(
            manager.reserve(reserve("org_1", 1, "send:1")),
            manager.reserve(reserve("org_1", 1, "send:2"))
        );
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .into_iter()
                .filter(|ok| *ok)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn allowance_is_consumed_before_purchased_credits() {
        let store = MemoryCreditStore::new();
        let manager = CreditManager::new(store.clone());
        let purchased = manager
            .grant(grant("org_1", CreditSource::Purchased, 10, "topup:1"))
            .await
            .unwrap();
        let allowance = manager
            .grant(grant("org_1", CreditSource::Allowance, 2, "period:1"))
            .await
            .unwrap();
        let reservation = manager
            .reserve(reserve("org_1", 3, "send:1"))
            .await
            .unwrap();
        assert_eq!(reservation.allocations[0].bucket_id, allowance.id);
        assert_eq!(reservation.allocations[0].amount, 2);
        assert_eq!(reservation.allocations[1].bucket_id, purchased.id);
        assert_eq!(reservation.allocations[1].amount, 1);
    }

    #[tokio::test]
    async fn account_boundaries_fail_closed() {
        let manager = CreditManager::new(MemoryCreditStore::new());
        manager
            .grant(grant("org_1", CreditSource::Allowance, 1, "period:1"))
            .await
            .unwrap();
        let reservation = manager
            .reserve(reserve("org_1", 1, "send:1"))
            .await
            .unwrap();
        assert!(manager.commit("org_2", &reservation.id).await.is_err());
        assert!(manager.release("org_2", &reservation.id).await.is_err());
    }

    #[tokio::test]
    async fn expired_reservation_is_released() {
        let store = MemoryCreditStore::new();
        store
            .grant(&grant("org_1", CreditSource::Allowance, 1, "period:1"), 10)
            .await
            .unwrap();
        let reservation = store
            .reserve(&reserve("org_1", 1, "send:1"), 20, 10)
            .await
            .unwrap();
        assert_eq!(store.release_expired(20, 100).await.unwrap(), 1);
        assert_eq!(
            store.balance("org_1", "sms", 20).await.unwrap().available,
            1
        );
        assert!(store.commit("org_1", &reservation.id, 20).await.is_err());
    }

    #[tokio::test]
    async fn an_expired_grant_retry_returns_the_original_bucket() {
        let store = MemoryCreditStore::new();
        let mut request = grant("org_1", CreditSource::Allowance, 5, "period:1");
        request.expires_at = Some(20);
        let original = store.grant(&request, 10).await.unwrap();
        let retry = store.grant(&request, 30).await.unwrap();
        assert_eq!(retry.id, original.id);

        let mut new_request = request;
        new_request.idempotency_key = "period:2".to_string();
        assert!(matches!(
            store.grant(&new_request, 30).await,
            Err(TidewayError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn zero_duration_reservations_are_rejected() {
        let manager = CreditManager::new(MemoryCreditStore::new())
            .with_reservation_ttl(std::time::Duration::ZERO);
        let error = manager
            .reserve(reserve("org_1", 1, "send:1"))
            .await
            .unwrap_err();
        assert!(matches!(error, TidewayError::BadRequest(_)));
    }
}
