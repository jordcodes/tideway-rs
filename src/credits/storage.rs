use async_trait::async_trait;

use crate::Result;

use super::{
    ConsumptionOrder, CreditBalance, CreditBucket, CreditHistoryQuery, CreditReservation,
    CreditRevocation, CreditTransaction, GrantCredits, ReserveCredits, RevokeCredits,
};

/// Atomic persistence contract for the credit ledger.
///
/// Production implementations must perform each method as one database transaction. In
/// particular, reservation selection and bucket deductions must not use check-then-update logic.
#[async_trait]
pub trait CreditStore: Send + Sync {
    /// Return an existing matching grant before validating time-sensitive creation rules. This
    /// preserves idempotent retries after a previously valid bucket has expired.
    async fn grant(&self, request: &GrantCredits, now: i64) -> Result<CreditBucket>;

    async fn reserve(
        &self,
        request: &ReserveCredits,
        reservation_expires_at: i64,
        now: i64,
    ) -> Result<CreditReservation>;

    async fn commit(
        &self,
        account_id: &str,
        reservation_id: &str,
        now: i64,
    ) -> Result<CreditReservation>;

    async fn release(
        &self,
        account_id: &str,
        reservation_id: &str,
        now: i64,
    ) -> Result<CreditReservation>;

    /// Read the requested account/type balance without persisting expiry. Expired holds
    /// count as available only while their buckets remain valid; use `release_expired`
    /// to persist cleanup and its ledger entries.
    async fn balance(&self, account_id: &str, credit_type: &str, now: i64)
    -> Result<CreditBalance>;

    async fn history(
        &self,
        account_id: &str,
        credit_type: &str,
        query: CreditHistoryQuery,
    ) -> Result<Vec<CreditTransaction>>;

    /// Raise a grant's cumulative revoked amount to `request.amount`.
    ///
    /// Returns `None` when no grant has the requested idempotency key. Revoked credits come out
    /// of the grant's remaining amount first; the rest is recorded as unrecovered and taken from
    /// reservations on that grant when they are released, never returned to the balance.
    ///
    /// The default implementation revokes nothing: it logs a warning and returns `None`, so
    /// refund and dispute webhooks still succeed. Override it to take back refunded or disputed
    /// credits.
    async fn revoke(&self, request: &RevokeCredits, now: i64) -> Result<Option<CreditRevocation>> {
        let _ = now;
        tracing::warn!(
            grant_idempotency_key = %request.grant_idempotency_key,
            idempotency_key = %request.idempotency_key,
            "Credit store does not implement revoke; no credits were revoked"
        );
        Ok(None)
    }

    /// Release expired reservations and restore their bucket allocations.
    async fn release_expired(&self, now: i64, limit: u64) -> Result<u64>;

    /// Store-specific ordering hook used by implementations that expose query planning helpers.
    fn supports_order(&self, _order: ConsumptionOrder) -> bool {
        true
    }
}
