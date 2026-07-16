use async_trait::async_trait;

use crate::Result;

use super::{
    ConsumptionOrder, CreditBalance, CreditBucket, CreditHistoryQuery, CreditReservation,
    CreditTransaction, GrantCredits, ReserveCredits,
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

    async fn balance(&self, account_id: &str, credit_type: &str, now: i64)
    -> Result<CreditBalance>;

    async fn history(
        &self,
        account_id: &str,
        credit_type: &str,
        query: CreditHistoryQuery,
    ) -> Result<Vec<CreditTransaction>>;

    /// Release expired reservations and restore their bucket allocations.
    async fn release_expired(&self, now: i64, limit: u64) -> Result<u64>;

    /// Store-specific ordering hook used by implementations that expose query planning helpers.
    fn supports_order(&self, _order: ConsumptionOrder) -> bool {
        true
    }
}
