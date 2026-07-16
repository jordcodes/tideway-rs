use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{Result, TidewayError};

use super::{
    CreditBalance, CreditBucket, CreditHistoryQuery, CreditReservation, CreditStore,
    CreditTransaction, GrantCredits, ReserveCredits,
};

const MAX_IDENTIFIER_LENGTH: usize = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 256;
const MAX_METADATA_BYTES: usize = 16 * 1024;

/// High-level credit ledger API.
#[derive(Clone)]
pub struct CreditManager<S> {
    store: S,
    reservation_ttl: Duration,
}

impl<S: CreditStore> CreditManager<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            store,
            reservation_ttl: Duration::from_secs(15 * 60),
        }
    }

    /// Set how long an uncommitted reservation may hold credits.
    #[must_use]
    pub fn with_reservation_ttl(mut self, ttl: Duration) -> Self {
        self.reservation_ttl = ttl;
        self
    }

    pub async fn grant(&self, request: GrantCredits) -> Result<CreditBucket> {
        validate_grant(&request)?;
        self.store.grant(&request, now_timestamp()?).await
    }

    pub async fn reserve(&self, request: ReserveCredits) -> Result<CreditReservation> {
        validate_reservation(&request)?;
        if !self.store.supports_order(request.order) {
            return Err(TidewayError::bad_request(
                "Credit store does not support the requested consumption order",
            ));
        }
        let now = now_timestamp()?;
        let ttl = i64::try_from(self.reservation_ttl.as_secs())
            .map_err(|_| TidewayError::bad_request("Credit reservation TTL is too large"))?;
        if ttl == 0 {
            return Err(TidewayError::bad_request(
                "Credit reservation TTL must be at least one second",
            ));
        }
        let expires_at = now
            .checked_add(ttl)
            .ok_or_else(|| TidewayError::bad_request("Credit reservation expiry overflow"))?;
        self.store.reserve(&request, expires_at, now).await
    }

    pub async fn commit(
        &self,
        account_id: &str,
        reservation_id: &str,
    ) -> Result<CreditReservation> {
        validate_identifier("account_id", account_id)?;
        validate_identifier("reservation_id", reservation_id)?;
        self.store
            .commit(account_id, reservation_id, now_timestamp()?)
            .await
    }

    pub async fn release(
        &self,
        account_id: &str,
        reservation_id: &str,
    ) -> Result<CreditReservation> {
        validate_identifier("account_id", account_id)?;
        validate_identifier("reservation_id", reservation_id)?;
        self.store
            .release(account_id, reservation_id, now_timestamp()?)
            .await
    }

    pub async fn balance(&self, account_id: &str, credit_type: &str) -> Result<CreditBalance> {
        validate_identifier("account_id", account_id)?;
        validate_identifier("credit_type", credit_type)?;
        self.store
            .balance(account_id, credit_type, now_timestamp()?)
            .await
    }

    pub async fn history(
        &self,
        account_id: &str,
        credit_type: &str,
        mut query: CreditHistoryQuery,
    ) -> Result<Vec<CreditTransaction>> {
        validate_identifier("account_id", account_id)?;
        validate_identifier("credit_type", credit_type)?;
        query.limit = query.limit.clamp(1, 200);
        self.store.history(account_id, credit_type, query).await
    }

    pub async fn release_expired(&self, limit: u64) -> Result<u64> {
        self.store
            .release_expired(now_timestamp()?, limit.clamp(1, 1_000))
            .await
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }
}

fn validate_grant(request: &GrantCredits) -> Result<()> {
    validate_identifier("account_id", &request.account_id)?;
    validate_identifier("credit_type", &request.credit_type)?;
    validate_idempotency_key(&request.idempotency_key)?;
    validate_amount(request.amount)?;
    validate_metadata(&request.metadata)
}

fn validate_reservation(request: &ReserveCredits) -> Result<()> {
    validate_identifier("account_id", &request.account_id)?;
    validate_identifier("credit_type", &request.credit_type)?;
    validate_idempotency_key(&request.idempotency_key)?;
    validate_amount(request.amount)?;
    validate_metadata(&request.metadata)
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(TidewayError::bad_request(format!(
            "{field} must contain between 1 and {MAX_IDENTIFIER_LENGTH} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TidewayError::bad_request(format!(
            "{field} cannot contain control characters"
        )));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDEMPOTENCY_KEY_LENGTH {
        return Err(TidewayError::bad_request(format!(
            "idempotency_key must contain between 1 and {MAX_IDEMPOTENCY_KEY_LENGTH} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TidewayError::bad_request(
            "idempotency_key cannot contain control characters",
        ));
    }
    Ok(())
}

fn validate_amount(amount: u64) -> Result<()> {
    if amount == 0 || amount > i64::MAX as u64 {
        return Err(TidewayError::bad_request(
            "Credit amount must be between 1 and i64::MAX",
        ));
    }
    Ok(())
}

fn validate_metadata(metadata: &serde_json::Value) -> Result<()> {
    let size = serde_json::to_vec(metadata)
        .map_err(|error| TidewayError::bad_request(format!("Invalid credit metadata: {error}")))?
        .len();
    if size > MAX_METADATA_BYTES {
        return Err(TidewayError::bad_request(format!(
            "Credit metadata exceeds {MAX_METADATA_BYTES} bytes"
        )));
    }
    Ok(())
}

fn now_timestamp() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TidewayError::internal("System clock is before Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| TidewayError::internal("System timestamp overflow"))
}
