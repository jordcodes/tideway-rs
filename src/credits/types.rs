use serde::{Deserialize, Serialize};

/// Origin of a bucket of credits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditSource {
    /// Recurring allowance included with a plan.
    Allowance,
    /// One-time credits bought by the customer.
    Purchased,
    /// Manually or automatically granted promotional credits.
    Promotional,
}

impl CreditSource {
    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allowance => "allowance",
            Self::Purchased => "purchased",
            Self::Promotional => "promotional",
        }
    }

    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "allowance" => Some(Self::Allowance),
            "purchased" => Some(Self::Purchased),
            "promotional" => Some(Self::Promotional),
            _ => None,
        }
    }
}

/// Ordering used when a reservation spans multiple credit buckets.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumptionOrder {
    /// Spend allowance, then promotional, then purchased credits. Within each source, the bucket
    /// expiring soonest is consumed first.
    #[default]
    AllowanceFirst,
    /// Spend the bucket expiring soonest regardless of source, with persistent buckets last.
    EarliestExpiry,
}

impl ConsumptionOrder {
    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AllowanceFirst => "allowance_first",
            Self::EarliestExpiry => "earliest_expiry",
        }
    }

    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "allowance_first" => Some(Self::AllowanceFirst),
            "earliest_expiry" => Some(Self::EarliestExpiry),
            _ => None,
        }
    }
}

/// Request to grant a new bucket of credits.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GrantCredits {
    pub account_id: String,
    pub credit_type: String,
    pub amount: u64,
    pub source: CreditSource,
    /// Unix timestamp. `None` creates a persistent bucket.
    pub expires_at: Option<i64>,
    /// Stable operation identifier. Retrying it returns the original grant.
    pub idempotency_key: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Compatibility alias that reads naturally in request-oriented APIs.
pub type CreditGrantRequest = GrantCredits;

/// Request to reserve credits before an external side effect.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReserveCredits {
    pub account_id: String,
    pub credit_type: String,
    pub amount: u64,
    pub idempotency_key: String,
    #[serde(default)]
    pub order: ConsumptionOrder,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Request to take back credits from an earlier grant, such as after a refund or dispute.
///
/// `amount` is the cumulative total that should be revoked from the grant, not a delta.
/// Repeating a request, or sending an older smaller total, changes nothing, so a retried or
/// out-of-order webhook cannot revoke twice.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RevokeCredits {
    /// [`GrantCredits::idempotency_key`] of the grant to revoke. It must identify exactly one
    /// grant across all accounts and credit types.
    pub grant_idempotency_key: String,
    /// Cumulative credits to revoke from the grant.
    pub amount: RevocationAmount,
    /// Stable operation identifier recorded on the ledger entry.
    pub idempotency_key: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Cumulative amount of a grant to revoke.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationAmount {
    /// A number of credits, capped to the original grant.
    Credits(u64),
    /// A share of the original grant, rounded up and capped to the whole grant. Use it to
    /// revoke in proportion to a partial refund.
    Fraction { numerator: u64, denominator: u64 },
}

impl RevocationAmount {
    /// The whole grant.
    pub const ALL: Self = Self::Fraction {
        numerator: 1,
        denominator: 1,
    };

    /// Resolve the cumulative credits to revoke from a grant of `original` credits.
    #[must_use]
    pub fn resolve(self, original: u64) -> u64 {
        match self {
            Self::Credits(credits) => credits.min(original),
            Self::Fraction {
                numerator,
                denominator,
            } => {
                if denominator == 0 {
                    return 0;
                }
                let share = (u128::from(original) * u128::from(numerator))
                    .div_ceil(u128::from(denominator));
                u64::try_from(share).unwrap_or(u64::MAX).min(original)
            }
        }
    }
}

/// Revocation state of one grant after [`RevokeCredits`] was applied.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditRevocation {
    /// The revoked grant, with its updated remaining amount.
    pub bucket: CreditBucket,
    /// Cumulative credits revoked from the grant.
    pub revoked_amount: u64,
    /// Revoked credits not yet taken back because they are held by open reservations or were
    /// already spent. Held credits are taken back when their reservation is released; credits
    /// that were committed cannot be recovered.
    pub unrecovered_amount: u64,
}

/// One durable bucket created by a grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditBucket {
    pub id: String,
    pub account_id: String,
    pub credit_type: String,
    pub source: CreditSource,
    pub original_amount: u64,
    pub remaining_amount: u64,
    pub expires_at: Option<i64>,
    pub idempotency_key: String,
    pub created_at: i64,
}

/// Lifecycle of a credit reservation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Committed,
    Released,
}

impl ReservationStatus {
    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::Released => "released",
        }
    }

    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(Self::Reserved),
            "committed" => Some(Self::Committed),
            "released" => Some(Self::Released),
            _ => None,
        }
    }
}

/// Portion of a reservation taken from one bucket.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditAllocation {
    pub bucket_id: String,
    pub amount: u64,
}

/// Credits held for an application operation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CreditReservation {
    pub id: String,
    pub account_id: String,
    pub credit_type: String,
    pub amount: u64,
    pub status: ReservationStatus,
    pub idempotency_key: String,
    pub order: ConsumptionOrder,
    pub allocations: Vec<CreditAllocation>,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Available balance for one source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceBalance {
    pub source: CreditSource,
    pub available: u64,
}

/// Current balance for an account and credit type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditBalance {
    pub account_id: String,
    pub credit_type: String,
    pub available: u64,
    pub reserved: u64,
    pub by_source: Vec<SourceBalance>,
}

/// Audit-ledger event kind.
///
/// New kinds may be added in minor releases; match with a wildcard arm.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CreditTransactionKind {
    Grant,
    Reserve,
    Commit,
    Release,
    /// Credits removed from a grant after its payment was refunded or disputed.
    Revoke,
}

impl CreditTransactionKind {
    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Reserve => "reserve",
            Self::Commit => "commit",
            Self::Release => "release",
            Self::Revoke => "revoke",
        }
    }

    #[cfg(feature = "credits-seaorm")]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "grant" => Some(Self::Grant),
            "reserve" => Some(Self::Reserve),
            "commit" => Some(Self::Commit),
            "release" => Some(Self::Release),
            "revoke" => Some(Self::Revoke),
            _ => None,
        }
    }
}

/// Append-only audit transaction.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CreditTransaction {
    pub id: String,
    pub account_id: String,
    pub credit_type: String,
    pub kind: CreditTransactionKind,
    pub amount: u64,
    pub bucket_id: Option<String>,
    pub reservation_id: Option<String>,
    pub idempotency_key: String,
    pub created_at: i64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Pagination for transaction history.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditHistoryQuery {
    pub offset: u64,
    pub limit: u64,
}

impl Default for CreditHistoryQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}
