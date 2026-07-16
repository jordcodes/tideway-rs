//! Provider-neutral allowances and prepaid credits.
//!
//! Credits are integer product units such as SMS sends, emails, API calls, or AI credits. They
//! are not money and cannot be transferred or redeemed for cash. Applications decide what an
//! operation costs and when its external side effect has succeeded.

mod manager;
mod memory;
#[cfg(feature = "credits-seaorm")]
mod sea_orm_store;
mod storage;
#[cfg(feature = "credits-stripe")]
mod stripe;
mod types;

pub use manager::CreditManager;
pub use memory::MemoryCreditStore;
#[cfg(feature = "credits-seaorm")]
pub use sea_orm_store::SeaOrmCreditStore;
pub use storage::CreditStore;
#[cfg(feature = "credits-stripe")]
pub use stripe::*;
pub use types::{
    ConsumptionOrder, CreditAllocation, CreditBalance, CreditBucket, CreditGrantRequest,
    CreditHistoryQuery, CreditReservation, CreditSource, CreditTransaction, CreditTransactionKind,
    GrantCredits, ReservationStatus, ReserveCredits, SourceBalance,
};
