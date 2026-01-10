//! Seat availability checking.
//!
//! This module provides abstractions for checking seat availability,
//! decoupling organization management from billing details.

use crate::error::Result;
use async_trait::async_trait;

/// Abstraction for seat availability checking.
///
/// This trait decouples membership management from billing details.
/// Implement this to connect with your billing system's seat limits.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::SeatChecker;
/// use async_trait::async_trait;
///
/// struct MySeatChecker {
///     billing_service: BillingService,
/// }
///
/// #[async_trait]
/// impl SeatChecker for MySeatChecker {
///     async fn has_seat_available(&self, org_id: &str, current_count: u32) -> Result<bool> {
///         let limit = self.billing_service.get_seat_limit(org_id).await?;
///         Ok(limit.map_or(true, |l| current_count < l))
///     }
///
///     async fn get_seat_limit(&self, org_id: &str) -> Result<Option<u32>> {
///         self.billing_service.get_seat_limit(org_id).await
///     }
/// }
/// ```
#[async_trait]
pub trait SeatChecker: Send + Sync {
    /// Check if the organization has room for another member.
    ///
    /// # Arguments
    ///
    /// * `org_id` - The organization ID
    /// * `current_count` - Current member count (including pending invitations)
    ///
    /// # Returns
    ///
    /// `true` if another member can be added, `false` if seat limit reached.
    async fn has_seat_available(&self, org_id: &str, current_count: u32) -> Result<bool>;

    /// Get the current seat limit for an organization.
    ///
    /// Returns `None` if there is no limit (unlimited seats).
    async fn get_seat_limit(&self, org_id: &str) -> Result<Option<u32>>;
}

/// No-op implementation for applications without billing.
///
/// All seat checks pass - unlimited members are allowed.
///
/// # Example
///
/// ```rust
/// use tideway::organizations::{OrganizationManager, UnlimitedSeats, OrganizationConfig};
///
/// // Use UnlimitedSeats when you don't have billing-based seat limits
/// // let manager = OrganizationManager::new(
/// //     org_store,
/// //     membership_store,
/// //     UnlimitedSeats,
/// //     OrganizationConfig::default(),
/// // );
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct UnlimitedSeats;

impl UnlimitedSeats {
    /// Create a new unlimited seats checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SeatChecker for UnlimitedSeats {
    async fn has_seat_available(&self, _org_id: &str, _current_count: u32) -> Result<bool> {
        Ok(true)
    }

    async fn get_seat_limit(&self, _org_id: &str) -> Result<Option<u32>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unlimited_seats() {
        let checker = UnlimitedSeats::new();

        // Should always have seats available
        assert!(checker.has_seat_available("org_1", 0).await.unwrap());
        assert!(checker.has_seat_available("org_1", 100).await.unwrap());
        assert!(checker.has_seat_available("org_1", 10000).await.unwrap());

        // Should always return no limit
        assert_eq!(checker.get_seat_limit("org_1").await.unwrap(), None);
    }
}
