//! Billing integration for organizations.
//!
//! This module provides integration with the billing module for:
//! - Making organizations billable entities
//! - Enforcing seat limits based on subscription plans

use crate::billing::seats::SeatManager;
use crate::billing::storage::BillingStore;
use crate::billing::subscription::StripeSubscriptionClient;
use crate::error::Result;
use super::seats::SeatChecker;
use async_trait::async_trait;

/// Helper trait for organizations that want billing integration.
///
/// Implement this on your Organization type to make it compatible
/// with the billing module's `BillableEntity` trait.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::BillableOrganization;
///
/// impl BillableOrganization for MyOrganization {
///     fn billable_id(&self) -> &str {
///         &self.id
///     }
///
///     fn contact_email(&self) -> &str {
///         &self.billing_email
///     }
///
///     fn name(&self) -> &str {
///         &self.name
///     }
/// }
/// ```
pub trait BillableOrganization {
    /// Get the billable ID (typically the organization ID).
    fn billable_id(&self) -> &str;

    /// Get the billing/contact email address.
    fn contact_email(&self) -> &str;

    /// Get the organization name.
    fn name(&self) -> &str;
}

/// Blanket implementation: any `BillableOrganization` is also a `BillableEntity`.
impl<T: BillableOrganization + Send + Sync> crate::billing::BillableEntity for T {
    fn billable_id(&self) -> &str {
        BillableOrganization::billable_id(self)
    }

    fn billable_type(&self) -> &str {
        "org"
    }

    fn email(&self) -> &str {
        BillableOrganization::contact_email(self)
    }

    fn name(&self) -> Option<&str> {
        Some(BillableOrganization::name(self))
    }
}

/// Seat checker implementation using the billing module's `SeatManager`.
///
/// Connects organization membership management to billing-based seat limits.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{BillingSeatChecker, MembershipManager};
/// use tideway::billing::{SeatManager, Plans};
///
/// // Create billing's SeatManager
/// let seat_manager = SeatManager::new(billing_store, stripe_client, plans);
///
/// // Wrap it in BillingSeatChecker
/// let seat_checker = BillingSeatChecker::new(seat_manager);
///
/// // Use with MembershipManager
/// let membership_manager = MembershipManager::new(
///     membership_store,
///     org_store,
///     seat_checker,
/// );
///
/// // Now add_member will check seat limits from the billing plan
/// ```
pub struct BillingSeatChecker<B: BillingStore, C: StripeSubscriptionClient> {
    seat_manager: SeatManager<B, C>,
}

impl<B, C> BillingSeatChecker<B, C>
where
    B: BillingStore,
    C: StripeSubscriptionClient,
{
    /// Create a new billing-based seat checker.
    pub fn new(seat_manager: SeatManager<B, C>) -> Self {
        Self { seat_manager }
    }

    /// Get a reference to the underlying seat manager.
    pub fn seat_manager(&self) -> &SeatManager<B, C> {
        &self.seat_manager
    }
}

#[async_trait]
impl<B, C> SeatChecker for BillingSeatChecker<B, C>
where
    B: BillingStore + Send + Sync,
    C: StripeSubscriptionClient + Send + Sync,
{
    async fn has_seat_available(&self, org_id: &str, current_count: u32) -> Result<bool> {
        self.seat_manager.has_seat_available(org_id, current_count).await
    }

    async fn get_seat_limit(&self, org_id: &str) -> Result<Option<u32>> {
        let info = self.seat_manager.get_seat_info(org_id).await?;
        Ok(Some(info.total_seats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test the BillableOrganization trait
    #[derive(Clone)]
    struct TestOrg {
        id: String,
        name: String,
        email: String,
    }

    impl BillableOrganization for TestOrg {
        fn billable_id(&self) -> &str {
            &self.id
        }

        fn contact_email(&self) -> &str {
            &self.email
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_billable_organization_trait() {
        let org = TestOrg {
            id: "org_123".to_string(),
            name: "Test Org".to_string(),
            email: "test@example.com".to_string(),
        };

        assert_eq!(BillableOrganization::billable_id(&org), "org_123");
        assert_eq!(BillableOrganization::contact_email(&org), "test@example.com");
        assert_eq!(BillableOrganization::name(&org), "Test Org");
    }

    #[test]
    fn test_billable_entity_blanket_impl() {
        use crate::billing::BillableEntity;

        let org = TestOrg {
            id: "org_456".to_string(),
            name: "Another Org".to_string(),
            email: "another@example.com".to_string(),
        };

        // Test via BillableEntity trait
        assert_eq!(BillableEntity::billable_id(&org), "org_456");
        assert_eq!(BillableEntity::billable_type(&org), "org");
        assert_eq!(BillableEntity::email(&org), "another@example.com");
        assert_eq!(BillableEntity::name(&org), Some("Another Org"));
    }
}
