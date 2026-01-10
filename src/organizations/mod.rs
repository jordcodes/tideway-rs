//! Organizations module for multi-tenant B2B SaaS applications.
//!
//! This module provides flexible organization management with:
//! - **Generic types** - Users define their own Organization, Membership, and Role types
//! - **Trait-based storage** - Implement traits for your database layer
//! - **Optional billing integration** - Connect with billing module for seat limits
//! - **Auth integration** - JWT claims and extractors for org context
//!
//! # Features
//!
//! - `organizations` - Core organization functionality
//! - `test-organizations` - In-memory stores for testing
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::organizations::{
//!     OrganizationStore, MembershipStore, OrganizationManager,
//!     OrganizationConfig, UnlimitedSeats, DefaultOrgRole,
//! };
//!
//! // Define your types
//! struct MyOrganization { /* ... */ }
//! struct MyMembership { /* ... */ }
//!
//! // Implement storage traits for your database
//! impl OrganizationStore for MyStore {
//!     type Organization = MyOrganization;
//!     // ...
//! }
//!
//! // Create manager with your store
//! let manager = OrganizationManager::new(store, membership_store, UnlimitedSeats, config);
//! ```

mod config;
mod error;
mod manager;
mod membership_manager;
mod invitation_manager;
mod seats;
pub mod storage;
mod types;
mod utils;

#[cfg(feature = "billing")]
mod billing;

pub mod auth;

#[cfg(any(test, feature = "test-organizations"))]
pub mod test;

// Configuration exports
pub use config::{InvitationConfig, OrganizationConfig};

// Error exports
pub use error::OrganizationError;

// Manager exports
pub use manager::{MembershipCreateParams, OrgCreateParams, OrganizationManager};
pub use membership_manager::MembershipManager;
pub use invitation_manager::{InvitationCreateParams, InvitationManager};

// Seat checker exports
pub use seats::{SeatChecker, UnlimitedSeats};

// Storage trait exports
pub use storage::{InvitationStore, MembershipStore, OrganizationStore};

// Type exports
pub use types::{DefaultOrgRole, OrgRolePermissions, ParseRoleError};

// Billing exports (when billing feature enabled)
#[cfg(feature = "billing")]
pub use billing::{BillableOrganization, BillingSeatChecker};

// Auth integration exports
pub use auth::{create_org_token_subject, AuthenticatedUserId, CurrentMembership, CurrentOrg, OrgClaims};

// Test exports
#[cfg(any(test, feature = "test-organizations"))]
pub use test::{
    InMemoryOrgStore, TestInvitation, TestMembership, TestOrganization,
};
