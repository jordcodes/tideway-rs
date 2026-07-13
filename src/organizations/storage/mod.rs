//! Storage traits for organizations.
//!
//! This module provides trait abstractions for organization storage.
//! Users implement these traits for their database layer.

mod audit;
mod invitation;
mod membership;
mod organization;

pub use audit::{OptionalAuditStore, OrgAuditStore, WithAuditStore};
pub use invitation::InvitationStore;
#[cfg(any(test, feature = "organizations-seaorm", feature = "test-organizations"))]
pub(crate) use invitation::hash_invitation_token;
pub use membership::MembershipStore;
pub use organization::OrganizationStore;
