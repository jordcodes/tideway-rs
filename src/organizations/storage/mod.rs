//! Storage traits for organizations.
//!
//! This module provides trait abstractions for organization storage.
//! Users implement these traits for their database layer.

mod audit;
mod invitation;
mod membership;
mod organization;

pub use audit::{OrgAuditStore, OptionalAuditStore, WithAuditStore};
pub use invitation::InvitationStore;
pub use membership::MembershipStore;
pub use organization::OrganizationStore;
