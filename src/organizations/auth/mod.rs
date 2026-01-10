//! Auth integration for organizations.
//!
//! This module provides JWT claims extension, extractors, and middleware for
//! organization-scoped authentication.

mod claims;
mod extractors;
mod middleware;

pub use claims::{create_org_token_subject, OrgClaims};
pub use extractors::{AuthenticatedUserId, CurrentMembership, CurrentOrg};
pub use middleware::{OrgStoreLayer, RequireOrgMembership, RequirePermission};
