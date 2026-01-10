//! Auth integration for organizations.
//!
//! This module provides JWT claims extension and extractors for
//! organization-scoped authentication.

mod claims;
mod extractors;

pub use claims::{create_org_token_subject, OrgClaims};
pub use extractors::{CurrentMembership, CurrentOrg};
