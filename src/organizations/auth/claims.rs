//! JWT claims for organization context.

use crate::auth::TokenSubject;
use serde::{Deserialize, Serialize};

/// Extended claims including organization context.
///
/// Stored in JWT - role stored as string for flexibility with custom role types.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::OrgClaims;
///
/// let claims = OrgClaims {
///     org_id: "org_123".to_string(),
///     org_role: "admin".to_string(),
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgClaims {
    /// The organization ID this token is scoped to.
    pub org_id: String,

    /// String representation of the user's role in this organization.
    ///
    /// This is stored as a string to support custom role types.
    /// Use your role type's `to_string()` method when creating the token.
    pub org_role: String,
}

impl OrgClaims {
    /// Create new organization claims.
    pub fn new(org_id: impl Into<String>, org_role: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            org_role: org_role.into(),
        }
    }
}

/// Helper to create a token subject with organization context.
///
/// Role is serialized to string for JWT storage, allowing any role type
/// that implements `ToString`.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{create_org_token_subject, DefaultOrgRole};
/// use tideway::auth::JwtIssuer;
///
/// let membership = membership_manager.get_membership(&org_id, &user_id).await?
///     .ok_or(Error::NotMember)?;
///
/// // Create token subject with organization context
/// let subject = create_org_token_subject(
///     &user_id,
///     &org_id,
///     &membership.role,
/// );
///
/// // Issue the token
/// let tokens = jwt_issuer.issue(subject, false)?;
/// ```
pub fn create_org_token_subject<'a, R: ToString>(
    user_id: &'a str,
    org_id: &str,
    role: &R,
) -> TokenSubject<'a, OrgClaims> {
    TokenSubject::new(user_id).with_custom(OrgClaims::new(org_id, role.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::organizations::DefaultOrgRole;

    #[test]
    fn test_org_claims_serialization() {
        let claims = OrgClaims::new("org_123", "admin");
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("org_123"));
        assert!(json.contains("admin"));

        let parsed: OrgClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.org_id, "org_123");
        assert_eq!(parsed.org_role, "admin");
    }

    #[test]
    fn test_create_org_token_subject() {
        let subject = create_org_token_subject("user_123", "org_456", &DefaultOrgRole::Admin);
        assert_eq!(subject.user_id, "user_123");
    }
}
