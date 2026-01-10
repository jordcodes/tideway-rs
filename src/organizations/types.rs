//! Organization types and traits.
//!
//! This module provides optional default types that users can use or ignore.
//! The framework is designed to work with any user-defined types.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Default role enum for organizations.
///
/// Users can use this role type or define their own.
/// If using custom roles, implement the permission methods on your
/// [`MembershipStore`](crate::organizations::MembershipStore) trait.
///
/// # Example
///
/// ```rust
/// use tideway::organizations::DefaultOrgRole;
///
/// let role = DefaultOrgRole::Admin;
/// assert!(role.can_manage_members());
/// assert!(!role.can_delete_org());
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultOrgRole {
    /// Organization owner with full permissions.
    Owner,
    /// Administrator with management permissions.
    Admin,
    /// Regular member with basic permissions.
    #[default]
    Member,
}

impl DefaultOrgRole {
    /// Get the string representation of the role.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// Get the hierarchy level (higher = more permissions).
    #[must_use]
    pub fn hierarchy_level(&self) -> u8 {
        match self {
            Self::Owner => 3,
            Self::Admin => 2,
            Self::Member => 1,
        }
    }

    /// Check if this role has at least the permissions of another role.
    #[must_use]
    pub fn has_at_least(&self, other: &Self) -> bool {
        self.hierarchy_level() >= other.hierarchy_level()
    }
}

/// Error returned when parsing a role string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRoleError {
    invalid_value: String,
}

impl fmt::Display for ParseRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid role: '{}' (expected: owner, admin, or member)", self.invalid_value)
    }
}

impl std::error::Error for ParseRoleError {}

impl FromStr for DefaultOrgRole {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            _ => Err(ParseRoleError {
                invalid_value: s.to_string(),
            }),
        }
    }
}

impl fmt::Display for DefaultOrgRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Trait for common role permission operations.
///
/// Implement this trait on your custom role type to get automatic
/// permission checking in the managers.
///
/// # Example
///
/// ```rust
/// use tideway::organizations::OrgRolePermissions;
///
/// #[derive(Clone, PartialEq)]
/// enum MyRole {
///     Owner,
///     Admin,
///     Developer,
///     Viewer,
/// }
///
/// impl OrgRolePermissions for MyRole {
///     fn can_manage_members(&self) -> bool {
///         matches!(self, Self::Owner | Self::Admin)
///     }
///
///     fn can_manage_settings(&self) -> bool {
///         matches!(self, Self::Owner | Self::Admin)
///     }
///
///     fn can_delete_org(&self) -> bool {
///         matches!(self, Self::Owner)
///     }
///
///     fn can_transfer_ownership(&self) -> bool {
///         matches!(self, Self::Owner)
///     }
///
///     fn is_owner(&self) -> bool {
///         matches!(self, Self::Owner)
///     }
/// }
/// ```
pub trait OrgRolePermissions {
    /// Check if this role can manage organization members.
    ///
    /// This includes inviting, removing, and changing roles of members.
    fn can_manage_members(&self) -> bool;

    /// Check if this role can manage organization settings.
    fn can_manage_settings(&self) -> bool;

    /// Check if this role can delete the organization.
    fn can_delete_org(&self) -> bool;

    /// Check if this role can transfer ownership to another member.
    fn can_transfer_ownership(&self) -> bool;

    /// Check if this is the owner role.
    fn is_owner(&self) -> bool;
}

impl OrgRolePermissions for DefaultOrgRole {
    fn can_manage_members(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    fn can_manage_settings(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    fn can_delete_org(&self) -> bool {
        matches!(self, Self::Owner)
    }

    fn can_transfer_ownership(&self) -> bool {
        matches!(self, Self::Owner)
    }

    fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_role_permissions() {
        let owner = DefaultOrgRole::Owner;
        let admin = DefaultOrgRole::Admin;
        let member = DefaultOrgRole::Member;

        // Owner can do everything
        assert!(owner.can_manage_members());
        assert!(owner.can_manage_settings());
        assert!(owner.can_delete_org());
        assert!(owner.can_transfer_ownership());
        assert!(owner.is_owner());

        // Admin can manage but not delete/transfer
        assert!(admin.can_manage_members());
        assert!(admin.can_manage_settings());
        assert!(!admin.can_delete_org());
        assert!(!admin.can_transfer_ownership());
        assert!(!admin.is_owner());

        // Member has no management permissions
        assert!(!member.can_manage_members());
        assert!(!member.can_manage_settings());
        assert!(!member.can_delete_org());
        assert!(!member.can_transfer_ownership());
        assert!(!member.is_owner());
    }

    #[test]
    fn test_role_hierarchy() {
        let owner = DefaultOrgRole::Owner;
        let admin = DefaultOrgRole::Admin;
        let member = DefaultOrgRole::Member;

        assert!(owner.has_at_least(&admin));
        assert!(owner.has_at_least(&member));
        assert!(admin.has_at_least(&member));
        assert!(!admin.has_at_least(&owner));
        assert!(!member.has_at_least(&admin));
    }

    #[test]
    fn test_role_parsing() {
        assert_eq!("owner".parse::<DefaultOrgRole>().unwrap(), DefaultOrgRole::Owner);
        assert_eq!("ADMIN".parse::<DefaultOrgRole>().unwrap(), DefaultOrgRole::Admin);
        assert_eq!("Member".parse::<DefaultOrgRole>().unwrap(), DefaultOrgRole::Member);
        assert!("invalid".parse::<DefaultOrgRole>().is_err());
    }

    #[test]
    fn test_role_display() {
        assert_eq!(DefaultOrgRole::Owner.to_string(), "owner");
        assert_eq!(DefaultOrgRole::Admin.to_string(), "admin");
        assert_eq!(DefaultOrgRole::Member.to_string(), "member");
    }

    #[test]
    fn test_role_serialization() {
        let owner = DefaultOrgRole::Owner;
        let json = serde_json::to_string(&owner).unwrap();
        assert_eq!(json, "\"owner\"");

        let parsed: DefaultOrgRole = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, owner);
    }
}
