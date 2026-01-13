//! Admin module errors.

use std::fmt;

/// Errors that can occur during admin operations.
#[derive(Debug, Clone)]
pub enum AdminError {
    /// User not found.
    UserNotFound(String),
    /// Organization not found.
    OrganizationNotFound(String),
    /// Platform invitation not found.
    InviteNotFound(String),
    /// User is not a platform admin.
    NotAuthorized,
    /// Database or storage error.
    Storage(String),
    /// Invalid parameter.
    InvalidParameter(String),
    /// Feature not supported/implemented.
    NotSupported(String),
    /// Invitation has expired.
    InviteExpired,
    /// Invitation was already used.
    InviteAlreadyUsed,
    /// Email already has a pending invite.
    InviteAlreadyExists(String),
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound(id) => write!(f, "user not found: {}", id),
            Self::OrganizationNotFound(id) => write!(f, "organization not found: {}", id),
            Self::InviteNotFound(id) => write!(f, "invitation not found: {}", id),
            Self::NotAuthorized => write!(f, "not authorized: admin access required"),
            Self::Storage(msg) => write!(f, "storage error: {}", msg),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {}", msg),
            Self::NotSupported(msg) => write!(f, "not supported: {}", msg),
            Self::InviteExpired => write!(f, "invitation has expired"),
            Self::InviteAlreadyUsed => write!(f, "invitation has already been used"),
            Self::InviteAlreadyExists(email) => {
                write!(f, "pending invitation already exists for: {}", email)
            }
        }
    }
}

impl std::error::Error for AdminError {}

impl From<crate::TidewayError> for AdminError {
    fn from(err: crate::TidewayError) -> Self {
        Self::Storage(err.to_string())
    }
}
