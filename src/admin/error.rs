//! Admin module errors.

use std::fmt;

/// Errors that can occur during admin operations.
#[derive(Debug, Clone)]
pub enum AdminError {
    /// User not found.
    UserNotFound(String),
    /// Organization not found.
    OrganizationNotFound(String),
    /// User is not a platform admin.
    NotAuthorized,
    /// Database or storage error.
    Storage(String),
    /// Invalid parameter.
    InvalidParameter(String),
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound(id) => write!(f, "user not found: {}", id),
            Self::OrganizationNotFound(id) => write!(f, "organization not found: {}", id),
            Self::NotAuthorized => write!(f, "not authorized: admin access required"),
            Self::Storage(msg) => write!(f, "storage error: {}", msg),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {}", msg),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<crate::TidewayError> for AdminError {
    fn from(err: crate::TidewayError) -> Self {
        Self::Storage(err.to_string())
    }
}
