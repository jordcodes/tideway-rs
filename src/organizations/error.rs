//! Organization error types.

use thiserror::Error;

/// Errors that can occur during organization operations.
#[derive(Debug, Error)]
pub enum OrganizationError {
    /// Organization not found.
    #[error("Organization not found: {org_id}")]
    NotFound {
        /// The ID that was not found.
        org_id: String,
    },

    /// Organization slug is already taken.
    #[error("Slug already taken: {slug}")]
    SlugTaken {
        /// The slug that is taken.
        slug: String,
    },

    /// User is not a member of the organization.
    #[error("User is not a member of this organization")]
    NotMember,

    /// User does not have sufficient permissions.
    #[error("Insufficient permissions: requires {required} permission")]
    InsufficientPermission {
        /// The required permission.
        required: String,
    },

    /// Cannot remove the organization owner.
    #[error("Cannot remove organization owner")]
    CannotRemoveOwner,

    /// Organization has reached its seat limit.
    #[error("Organization has reached its seat limit ({current}/{limit})")]
    SeatLimitReached {
        /// Current member count.
        current: u32,
        /// Maximum allowed members.
        limit: u32,
    },

    /// Invitation not found.
    #[error("Invitation not found: {invitation_id}")]
    InvitationNotFound {
        /// The invitation ID.
        invitation_id: String,
    },

    /// Invitation has expired.
    #[error("Invitation has expired")]
    InvitationExpired,

    /// User already has a pending invitation.
    #[error("User already has a pending invitation to this organization")]
    InvitationAlreadyExists,

    /// User is already a member of the organization.
    #[error("User is already a member of this organization")]
    AlreadyMember,

    /// Maximum organizations per user reached.
    #[error("Maximum organizations per user reached ({limit})")]
    MaxOrgsReached {
        /// The maximum allowed organizations.
        limit: u32,
    },

    /// Email verification required.
    #[error("Email verification required to create an organization")]
    EmailNotVerified,

    /// Maximum pending invitations reached.
    #[error("Maximum pending invitations reached for this organization ({limit})")]
    MaxPendingInvitationsReached {
        /// The maximum allowed pending invitations.
        limit: u32,
    },

    /// Invalid invitation token.
    #[error("Invalid or expired invitation token")]
    InvalidToken,

    /// Invalid email format.
    #[error("Invalid email format: {email}")]
    InvalidEmail {
        /// The invalid email address.
        email: String,
    },

    /// Rate limited.
    #[error("Too many requests. Try again in {retry_after_seconds} seconds")]
    RateLimited {
        /// Seconds until retry is allowed.
        retry_after_seconds: u64,
    },

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] crate::error::TidewayError),
}

impl OrganizationError {
    /// Create a not found error.
    pub fn not_found(org_id: impl Into<String>) -> Self {
        Self::NotFound {
            org_id: org_id.into(),
        }
    }

    /// Create a slug taken error.
    pub fn slug_taken(slug: impl Into<String>) -> Self {
        Self::SlugTaken { slug: slug.into() }
    }

    /// Create an insufficient permission error.
    pub fn insufficient_permission(required: impl Into<String>) -> Self {
        Self::InsufficientPermission {
            required: required.into(),
        }
    }

    /// Create a seat limit reached error.
    pub fn seat_limit_reached(current: u32, limit: u32) -> Self {
        Self::SeatLimitReached { current, limit }
    }

    /// Create an invitation not found error.
    pub fn invitation_not_found(invitation_id: impl Into<String>) -> Self {
        Self::InvitationNotFound {
            invitation_id: invitation_id.into(),
        }
    }

    /// Create a max orgs reached error.
    pub fn max_orgs_reached(limit: u32) -> Self {
        Self::MaxOrgsReached { limit }
    }

    /// Create a max pending invitations reached error.
    pub fn max_pending_invitations(limit: u32) -> Self {
        Self::MaxPendingInvitationsReached { limit }
    }

    /// Create an invalid email error.
    pub fn invalid_email(email: impl Into<String>) -> Self {
        Self::InvalidEmail {
            email: email.into(),
        }
    }
}

/// Result type for organization operations.
pub type Result<T> = std::result::Result<T, OrganizationError>;
