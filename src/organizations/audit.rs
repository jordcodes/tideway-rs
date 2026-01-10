//! Organization audit logging.
//!
//! Provides audit trail for organization operations.

use serde::{Deserialize, Serialize};

/// Audit entry for organization operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAuditEntry {
    /// Unique identifier for this audit entry.
    pub id: String,
    /// The type of event.
    pub event: OrgAuditEvent,
    /// Organization ID this event relates to.
    pub org_id: String,
    /// User ID who performed the action.
    pub actor_id: String,
    /// Target user ID (for membership events).
    pub target_id: Option<String>,
    /// Additional details about the event.
    pub details: Option<String>,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
}

/// Organization audit event types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrgAuditEvent {
    // Organization events
    /// Organization was created.
    OrgCreated,
    /// Organization settings were updated.
    OrgUpdated,
    /// Organization was deleted.
    OrgDeleted,

    // Membership events
    /// A member was added to the organization.
    MemberAdded,
    /// A member was removed from the organization.
    MemberRemoved,
    /// A member left the organization.
    MemberLeft,
    /// A member's role was changed.
    MemberRoleChanged,
    /// Ownership was transferred to another member.
    OwnershipTransferred,

    // Invitation events
    /// An invitation was sent.
    InvitationSent,
    /// An invitation was accepted.
    InvitationAccepted,
    /// An invitation was revoked.
    InvitationRevoked,
}

impl std::fmt::Display for OrgAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OrgCreated => write!(f, "org_created"),
            Self::OrgUpdated => write!(f, "org_updated"),
            Self::OrgDeleted => write!(f, "org_deleted"),
            Self::MemberAdded => write!(f, "member_added"),
            Self::MemberRemoved => write!(f, "member_removed"),
            Self::MemberLeft => write!(f, "member_left"),
            Self::MemberRoleChanged => write!(f, "member_role_changed"),
            Self::OwnershipTransferred => write!(f, "ownership_transferred"),
            Self::InvitationSent => write!(f, "invitation_sent"),
            Self::InvitationAccepted => write!(f, "invitation_accepted"),
            Self::InvitationRevoked => write!(f, "invitation_revoked"),
        }
    }
}

impl OrgAuditEntry {
    /// Create a new audit entry with the given event and organization.
    #[must_use]
    pub fn new(event: OrgAuditEvent, org_id: impl Into<String>, actor_id: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event,
            org_id: org_id.into(),
            actor_id: actor_id.into(),
            target_id: None,
            details: None,
            timestamp: crate::organizations::utils::current_timestamp(),
        }
    }

    /// Set the target user ID.
    #[must_use]
    pub fn with_target(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = Some(target_id.into());
        self
    }

    /// Set additional details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_builder() {
        let entry = OrgAuditEntry::new(OrgAuditEvent::OrgCreated, "org_123", "user_456")
            .with_details("name=Test Org, slug=test-org");

        assert_eq!(entry.event, OrgAuditEvent::OrgCreated);
        assert_eq!(entry.org_id, "org_123");
        assert_eq!(entry.actor_id, "user_456");
        assert!(entry.target_id.is_none());
        assert_eq!(entry.details, Some("name=Test Org, slug=test-org".to_string()));
    }

    #[test]
    fn test_audit_entry_with_target() {
        let entry = OrgAuditEntry::new(OrgAuditEvent::MemberAdded, "org_123", "admin_789")
            .with_target("new_user_456");

        assert_eq!(entry.event, OrgAuditEvent::MemberAdded);
        assert_eq!(entry.target_id, Some("new_user_456".to_string()));
    }

    #[test]
    fn test_event_display() {
        assert_eq!(OrgAuditEvent::OrgCreated.to_string(), "org_created");
        assert_eq!(OrgAuditEvent::MemberAdded.to_string(), "member_added");
        assert_eq!(OrgAuditEvent::OwnershipTransferred.to_string(), "ownership_transferred");
    }

    #[test]
    fn test_event_serialization() {
        let entry = OrgAuditEntry::new(OrgAuditEvent::InvitationSent, "org_1", "user_1");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"event\":\"invitation_sent\""));
    }
}
