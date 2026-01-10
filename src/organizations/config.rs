//! Organization configuration.

/// Configuration for organization management.
///
/// Controls organizational behavior like creation permissions and limits.
/// Role handling is delegated to user's factory functions and store implementations.
///
/// # Example
///
/// ```rust
/// use tideway::organizations::OrganizationConfig;
///
/// let config = OrganizationConfig::new()
///     .allow_user_creation(true)
///     .max_orgs_per_user(Some(5))
///     .require_verified_email(true);
/// ```
#[derive(Clone, Debug)]
pub struct OrganizationConfig {
    /// Whether users can create organizations themselves.
    ///
    /// If false, organizations can only be created administratively.
    pub allow_user_creation: bool,

    /// Maximum organizations a single user can own (None = unlimited).
    pub max_orgs_per_user: Option<u32>,

    /// Require email verification to create an organization.
    pub require_verified_email: bool,
}

impl Default for OrganizationConfig {
    fn default() -> Self {
        Self {
            allow_user_creation: true,
            max_orgs_per_user: Some(5),
            require_verified_email: true,
        }
    }
}

impl OrganizationConfig {
    /// Create a new configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether users can create organizations.
    #[must_use]
    pub fn allow_user_creation(mut self, allow: bool) -> Self {
        self.allow_user_creation = allow;
        self
    }

    /// Set maximum organizations per user.
    #[must_use]
    pub fn max_orgs_per_user(mut self, max: Option<u32>) -> Self {
        self.max_orgs_per_user = max;
        self
    }

    /// Set whether email verification is required.
    #[must_use]
    pub fn require_verified_email(mut self, require: bool) -> Self {
        self.require_verified_email = require;
        self
    }
}

/// Configuration for invitation management.
///
/// # Example
///
/// ```rust
/// use tideway::organizations::InvitationConfig;
///
/// let config = InvitationConfig::new()
///     .expiry_hours(48)
///     .max_pending_per_org(100);
/// ```
#[derive(Clone, Debug)]
pub struct InvitationConfig {
    /// Hours until invitation expires.
    pub expiry_hours: u32,

    /// Maximum pending invitations per organization.
    pub max_pending_per_org: u32,
}

impl Default for InvitationConfig {
    fn default() -> Self {
        Self {
            expiry_hours: 72,
            max_pending_per_org: 50,
        }
    }
}

impl InvitationConfig {
    /// Create a new configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set invitation expiry time in hours.
    #[must_use]
    pub fn expiry_hours(mut self, hours: u32) -> Self {
        self.expiry_hours = hours;
        self
    }

    /// Set maximum pending invitations per organization.
    #[must_use]
    pub fn max_pending_per_org(mut self, max: u32) -> Self {
        self.max_pending_per_org = max;
        self
    }

    /// Get expiry duration in seconds.
    #[must_use]
    pub fn expiry_seconds(&self) -> u64 {
        u64::from(self.expiry_hours) * 3600
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_config_defaults() {
        let config = OrganizationConfig::default();
        assert!(config.allow_user_creation);
        assert_eq!(config.max_orgs_per_user, Some(5));
        assert!(config.require_verified_email);
    }

    #[test]
    fn test_org_config_builder() {
        let config = OrganizationConfig::new()
            .allow_user_creation(false)
            .max_orgs_per_user(None)
            .require_verified_email(false);

        assert!(!config.allow_user_creation);
        assert_eq!(config.max_orgs_per_user, None);
        assert!(!config.require_verified_email);
    }

    #[test]
    fn test_invitation_config_defaults() {
        let config = InvitationConfig::default();
        assert_eq!(config.expiry_hours, 72);
        assert_eq!(config.max_pending_per_org, 50);
    }

    #[test]
    fn test_invitation_config_builder() {
        let config = InvitationConfig::new()
            .expiry_hours(24)
            .max_pending_per_org(100);

        assert_eq!(config.expiry_hours, 24);
        assert_eq!(config.max_pending_per_org, 100);
    }

    #[test]
    fn test_expiry_seconds() {
        let config = InvitationConfig::new().expiry_hours(24);
        assert_eq!(config.expiry_seconds(), 24 * 3600);
    }
}
