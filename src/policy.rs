//! Resource-level authorization policies.
//!
//! Organization roles answer "what can this member do in the org?". Policies
//! answer "can this actor perform this action on this record?" — for example,
//! whether a member may edit a specific project.
//!
//! The building blocks are:
//!
//! - [`Policy`] — per-resource authorization rules, deny-by-default.
//! - [`RolePermissions`] — permission strings (`"projects.update"`) attached to
//!   role names, with `"*"` and `"projects.*"` wildcards.
//! - [`OrgActor`] — the caller's user, organization, and role, used as the
//!   policy subject for organization-scoped resources.
//!
//! # Example
//!
//! ```rust
//! use tideway::policy::{Action, OrgActor, Policy, RolePermissions};
//!
//! struct Project {
//!     organization_id: String,
//!     owner_id: String,
//! }
//!
//! struct ProjectPolicy {
//!     permissions: RolePermissions,
//! }
//!
//! impl Policy<OrgActor, Project> for ProjectPolicy {
//!     fn view(&self, actor: &OrgActor, project: &Project) -> bool {
//!         actor.belongs_to(&project.organization_id)
//!             && actor.can(&self.permissions, "projects.view")
//!     }
//!
//!     fn update(&self, actor: &OrgActor, project: &Project) -> bool {
//!         actor.belongs_to(&project.organization_id)
//!             && (actor.can(&self.permissions, "projects.update")
//!                 || (actor.is(&project.owner_id)
//!                     && actor.can(&self.permissions, "projects.update.own")))
//!     }
//! }
//!
//! let policy = ProjectPolicy {
//!     permissions: RolePermissions::new()
//!         .grant("admin", ["projects.*"])
//!         .grant("member", ["projects.view", "projects.update.own"]),
//! };
//!
//! let project = Project { organization_id: "org_1".into(), owner_id: "user_1".into() };
//! let owner = OrgActor::new("user_1", "org_1", "member");
//! let teammate = OrgActor::new("user_2", "org_1", "member");
//!
//! assert!(policy.authorize(&owner, Action::Update, Some(&project)).is_ok());
//! assert!(policy.authorize(&teammate, Action::Update, Some(&project)).is_err());
//! assert!(policy.authorize(&teammate, Action::View, Some(&project)).is_ok());
//! // Abilities that are not implemented are denied.
//! assert!(policy.authorize(&owner, Action::Delete, Some(&project)).is_err());
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::error::TidewayError;

/// A standard action checked by a [`Policy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// List or search a collection of resources.
    ViewAny,
    /// Read a single resource.
    View,
    /// Create a new resource.
    Create,
    /// Modify an existing resource.
    Update,
    /// Remove an existing resource.
    Delete,
}

impl Action {
    /// Get the conventional string name of the action.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ViewAny => "view_any",
            Self::View => "view",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    /// Whether this action targets a specific record.
    #[must_use]
    pub fn requires_resource(&self) -> bool {
        matches!(self, Self::View | Self::Update | Self::Delete)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resource-level authorization rules for actor type `A` and resource type `R`.
///
/// Every ability is denied unless the policy overrides it. Implement
/// [`Policy::before`] to short-circuit checks, e.g. to allow platform admins
/// everything or to block suspended accounts.
pub trait Policy<A, R> {
    /// Runs before every ability check. Return `Some(allowed)` to decide
    /// without consulting the ability method, or `None` to fall through.
    fn before(&self, _actor: &A, _action: Action) -> Option<bool> {
        None
    }

    /// Whether the actor may list resources.
    fn view_any(&self, _actor: &A) -> bool {
        false
    }

    /// Whether the actor may read `resource`.
    fn view(&self, _actor: &A, _resource: &R) -> bool {
        false
    }

    /// Whether the actor may create a resource.
    fn create(&self, _actor: &A) -> bool {
        false
    }

    /// Whether the actor may modify `resource`.
    fn update(&self, _actor: &A, _resource: &R) -> bool {
        false
    }

    /// Whether the actor may remove `resource`.
    fn delete(&self, _actor: &A, _resource: &R) -> bool {
        false
    }

    /// Check an action. Record-level actions without a record are denied.
    fn allows(&self, actor: &A, action: Action, resource: Option<&R>) -> bool {
        if let Some(decision) = self.before(actor, action) {
            return decision;
        }

        match (action, resource) {
            (Action::ViewAny, _) => self.view_any(actor),
            (Action::Create, _) => self.create(actor),
            (Action::View, Some(resource)) => self.view(actor, resource),
            (Action::Update, Some(resource)) => self.update(actor, resource),
            (Action::Delete, Some(resource)) => self.delete(actor, resource),
            (Action::View | Action::Update | Action::Delete, None) => false,
        }
    }

    /// Check an action, returning [`TidewayError::Forbidden`] when denied.
    ///
    /// # Errors
    ///
    /// Returns a forbidden error if the policy does not allow the action.
    fn authorize(&self, actor: &A, action: Action, resource: Option<&R>) -> crate::Result<()> {
        if self.allows(actor, action, resource) {
            Ok(())
        } else {
            Err(TidewayError::forbidden(format!(
                "Not authorized to {action} this resource"
            )))
        }
    }
}

/// Permission strings attached to role names.
///
/// Permissions are free-form strings, conventionally `"<resource>.<action>"`.
/// A granted `"*"` matches every permission, and a granted `"projects.*"`
/// matches `"projects.update"`, `"projects.update.own"`, and so on.
///
/// # Example
///
/// ```rust
/// use tideway::policy::RolePermissions;
///
/// let permissions = RolePermissions::new()
///     .grant("owner", ["*"])
///     .grant("admin", ["projects.*", "members.invite"])
///     .grant("member", ["projects.view"]);
///
/// assert!(permissions.allows("owner", "billing.manage"));
/// assert!(permissions.allows("admin", "projects.delete"));
/// assert!(!permissions.allows("admin", "billing.manage"));
/// assert!(permissions.allows("member", "projects.view"));
/// assert!(!permissions.allows("member", "projects.update"));
/// assert!(!permissions.allows("guest", "projects.view"));
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RolePermissions {
    roles: BTreeMap<String, BTreeSet<String>>,
}

impl RolePermissions {
    /// Create an empty permission set. Every check is denied until granted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant permissions to a role, keeping any it already has.
    #[must_use]
    pub fn grant<I, P>(mut self, role: impl Into<String>, permissions: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.grant_mut(role, permissions);
        self
    }

    /// Grant permissions to a role in place.
    pub fn grant_mut<I, P>(&mut self, role: impl Into<String>, permissions: I) -> &mut Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.roles
            .entry(role.into())
            .or_default()
            .extend(permissions.into_iter().map(Into::into));
        self
    }

    /// Remove a permission grant from a role. Wildcard grants are only
    /// removed when passed exactly (e.g. `"projects.*"`).
    pub fn revoke(&mut self, role: &str, permission: &str) -> &mut Self {
        if let Some(granted) = self.roles.get_mut(role) {
            granted.remove(permission);
        }
        self
    }

    /// Whether `role` has `permission`, directly or through a wildcard.
    #[must_use]
    pub fn allows(&self, role: &str, permission: &str) -> bool {
        self.roles.get(role).is_some_and(|granted| {
            granted
                .iter()
                .any(|grant| permission_matches(grant, permission))
        })
    }

    /// The permission grants for `role`, as configured (wildcards unexpanded).
    pub fn permissions_for(&self, role: &str) -> impl Iterator<Item = &str> {
        self.roles
            .get(role)
            .into_iter()
            .flat_map(|granted| granted.iter().map(String::as_str))
    }

    /// The configured role names.
    pub fn roles(&self) -> impl Iterator<Item = &str> {
        self.roles.keys().map(String::as_str)
    }
}

fn permission_matches(grant: &str, permission: &str) -> bool {
    if grant == "*" || grant == permission {
        return true;
    }
    grant
        .strip_suffix(".*")
        .and_then(|prefix| permission.strip_prefix(prefix))
        .is_some_and(|rest| rest.starts_with('.'))
}

/// The authenticated caller in an organization-scoped request.
///
/// Used as the actor type for policies on organization-owned resources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgActor {
    /// The authenticated user's ID.
    pub user_id: String,
    /// The organization the request is scoped to.
    pub organization_id: String,
    /// The user's role in that organization (e.g. `"owner"`, `"admin"`, `"member"`).
    pub role: String,
}

impl OrgActor {
    /// Create an actor from user, organization, and role identifiers.
    #[must_use]
    pub fn new(
        user_id: impl Into<String>,
        organization_id: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            organization_id: organization_id.into(),
            role: role.into(),
        }
    }

    /// Whether this actor's role has `permission`.
    #[must_use]
    pub fn can(&self, permissions: &RolePermissions, permission: &str) -> bool {
        permissions.allows(&self.role, permission)
    }

    /// Whether this actor is the user identified by `user_id`.
    #[must_use]
    pub fn is(&self, user_id: &str) -> bool {
        self.user_id == user_id
    }

    /// Whether this actor is acting within `organization_id`.
    #[must_use]
    pub fn belongs_to(&self, organization_id: &str) -> bool {
        self.organization_id == organization_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Doc {
        organization_id: &'static str,
        owner_id: &'static str,
    }

    struct DocPolicy {
        permissions: RolePermissions,
    }

    impl Default for DocPolicy {
        fn default() -> Self {
            Self {
                permissions: RolePermissions::new()
                    .grant("owner", ["*"])
                    .grant("admin", ["docs.*"])
                    .grant(
                        "member",
                        [
                            "docs.view",
                            "docs.create",
                            "docs.update.own",
                            "docs.delete.own",
                        ],
                    ),
            }
        }
    }

    impl DocPolicy {
        fn can_on(&self, actor: &OrgActor, doc: &Doc, action: &str) -> bool {
            actor.belongs_to(doc.organization_id)
                && (actor.can(&self.permissions, &format!("docs.{action}"))
                    || (actor.is(doc.owner_id)
                        && actor.can(&self.permissions, &format!("docs.{action}.own"))))
        }
    }

    impl Policy<OrgActor, Doc> for DocPolicy {
        fn view_any(&self, actor: &OrgActor) -> bool {
            actor.can(&self.permissions, "docs.view")
        }

        fn view(&self, actor: &OrgActor, doc: &Doc) -> bool {
            self.can_on(actor, doc, "view")
        }

        fn create(&self, actor: &OrgActor) -> bool {
            actor.can(&self.permissions, "docs.create")
        }

        fn update(&self, actor: &OrgActor, doc: &Doc) -> bool {
            self.can_on(actor, doc, "update")
        }

        fn delete(&self, actor: &OrgActor, doc: &Doc) -> bool {
            self.can_on(actor, doc, "delete")
        }
    }

    const DOC: Doc = Doc {
        organization_id: "org_1",
        owner_id: "alice",
    };

    #[test]
    fn member_can_edit_own_record_but_not_a_teammates() {
        let policy = DocPolicy::default();
        let alice = OrgActor::new("alice", "org_1", "member");
        let bob = OrgActor::new("bob", "org_1", "member");

        assert!(policy.allows(&alice, Action::Update, Some(&DOC)));
        assert!(policy.allows(&alice, Action::Delete, Some(&DOC)));
        assert!(policy.allows(&bob, Action::View, Some(&DOC)));
        assert!(!policy.allows(&bob, Action::Update, Some(&DOC)));
        assert!(!policy.allows(&bob, Action::Delete, Some(&DOC)));
    }

    #[test]
    fn admin_wildcard_covers_every_record_in_the_org() {
        let policy = DocPolicy::default();
        let admin = OrgActor::new("carol", "org_1", "admin");

        for action in [
            Action::ViewAny,
            Action::View,
            Action::Create,
            Action::Update,
            Action::Delete,
        ] {
            assert!(policy.allows(&admin, action, Some(&DOC)), "{action}");
        }
    }

    #[test]
    fn records_in_other_organizations_are_denied() {
        let policy = DocPolicy::default();
        let outsider = OrgActor::new("alice", "org_2", "owner");

        assert!(!policy.allows(&outsider, Action::View, Some(&DOC)));
        assert!(!policy.allows(&outsider, Action::Update, Some(&DOC)));
    }

    #[test]
    fn unknown_roles_and_missing_records_are_denied() {
        let policy = DocPolicy::default();
        let guest = OrgActor::new("dave", "org_1", "guest");
        let owner = OrgActor::new("alice", "org_1", "owner");

        assert!(!policy.allows(&guest, Action::ViewAny, None));
        assert!(!policy.allows(&guest, Action::View, Some(&DOC)));
        assert!(!policy.allows(&owner, Action::Update, None));
    }

    #[test]
    fn authorize_returns_forbidden_error() {
        let policy = DocPolicy::default();
        let bob = OrgActor::new("bob", "org_1", "member");

        let error = policy
            .authorize(&bob, Action::Delete, Some(&DOC))
            .expect_err("teammate delete should be denied");
        assert!(matches!(error, TidewayError::Forbidden(ref msg) if msg.contains("delete")));
    }

    #[test]
    fn unimplemented_abilities_default_to_deny() {
        struct EmptyPolicy;
        impl Policy<OrgActor, Doc> for EmptyPolicy {}

        let owner = OrgActor::new("alice", "org_1", "owner");
        for action in [
            Action::ViewAny,
            Action::View,
            Action::Create,
            Action::Update,
            Action::Delete,
        ] {
            assert!(!EmptyPolicy.allows(&owner, action, Some(&DOC)), "{action}");
        }
    }

    #[test]
    fn before_hook_short_circuits_abilities() {
        struct SuperuserPolicy;
        impl Policy<OrgActor, Doc> for SuperuserPolicy {
            fn before(&self, actor: &OrgActor, _action: Action) -> Option<bool> {
                (actor.role == "superuser").then_some(true)
            }
        }

        let superuser = OrgActor::new("root", "org_9", "superuser");
        let member = OrgActor::new("alice", "org_1", "member");
        assert!(SuperuserPolicy.allows(&superuser, Action::Delete, Some(&DOC)));
        assert!(!SuperuserPolicy.allows(&member, Action::View, Some(&DOC)));
    }

    #[test]
    fn wildcards_match_only_on_segment_boundaries() {
        let permissions = RolePermissions::new()
            .grant("admin", ["projects.*"])
            .grant("owner", ["*"]);

        assert!(permissions.allows("admin", "projects.update"));
        assert!(permissions.allows("admin", "projects.update.own"));
        assert!(!permissions.allows("admin", "projects"));
        assert!(!permissions.allows("admin", "projectsx.update"));
        assert!(!permissions.allows("admin", "tasks.update"));
        assert!(permissions.allows("owner", "anything.at.all"));
    }

    #[test]
    fn grants_accumulate_and_can_be_revoked() {
        let mut permissions = RolePermissions::new()
            .grant("member", ["projects.view"])
            .grant("member", ["projects.create"]);

        assert!(permissions.allows("member", "projects.view"));
        assert!(permissions.allows("member", "projects.create"));

        permissions.revoke("member", "projects.create");
        assert!(!permissions.allows("member", "projects.create"));
        assert_eq!(
            permissions.permissions_for("member").collect::<Vec<_>>(),
            vec!["projects.view"]
        );
        assert_eq!(permissions.roles().collect::<Vec<_>>(), vec!["member"]);
    }
}
