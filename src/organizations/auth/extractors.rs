//! Axum extractors for organization context.
//!
//! These extractors provide convenient access to organization and membership
//! context in route handlers.

use super::claims::OrgClaims;
use crate::error::TidewayError;
use crate::organizations::storage::{MembershipStore, OrganizationStore};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::future::Future;
use std::marker::PhantomData;

/// Extract the current organization from JWT claims.
///
/// This extractor:
/// 1. Extracts the org_id from the JWT's custom claims
/// 2. Loads the organization from the store
///
/// Requires the OrganizationStore to be in request extensions.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::CurrentOrg;
///
/// async fn org_handler(
///     CurrentOrg(org): CurrentOrg<MyOrgStore>,
/// ) -> Json<OrgInfo> {
///     Json(OrgInfo {
///         id: org.id,
///         name: org.name,
///     })
/// }
/// ```
pub struct CurrentOrg<O: OrganizationStore>(pub O::Organization, PhantomData<O>);

impl<O: OrganizationStore> CurrentOrg<O> {
    /// Create a new CurrentOrg wrapper.
    pub fn new(org: O::Organization) -> Self {
        Self(org, PhantomData)
    }

    /// Get a reference to the organization.
    pub fn org(&self) -> &O::Organization {
        &self.0
    }

    /// Consume the extractor and return the organization.
    pub fn into_inner(self) -> O::Organization {
        self.0
    }
}

impl<O, S> FromRequestParts<S> for CurrentOrg<O>
where
    O: OrganizationStore + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            // Get the organization store from extensions
            let store = parts
                .extensions
                .get::<O>()
                .cloned()
                .ok_or_else(|| {
                    TidewayError::internal("OrganizationStore not found in request extensions")
                })?;

            // Get org claims from extensions (set by auth middleware)
            let claims = parts
                .extensions
                .get::<OrgClaims>()
                .ok_or_else(|| {
                    TidewayError::unauthorized("No organization context in token")
                })?;

            // Load organization
            let org = store
                .find_by_id(&claims.org_id)
                .await
                .map_err(|e| TidewayError::internal(format!("Failed to load organization: {e}")))?
                .ok_or_else(|| {
                    TidewayError::not_found(format!("Organization not found: {}", claims.org_id))
                })?;

            Ok(CurrentOrg::new(org))
        })
    }
}

/// Extract the current membership context from JWT claims.
///
/// This extractor provides:
/// - The user ID
/// - The organization
/// - The membership record
/// - The role (from membership)
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::CurrentMembership;
///
/// async fn member_handler(
///     membership: CurrentMembership<MyOrgStore, MyMemberStore>,
/// ) -> Json<MemberInfo> {
///     Json(MemberInfo {
///         user_id: membership.user_id,
///         org_name: org_store.org_name(&membership.org),
///         role: membership.role,
///     })
/// }
/// ```
pub struct CurrentMembership<O, M>
where
    O: OrganizationStore,
    M: MembershipStore,
{
    /// The authenticated user's ID.
    pub user_id: String,
    /// The current organization.
    pub org: O::Organization,
    /// The user's membership record.
    pub membership: M::Membership,
    /// The user's role in this organization.
    pub role: M::Role,
}

impl<O, M, S> FromRequestParts<S> for CurrentMembership<O, M>
where
    O: OrganizationStore + Clone + 'static,
    M: MembershipStore + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            // Get stores from extensions
            let org_store = parts
                .extensions
                .get::<O>()
                .cloned()
                .ok_or_else(|| {
                    TidewayError::internal("OrganizationStore not found in request extensions")
                })?;

            let membership_store = parts
                .extensions
                .get::<M>()
                .cloned()
                .ok_or_else(|| {
                    TidewayError::internal("MembershipStore not found in request extensions")
                })?;

            // Get org claims from extensions
            let claims = parts
                .extensions
                .get::<OrgClaims>()
                .ok_or_else(|| {
                    TidewayError::unauthorized("No organization context in token")
                })?;

            // Get user ID from standard claims (assuming it's in extensions)
            // This would typically be set by the auth middleware
            let user_id = parts
                .extensions
                .get::<AuthenticatedUserId>()
                .map(|u| u.0.clone())
                .ok_or_else(|| {
                    TidewayError::unauthorized("User not authenticated")
                })?;

            // Load organization
            let org = org_store
                .find_by_id(&claims.org_id)
                .await
                .map_err(|e| TidewayError::internal(format!("Failed to load organization: {e}")))?
                .ok_or_else(|| {
                    TidewayError::not_found(format!("Organization not found: {}", claims.org_id))
                })?;

            // Load membership
            let membership = membership_store
                .get_membership(&claims.org_id, &user_id)
                .await
                .map_err(|e| TidewayError::internal(format!("Failed to load membership: {e}")))?
                .ok_or_else(|| {
                    TidewayError::forbidden("Not a member of this organization")
                })?;

            // Get role from membership
            let role = membership_store.membership_role(&membership);

            Ok(CurrentMembership {
                user_id,
                org,
                membership,
                role,
            })
        })
    }
}

/// Wrapper for authenticated user ID stored in extensions.
///
/// This should be set by the auth middleware after validating the JWT.
#[derive(Clone, Debug)]
pub struct AuthenticatedUserId(pub String);

impl AuthenticatedUserId {
    /// Create a new authenticated user ID.
    #[must_use]
    pub fn new(user_id: impl Into<String>) -> Self {
        Self(user_id.into())
    }
}
