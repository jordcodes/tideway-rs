//! Organization membership middleware.
//!
//! Validates that the authenticated user is a member of the organization
//! specified in their JWT claims.

use super::claims::OrgClaims;
use super::extractors::AuthenticatedUserId;
use crate::error::TidewayError;
use crate::organizations::storage::MembershipStore;
use axum::{extract::Request, middleware::Next, response::Response};
use std::marker::PhantomData;

/// Middleware that requires the user to be a member of their claimed organization.
///
/// This middleware should be applied after authentication middleware.
/// It validates that:
/// 1. The user has organization claims in their token
/// 2. The user is actually a member of the claimed organization
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use tideway::organizations::RequireOrgMembership;
///
/// let org_routes = Router::new()
///     .route("/settings", get(org_settings))
///     .route("/members", get(list_members))
///     .layer(axum::middleware::from_fn(RequireOrgMembership::<MyMembershipStore>::middleware));
/// ```
pub struct RequireOrgMembership<M: MembershipStore> {
    _store: PhantomData<M>,
}

impl<M: MembershipStore + Clone + 'static> RequireOrgMembership<M> {
    /// Middleware function that requires organization membership.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - MembershipStore is not in request extensions
    /// - OrgClaims are not in request extensions
    /// - AuthenticatedUserId is not in request extensions
    /// - User is not a member of the claimed organization
    pub async fn middleware(request: Request, next: Next) -> Result<Response, TidewayError> {
        // Get the membership store from extensions
        let store = request
            .extensions()
            .get::<M>()
            .cloned()
            .ok_or_else(|| {
                TidewayError::internal("MembershipStore not found in request extensions")
            })?;

        // Get org claims from extensions
        let org_claims = request.extensions().get::<OrgClaims>().ok_or_else(|| {
            TidewayError::unauthorized("No organization context in token")
        })?;

        // Get user ID from extensions
        let user_id = request
            .extensions()
            .get::<AuthenticatedUserId>()
            .ok_or_else(|| TidewayError::unauthorized("User not authenticated"))?;

        // Check membership
        let is_member = store
            .is_member(&org_claims.org_id, &user_id.0)
            .await
            .map_err(|e| TidewayError::internal(format!("Failed to check membership: {e}")))?;

        if !is_member {
            return Err(TidewayError::forbidden("Not a member of this organization"));
        }

        Ok(next.run(request).await)
    }
}

/// Layer that adds a MembershipStore to request extensions.
///
/// Apply this layer to make the store available for middleware and extractors.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::OrgStoreLayer;
///
/// let app = Router::new()
///     .route("/org/:org_id/settings", get(settings))
///     .layer(OrgStoreLayer::new(membership_store));
/// ```
#[derive(Clone)]
pub struct OrgStoreLayer<M: MembershipStore> {
    store: M,
}

impl<M: MembershipStore + Clone + 'static> OrgStoreLayer<M> {
    /// Create a new layer with the given store.
    #[must_use]
    pub fn new(store: M) -> Self {
        Self { store }
    }

    /// Middleware function that adds stores to extensions.
    pub async fn middleware(&self, mut request: Request, next: Next) -> Response {
        request.extensions_mut().insert(self.store.clone());
        next.run(request).await
    }
}

/// Middleware that requires a specific permission.
///
/// Generic over the MembershipStore and permission check function.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use tideway::organizations::RequirePermission;
///
/// // Require can_manage_members permission
/// let admin_routes = Router::new()
///     .route("/invite", post(invite_member))
///     .layer(axum::middleware::from_fn(
///         RequirePermission::<MyStore>::can_manage_members()
///     ));
/// ```
pub struct RequirePermission<M: MembershipStore> {
    _store: PhantomData<M>,
}

impl<M> RequirePermission<M>
where
    M: MembershipStore + Clone + 'static,
{
    /// Create a middleware function that checks a custom permission.
    pub fn check<F>(
        check: F,
    ) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, TidewayError>> + Send>>
           + Clone
           + Send
           + Sync
           + 'static
    where
        F: Fn(&M, &M::Role) -> bool + Clone + Send + Sync + 'static,
    {
        move |request: Request, next: Next| {
            let check = check.clone();
            Box::pin(async move {
                // Get the membership store from extensions
                let store = request
                    .extensions()
                    .get::<M>()
                    .cloned()
                    .ok_or_else(|| {
                        TidewayError::internal("MembershipStore not found in request extensions")
                    })?;

                // Get org claims from extensions
                let org_claims =
                    request.extensions().get::<OrgClaims>().ok_or_else(|| {
                        TidewayError::unauthorized("No organization context in token")
                    })?;

                // Get user ID from extensions
                let user_id = request
                    .extensions()
                    .get::<AuthenticatedUserId>()
                    .ok_or_else(|| TidewayError::unauthorized("User not authenticated"))?;

                // Get membership
                let membership = store
                    .get_membership(&org_claims.org_id, &user_id.0)
                    .await
                    .map_err(|e| {
                        TidewayError::internal(format!("Failed to get membership: {e}"))
                    })?
                    .ok_or_else(|| {
                        TidewayError::forbidden("Not a member of this organization")
                    })?;

                // Check permission
                let role = store.membership_role(&membership);
                if !check(&store, &role) {
                    return Err(TidewayError::forbidden("Insufficient permissions"));
                }

                Ok(next.run(request).await)
            })
        }
    }

    /// Middleware that requires `can_manage_members` permission.
    pub fn can_manage_members(
    ) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, TidewayError>> + Send>>
           + Clone
           + Send
           + Sync
           + 'static {
        Self::check(|store, role| store.can_manage_members(role))
    }

    /// Middleware that requires `can_manage_settings` permission.
    pub fn can_manage_settings(
    ) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, TidewayError>> + Send>>
           + Clone
           + Send
           + Sync
           + 'static {
        Self::check(|store, role| store.can_manage_settings(role))
    }

    /// Middleware that requires `can_delete_org` permission.
    pub fn can_delete_org(
    ) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, TidewayError>> + Send>>
           + Clone
           + Send
           + Sync
           + 'static {
        Self::check(|store, role| store.can_delete_org(role))
    }

    /// Middleware that requires `is_owner` permission.
    pub fn is_owner(
    ) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, TidewayError>> + Send>>
           + Clone
           + Send
           + Sync
           + 'static {
        Self::check(|store, role| store.is_owner(role))
    }
}
