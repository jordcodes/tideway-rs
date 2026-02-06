use crate::app::AuthProviderExtension;
use crate::auth::{provider::AuthProvider, token::TokenExtractor};
use crate::error::TidewayError;
use axum::{extract::FromRequestParts, http::request::Parts};
use std::future::Future;
use std::sync::Arc;

fn resolve_provider<P: AuthProvider>(parts: &Parts) -> Result<P, TidewayError> {
    if let Some(provider) = parts.extensions.get::<P>() {
        return Ok(provider.clone());
    }

    if let Some(provider) = parts.extensions.get::<AuthProviderExtension>() {
        if let Some(typed) = provider.0.downcast_ref::<P>() {
            return Ok(typed.clone());
        }
    }

    Err(TidewayError::internal(
        "Auth provider not found in request extensions",
    ))
}

/// Trait for users that can be administrators.
///
/// Implement this trait on your user type to enable admin-only route protection.
///
/// # Example
///
/// ```rust,ignore
/// impl AdminUser for User {
///     fn is_admin(&self) -> bool {
///         self.is_platform_admin
///     }
/// }
/// ```
pub trait AdminUser {
    /// Returns true if this user has administrator privileges.
    fn is_admin(&self) -> bool;
}

/// Axum extractor for authenticated users
///
/// Use this in your handler to require authentication.
/// The request will be rejected with 401 if authentication fails.
///
/// # Type Parameters
///
/// * `P` - The AuthProvider type
///
/// # Example
///
/// ```rust,ignore
/// async fn protected_handler(
///     AuthUser(user): AuthUser<MyAuthProvider>
/// ) -> Json<UserData> {
///     Json(UserData {
///         id: user.id,
///         email: user.email,
///     })
/// }
/// ```
pub struct AuthUser<P: AuthProvider>(pub P::User);

impl<P, S> FromRequestParts<S> for AuthUser<P>
where
    P: AuthProvider,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            // Extract the auth provider from the app state
            let provider = resolve_provider::<P>(parts)?;

            // Reuse cached user if already loaded by middleware
            if let Some(user) = parts.extensions.get::<P::User>().cloned() {
                provider.validate_user(&user).await?;
                return Ok(AuthUser(user));
            }

            // Test bypass: Check for X-Test-User header
            #[cfg(feature = "test-auth-bypass")]
            {
                if let Some(_test_user_id) = parts.headers.get("X-Test-User-Id") {
                    // In test mode, we skip token verification
                    // Note: This requires P::Claims to implement Default trait
                    // Users must ensure their Claims type implements Default when using test-auth-bypass
                    return Err(TidewayError::internal(
                        "Test auth bypass requires Claims to implement Default trait. \
                        Implement Default for your Claims type or disable test-auth-bypass feature.",
                    ));
                }
            }

            // Extract token from Authorization header
            let token = TokenExtractor::from_header(parts)?;

            // Verify token and get claims
            let claims = Arc::new(provider.verify_token(&token).await?);

            // Load user from claims
            let user = provider.load_user(&claims).await?;

            // Validate user (optional business logic)
            provider.validate_user(&user).await?;

            // Cache user + claims for downstream extractors in the same request.
            parts.extensions.insert(user.clone());
            // Cache verified claims after successful user validation
            parts.extensions.insert(Arc::clone(&claims));

            Ok(AuthUser(user))
        })
    }
}

/// Axum extractor for optional authentication
///
/// Use this when authentication is optional.
/// Returns Some(user) if authenticated, None if not.
/// Does not reject the request if authentication fails.
///
/// # Example
///
/// ```rust,ignore
/// async fn handler(
///     OptionalAuth(user): OptionalAuth<MyAuthProvider>
/// ) -> Json<Response> {
///     if let Some(user) = user {
///         Json(Response::Authenticated { user_id: user.id })
///     } else {
///         Json(Response::Anonymous)
///     }
/// }
/// ```
pub struct OptionalAuth<P: AuthProvider>(pub Option<P::User>);

impl<P, S> FromRequestParts<S> for OptionalAuth<P>
where
    P: AuthProvider,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            // Try to get the auth provider
            let provider = match resolve_provider::<P>(parts) {
                Ok(provider) => provider,
                Err(_) => return Ok(OptionalAuth(None)),
            };

            // Reuse cached user if already loaded by middleware
            if let Some(user) = parts.extensions.get::<P::User>().cloned() {
                if provider.validate_user(&user).await.is_ok() {
                    return Ok(OptionalAuth(Some(user)));
                }
                return Ok(OptionalAuth(None));
            }

            // Try to extract token
            let token = match TokenExtractor::from_header(parts) {
                Ok(t) => t,
                Err(_) => return Ok(OptionalAuth(None)),
            };

            // Try to verify and load user
            match provider.verify_token(&token).await {
                Ok(claims) => {
                    let claims = Arc::new(claims);
                    match provider.load_user(&claims).await {
                        Ok(user) => {
                            // Validate user
                            if provider.validate_user(&user).await.is_ok() {
                                // Cache user + claims for downstream extractors in the same request.
                                parts.extensions.insert(user.clone());
                                // Cache verified claims after successful user validation
                                parts.extensions.insert(Arc::clone(&claims));
                                Ok(OptionalAuth(Some(user)))
                            } else {
                                Ok(OptionalAuth(None))
                            }
                        }
                        Err(_) => Ok(OptionalAuth(None)),
                    }
                }
                Err(_) => Ok(OptionalAuth(None)),
            }
        })
    }
}

/// Helper extractor for accessing just the JWT claims without loading the full user
///
/// Useful when you only need to verify authentication but don't need
/// to query the database for user details.
///
/// # Example
///
/// ```rust,ignore
/// async fn handler(
///     Claims(claims): Claims<MyAuthProvider>
/// ) -> String {
///     format!("User ID: {}", claims.sub)
/// }
/// ```
pub struct Claims<P: AuthProvider>(pub P::Claims);

impl<P, S> FromRequestParts<S> for Claims<P>
where
    P: AuthProvider,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            let provider = resolve_provider::<P>(parts)?;

            let token = TokenExtractor::from_header(parts)?;
            let claims = provider.verify_token(&token).await?;

            Ok(Claims(claims))
        })
    }
}

/// Axum extractor that reuses cached claims if available.
///
/// This avoids re-verifying the token when claims were already verified earlier
/// in the same request (e.g., by auth middleware).
pub struct ClaimsRef<P: AuthProvider>(pub Arc<P::Claims>);

impl<P, S> FromRequestParts<S> for ClaimsRef<P>
where
    P: AuthProvider,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            if let Some(claims) = parts.extensions.get::<Arc<P::Claims>>() {
                return Ok(ClaimsRef(Arc::clone(claims)));
            }

            let provider = resolve_provider::<P>(parts)?;

            let token = TokenExtractor::from_header(parts)?;
            let claims = Arc::new(provider.verify_token(&token).await?);
            parts.extensions.insert(Arc::clone(&claims));

            Ok(ClaimsRef(claims))
        })
    }
}

/// Axum extractor for admin-only routes.
///
/// Use this in your handler to require admin privileges.
/// The request will be rejected with 401 if not authenticated,
/// or 403 if authenticated but not an admin.
///
/// Requires your user type to implement the [`AdminUser`] trait.
///
/// # Type Parameters
///
/// * `P` - The AuthProvider type (user type must implement AdminUser)
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::{RequireAdmin, AdminUser};
///
/// impl AdminUser for User {
///     fn is_admin(&self) -> bool {
///         self.is_platform_admin
///     }
/// }
///
/// async fn admin_only_handler(
///     RequireAdmin(user): RequireAdmin<MyAuthProvider>
/// ) -> Json<AdminData> {
///     // Only admins can reach here
///     Json(AdminData { ... })
/// }
/// ```
pub struct RequireAdmin<P: AuthProvider>(pub P::User)
where
    P::User: AdminUser;

impl<P, S> FromRequestParts<S> for RequireAdmin<P>
where
    P: AuthProvider,
    P::User: AdminUser,
    S: Send + Sync,
{
    type Rejection = TidewayError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async move {
            // Extract the auth provider from the app state
            let provider = resolve_provider::<P>(parts)?;

            // Reuse cached user if already loaded by middleware
            if let Some(user) = parts.extensions.get::<P::User>().cloned() {
                provider.validate_user(&user).await?;
                if !user.is_admin() {
                    return Err(TidewayError::forbidden("Admin privileges required"));
                }
                return Ok(RequireAdmin(user));
            }

            // Extract token from Authorization header
            let token = TokenExtractor::from_header(parts)?;

            // Verify token and get claims
            let claims = Arc::new(provider.verify_token(&token).await?);

            // Load user from claims
            let user = provider.load_user(&claims).await?;

            // Validate user (optional business logic)
            provider.validate_user(&user).await?;

            // Cache verified claims after successful user validation
            parts.extensions.insert(Arc::clone(&claims));

            // Check admin privileges
            if !user.is_admin() {
                return Err(TidewayError::forbidden("Admin privileges required"));
            }

            Ok(RequireAdmin(user))
        })
    }
}
