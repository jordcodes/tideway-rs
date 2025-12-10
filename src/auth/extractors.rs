use crate::auth::{provider::AuthProvider, token::TokenExtractor};
use crate::error::TidewayError;
use axum::{extract::FromRequestParts, http::request::Parts};
use std::future::Future;

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
            let provider = parts
                .extensions
                .get::<P>()
                .ok_or_else(|| {
                    TidewayError::internal("Auth provider not found in request extensions")
                })?
                .clone();

            // Test bypass: Check for X-Test-User header
            #[cfg(feature = "test-auth-bypass")]
            {
                if let Some(_test_user_id) = parts.headers.get("X-Test-User-Id") {
                    // In test mode, we skip token verification
                    // Note: This requires P::Claims to implement Default trait
                    // Users must ensure their Claims type implements Default when using test-auth-bypass
                    return Err(TidewayError::internal(
                        "Test auth bypass requires Claims to implement Default trait. \
                        Implement Default for your Claims type or disable test-auth-bypass feature."
                    ));
                }
            }

            // Extract token from Authorization header
            let token = TokenExtractor::from_header(parts)?;

            // Verify token and get claims
            let claims = provider.verify_token(&token).await?;

            // Load user from claims
            let user = provider.load_user(&claims).await?;

            // Validate user (optional business logic)
            provider.validate_user(&user).await?;

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
            let provider = match parts.extensions.get::<P>() {
                Some(p) => p.clone(),
                None => return Ok(OptionalAuth(None)),
            };

            // Try to extract token
            let token = match TokenExtractor::from_header(parts) {
                Ok(t) => t,
                Err(_) => return Ok(OptionalAuth(None)),
            };

            // Try to verify and load user
            match provider.verify_token(&token).await {
                Ok(claims) => match provider.load_user(&claims).await {
                    Ok(user) => {
                        // Validate user
                        if provider.validate_user(&user).await.is_ok() {
                            Ok(OptionalAuth(Some(user)))
                        } else {
                            Ok(OptionalAuth(None))
                        }
                    }
                    Err(_) => Ok(OptionalAuth(None)),
                },
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
            let provider = parts
                .extensions
                .get::<P>()
                .ok_or_else(|| {
                    TidewayError::internal("Auth provider not found in request extensions")
                })?
                .clone();

            let token = TokenExtractor::from_header(parts)?;
            let claims = provider.verify_token(&token).await?;

            Ok(Claims(claims))
        })
    }
}
