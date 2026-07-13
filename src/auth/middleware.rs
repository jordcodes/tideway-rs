use crate::app::AuthProviderExtension;
#[cfg(feature = "test-auth-bypass")]
use crate::auth::extractors::resolve_test_claims;
use crate::auth::{provider::AuthProvider, token::TokenExtractor};
use crate::error::TidewayError;
use axum::{extract::Request, middleware::Next, response::Response};
use std::marker::PhantomData;
use std::sync::Arc;

fn resolve_provider<P: AuthProvider>(request: &Request) -> Result<P, TidewayError> {
    if let Some(provider) = request.extensions().get::<P>() {
        return Ok(provider.clone());
    }

    if let Some(provider) = request.extensions().get::<AuthProviderExtension>()
        && let Some(typed) = provider.0.downcast_ref::<P>()
    {
        return Ok(typed.clone());
    }

    Err(TidewayError::internal(
        "Auth provider not found in request extensions",
    ))
}

/// Middleware that requires authentication for all routes it wraps
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use tideway::auth::RequireAuth;
///
/// let protected_routes = Router::new()
///     .route("/dashboard", get(dashboard))
///     .route("/profile", get(profile))
///     .layer(axum::middleware::from_fn(RequireAuth::<MyAuthProvider>::middleware));
/// ```
pub struct RequireAuth<P: AuthProvider> {
    _provider: PhantomData<P>,
}

impl<P: AuthProvider> RequireAuth<P> {
    /// Middleware function that requires authentication
    pub async fn middleware(request: Request, next: Next) -> Result<Response, TidewayError> {
        // Get the auth provider from extensions
        let provider = resolve_provider::<P>(&request)?;

        let (parts, body) = request.into_parts();

        #[cfg(feature = "test-auth-bypass")]
        let claims = if let Some(claims) = resolve_test_claims(&parts, &provider).await? {
            Arc::new(claims)
        } else {
            let token = TokenExtractor::from_header(&parts)?;
            Arc::new(provider.verify_token(&token).await?)
        };

        #[cfg(not(feature = "test-auth-bypass"))]
        let claims = {
            let token = TokenExtractor::from_header(&parts)?;
            Arc::new(provider.verify_token(&token).await?)
        };

        let user = provider.load_user(&claims).await?;

        // Validate user
        provider.validate_user(&user).await?;

        // Store user in extensions for downstream handlers
        let mut request = Request::from_parts(parts, body);
        request.extensions_mut().insert(user);
        request.extensions_mut().insert(claims);

        Ok(next.run(request).await)
    }
}

/// Middleware layer builder for adding auth provider to request extensions
///
/// This must be applied before using auth extractors.
///
/// # Example
///
/// ```rust,ignore
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(Extension(my_auth_provider));
/// ```
pub struct AuthLayer<P: AuthProvider> {
    provider: P,
}

impl<P: AuthProvider> AuthLayer<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Middleware function that adds the auth provider to extensions
    pub async fn middleware(&self, mut request: Request, next: Next) -> Response {
        request.extensions_mut().insert(self.provider.clone());
        next.run(request).await
    }
}

impl<P: AuthProvider> Clone for AuthLayer<P> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
        }
    }
}
