use crate::error::Result;
use async_trait::async_trait;
use serde::de::DeserializeOwned;

/// Trait for authentication providers
///
/// Implement this trait to integrate any JWT-based auth provider
/// (Outseta, Auth0, Clerk, Supabase, custom, etc.)
///
/// # Type Parameters
///
/// * `Claims` - The JWT claims type (e.g., OutsetaClaims, Auth0Claims)
/// * `User` - The authenticated user type returned to your handlers
///
/// # Example
///
/// ```rust,ignore
/// use tideway::auth::{AuthProvider, JwtVerifier};
///
/// #[derive(Deserialize)]
/// struct MyClaims {
///     sub: String,
///     email: String,
/// }
///
/// struct MyUser {
///     id: String,
///     email: String,
/// }
///
/// struct MyAuthProvider {
///     verifier: JwtVerifier<MyClaims>,
/// }
///
/// #[async_trait]
/// impl AuthProvider for MyAuthProvider {
///     type Claims = MyClaims;
///     type User = MyUser;
///
///     async fn verify_token(&self, token: &str) -> Result<Self::Claims> {
///         let token_data = self.verifier.verify(token).await?;
///         Ok(token_data.claims)
///     }
///
///     async fn load_user(&self, claims: &Self::Claims) -> Result<Self::User> {
///         // Load user from database or return claims as-is
///         Ok(MyUser {
///             id: claims.sub.clone(),
///             email: claims.email.clone(),
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait AuthProvider: Send + Sync + Clone + 'static {
    /// The JWT claims type
    type Claims: DeserializeOwned + Send + Sync;

    /// The authenticated user type
    type User: Send + Sync + Clone;

    /// Verify a JWT token and return the claims
    async fn verify_token(&self, token: &str) -> Result<Self::Claims>;

    /// Load the full user object from claims
    ///
    /// This is where you would typically:
    /// - Query your database for user details
    /// - Create a new user if this is their first login
    /// - Enrich the user object with additional data
    async fn load_user(&self, claims: &Self::Claims) -> Result<Self::User>;

    /// Optional: Validate additional business logic after token verification
    ///
    /// Override this to add custom validation (e.g., check if user is banned)
    async fn validate_user(&self, _user: &Self::User) -> Result<()> {
        Ok(())
    }
}
