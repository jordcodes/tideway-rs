use axum::Router;
use crate::app::AppContext;

/// Trait for composable route modules
///
/// Implement this trait to create modular, reusable route groups.
/// Each module can register its own routes and be composed into the main application.
///
/// # Example
///
/// ```ignore
/// struct UsersModule;
///
/// impl RouteModule for UsersModule {
///     fn routes(&self) -> Router {
///         Router::new()
///             .route("/users", get(list_users))
///             .route("/users/:id", get(get_user))
///     }
/// }
/// ```
pub trait RouteModule {
    /// Returns a router with all routes for this module
    ///
    /// The router should NOT have state applied - state will be applied
    /// by the App when merging modules. Handlers should use `State<AppContext>`
    /// to access the application context.
    ///
    /// Note: Due to Axum's type system, if handlers use `State<AppContext>`,
    /// this will return `Router<AppContext>`. Use `into()` to convert to `Router`
    /// if needed for compatibility.
    fn routes(&self) -> Router<AppContext>
    where
        Self: Sized;

    /// Optional: specify a path prefix for all routes in this module
    fn prefix(&self) -> Option<&str> {
        None
    }

    /// Registers this module's routes into the application router
    ///
    /// Note: The router returned should not have state - state is applied
    /// at the App level via `with_context()`.
    fn register(self, router: Router<AppContext>) -> Router<AppContext>
    where
        Self: Sized,
    {
        let routes = self.routes();

        if let Some(prefix) = self.prefix() {
            router.nest(prefix, routes)
        } else {
            router.merge(routes)
        }
    }
}
