//! Admin module for platform administration.
//!
//! This module provides traits and types for SaaS platform administration.
//! It allows platform owners to manage users, organizations, view stats,
//! and perform administrative actions like impersonation.
//!
//! # Architecture
//!
//! Tideway follows a modular architecture where the framework provides
//! traits and types, while applications implement the actual routes and
//! storage.
//!
//! - **tideway**: Provides `AdminStore` trait and shared types
//! - **your app**: Implements the trait and defines admin routes
//!
//! # Features
//!
//! - `admin` - Core admin functionality (traits and types)
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::admin::{AdminStore, AdminError, ListUsersParams, PaginatedResult, PlatformStats};
//! use async_trait::async_trait;
//!
//! // Implement the AdminStore trait for your database
//! struct SeaOrmAdminStore {
//!     db: Arc<DatabaseConnection>,
//! }
//!
//! #[async_trait]
//! impl AdminStore for SeaOrmAdminStore {
//!     type User = user::Model;
//!     type Organization = organization::Model;
//!
//!     async fn is_platform_admin(&self, user_id: &str) -> Result<bool, AdminError> {
//!         let user = user::Entity::find_by_id(user_id)
//!             .one(self.db.as_ref())
//!             .await
//!             .map_err(|e| AdminError::Storage(e.to_string()))?;
//!         Ok(user.map(|u| u.is_platform_admin).unwrap_or(false))
//!     }
//!
//!     async fn list_users(&self, params: ListUsersParams)
//!         -> Result<PaginatedResult<Self::User>, AdminError>
//!     {
//!         // Implement user listing with pagination
//!     }
//!
//!     // ... implement other required methods
//! }
//!
//! // Define your admin routes in your application
//! pub fn admin_routes() -> Router {
//!     Router::new()
//!         .route("/stats", get(get_stats))
//!         .route("/users", get(list_users))
//!         .route("/users/:id", get(get_user))
//!         // ... other routes
//!         .layer(from_fn(require_admin))
//! }
//! ```

mod error;
mod storage;
mod types;

pub use error::AdminError;
pub use storage::AdminStore;
pub use types::{
    AuditEntry, AuditLogParams, ListOrgsParams, ListUsersParams, PaginatedResult, PlatformStats,
    SortOrder, UpdateUser,
};
