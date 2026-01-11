//! HTTP request/response types and extractors.
//!
//! Provides standardized response wrappers, form handling, query parsing,
//! and the RouteModule trait for organizing routes.

pub mod form;
pub mod path;
pub mod query;
pub mod response;
pub mod routes;

pub use form::{FileConfig, Form, Multipart};
pub use path::PathParams;
pub use query::{PaginationQuery, Query};
pub use response::{
    ApiResponse, CreatedResponse, JsonResponse, MessageResponse, NoContentResponse, PaginatedData,
    PaginationMeta,
};
pub use routes::RouteModule;
