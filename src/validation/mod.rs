//! Request validation support for Tideway applications
//!
//! This module provides type-safe request validation using the `validator` crate.
//! Enable the `validation` feature to use validation extractors.
//!
//! # Example
//!
//! ```rust,no_run
//! use tideway::validation::ValidatedJson;
//! use validator::Validate;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize, Validate)]
//! struct CreateUserRequest {
//!     #[validate(email)]
//!     email: String,
//!     #[validate(length(min = 8))]
//!     password: String,
//! }
//!
//! async fn create_user(
//!     ValidatedJson(req): ValidatedJson<CreateUserRequest>
//! ) -> tideway::Result<axum::Json<serde_json::Value>> {
//!     // req is guaranteed to be valid
//!     Ok(axum::Json(serde_json::json!({"status": "ok"})))
//! }
//! ```

#[cfg(feature = "validation")]
mod extractor;
#[cfg(feature = "validation")]
mod validators;

#[cfg(feature = "validation")]
pub use extractor::{validate_form, validate_json, ValidatedForm, ValidatedJson, ValidatedQuery};
#[cfg(feature = "validation")]
pub use validators::{validate_duration, validate_json_string, validate_phone, validate_slug, validate_uuid};
#[cfg(feature = "validation")]
pub use validator;
