//! Storage traits for authentication.
//!
//! These traits define the interface for storing and retrieving authentication data.
//! Implement them for your database layer (SeaORM, SQLx, etc.).

pub mod token;
pub mod user;

pub use token::{MfaTokenStore, RefreshTokenStore};
pub use user::{PasswordResetStore, UserCreator, UserStore, VerificationStore};
