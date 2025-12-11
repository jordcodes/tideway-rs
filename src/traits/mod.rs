//! Trait definitions for extensible components
//!
//! These traits allow users to swap implementations or provide their own
//! for database connections, caching, session management, background jobs, and email.

#[allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds properly
#[cfg(feature = "database")]
pub mod database;

#[cfg(feature = "cache")]
pub mod cache;

#[cfg(feature = "sessions")]
pub mod session;

#[cfg(feature = "jobs")]
pub mod job;

#[cfg(feature = "email")]
pub mod mailer;
