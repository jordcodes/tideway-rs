//! Session management and storage.
//!
//! Provides session handling with in-memory and cookie-based storage backends.

mod config;
mod in_memory;

#[cfg(feature = "sessions")]
mod cookie;

pub use config::SessionConfig;
pub use in_memory::InMemorySessionStore;

#[cfg(feature = "sessions")]
pub use cookie::CookieSessionStore;
