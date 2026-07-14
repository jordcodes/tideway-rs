//! Curated, stable imports for common Tideway usage.
//!
//! This module is intentionally small to provide a predictable import surface
//! for application code:
//!
//! ```rust,ignore
//! use tideway::prelude::*;
//! ```
//!
//! Note: feature-specific items are re-exported only when the corresponding
//! feature is enabled.

pub use crate::{
    App, AppBuilder, AppContext, AppContextBuilder, Config, ConfigBuilder, MessageResponse, Result,
    RouteModule, TidewayError, ensure, init_tracing, init_tracing_with_config,
};

pub use crate::{module, register_modules, register_optional_modules};

#[cfg(feature = "cache")]
pub use crate::{Cache, CacheExt};

#[cfg(feature = "database")]
pub use crate::{DatabaseConnection, DatabasePool, SeaOrmPool};

#[cfg(feature = "email")]
pub use crate::{ConsoleMailer, Email, Mailer, ResendConfig, ResendMailer, SmtpConfig, SmtpMailer};

#[cfg(feature = "jobs")]
pub use crate::{
    InMemoryJobQueue, Job, JobBackend, JobData, JobQueue, JobRegistry, JobWorker, WorkerPool,
};

#[cfg(feature = "sessions")]
pub use crate::{SessionData, SessionStore};

#[cfg(feature = "validation")]
pub use crate::{
    ValidatedForm, ValidatedJson, ValidatedQuery, validate_form, validate_json, validator,
};

#[cfg(feature = "websocket")]
pub use crate::{
    Connection, ConnectionManager, ConnectionMetrics, Message, Room, WebSocketHandler, ws,
};
