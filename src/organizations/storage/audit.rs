//! Organization audit storage trait.

use crate::error::Result;
use crate::organizations::audit::OrgAuditEntry;
use async_trait::async_trait;
use std::future::Future;

/// Trait for organization audit storage.
///
/// Implement this trait to persist audit logs to your database.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::organizations::{OrgAuditStore, OrgAuditEntry};
/// use async_trait::async_trait;
///
/// struct MyAuditStore { db: DatabaseConnection }
///
/// #[async_trait]
/// impl OrgAuditStore for MyAuditStore {
///     async fn record_audit(&self, entry: &OrgAuditEntry) -> Result<()> {
///         self.db.insert_audit_log(entry).await?;
///         Ok(())
///     }
///
///     async fn get_org_audit_log(
///         &self,
///         org_id: &str,
///         limit: usize,
///     ) -> Result<Vec<OrgAuditEntry>> {
///         self.db.query_audit_by_org(org_id, limit).await
///     }
///
///     async fn get_user_audit_log(
///         &self,
///         user_id: &str,
///         limit: usize,
///     ) -> Result<Vec<OrgAuditEntry>> {
///         self.db.query_audit_by_user(user_id, limit).await
///     }
/// }
/// ```
#[async_trait]
pub trait OrgAuditStore: Send + Sync {
    /// Record an audit entry.
    async fn record_audit(&self, entry: &OrgAuditEntry) -> Result<()>;

    /// Get audit log for an organization.
    ///
    /// Returns entries ordered by timestamp descending (newest first).
    async fn get_org_audit_log(&self, org_id: &str, limit: usize) -> Result<Vec<OrgAuditEntry>>;

    /// Get audit log for actions by a user.
    ///
    /// Returns entries where the user was the actor, ordered by timestamp descending.
    async fn get_user_audit_log(&self, user_id: &str, limit: usize) -> Result<Vec<OrgAuditEntry>>;
}

/// Optional audit store trait for fire-and-forget audit logging.
///
/// This trait allows managers to optionally log audit events without
/// blocking on the result. Implementations should handle errors gracefully.
pub trait OptionalAuditStore: Send + Sync + Clone + 'static {
    /// Record an audit entry (fire and forget).
    ///
    /// Errors are logged but not propagated.
    fn record(&self, entry: OrgAuditEntry) -> impl Future<Output = ()> + Send;
}

/// No-op implementation for when audit logging is disabled.
impl OptionalAuditStore for () {
    async fn record(&self, _entry: OrgAuditEntry) {
        // No-op
    }
}

/// Wrapper to enable audit logging with a real store.
#[derive(Clone)]
pub struct WithAuditStore<A: OrgAuditStore + Clone>(pub A);

impl<A: OrgAuditStore + Clone + 'static> OptionalAuditStore for WithAuditStore<A> {
    async fn record(&self, entry: OrgAuditEntry) {
        // Fire and forget - log errors but don't propagate
        if let Err(e) = self.0.record_audit(&entry).await {
            tracing::warn!(
                error = %e,
                event = %entry.event,
                org_id = %entry.org_id,
                "Failed to record audit entry"
            );
        }
    }
}
