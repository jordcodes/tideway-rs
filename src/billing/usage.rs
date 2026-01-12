//! Usage-based billing for metered subscriptions.
//!
//! Provides functionality for reporting usage to Stripe for metered billing plans.
//! This is useful for API calls, storage, compute time, or any usage-based pricing.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::billing::{UsageManager, UsageRecord, UsageAction};
//!
//! let usage_manager = UsageManager::new(billing_store, stripe_client);
//!
//! // Report usage for a subscription item
//! usage_manager.report_usage(UsageRecord {
//!     subscription_item_id: "si_xxx".to_string(),
//!     quantity: 100,
//!     timestamp: None, // defaults to now
//!     action: UsageAction::Increment, // or Set
//! }).await?;
//!
//! // Get usage summary for a subscription
//! let summary = usage_manager.get_usage_summary("sub_xxx").await?;
//! ```

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Usage record to report to Stripe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// The subscription item ID (si_xxx) to report usage for.
    pub subscription_item_id: String,
    /// The quantity of usage to report.
    pub quantity: u64,
    /// Optional Unix timestamp for the usage. Defaults to now if not provided.
    pub timestamp: Option<i64>,
    /// How to apply the usage: increment existing or set absolute value.
    pub action: UsageAction,
}

/// How to apply usage when reporting.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum UsageAction {
    /// Add to existing usage in the current period.
    #[default]
    Increment,
    /// Set the absolute usage value (overwrites).
    Set,
}

impl UsageAction {
    /// Convert to Stripe API action string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Increment => "increment",
            Self::Set => "set",
        }
    }
}

/// Result of reporting usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecordResult {
    /// Stripe usage record ID.
    pub id: String,
    /// The quantity reported.
    pub quantity: u64,
    /// Unix timestamp of the usage.
    pub timestamp: i64,
    /// The subscription item this applies to.
    pub subscription_item_id: String,
}

/// Summary of usage for a subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    /// Total usage in the current billing period.
    pub total_usage: u64,
    /// Usage by subscription item.
    pub items: Vec<UsageItemSummary>,
    /// Start of the current billing period (Unix timestamp).
    pub period_start: i64,
    /// End of the current billing period (Unix timestamp).
    pub period_end: i64,
}

/// Usage summary for a single subscription item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageItemSummary {
    /// Subscription item ID.
    pub subscription_item_id: String,
    /// Total usage for this item.
    pub total_usage: u64,
}

/// Trait for Stripe usage API operations.
#[async_trait]
pub trait StripeUsageClient: Send + Sync {
    /// Create a usage record for a subscription item.
    async fn create_usage_record(
        &self,
        subscription_item_id: &str,
        quantity: u64,
        timestamp: Option<i64>,
        action: UsageAction,
    ) -> Result<UsageRecordResult>;

    /// List usage records for a subscription item.
    async fn list_usage_records(
        &self,
        subscription_item_id: &str,
    ) -> Result<Vec<UsageRecordSummary>>;
}

/// Usage record summary from Stripe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecordSummary {
    /// Stripe ID.
    pub id: String,
    /// Total usage.
    pub total_usage: u64,
    /// Period start (Unix timestamp).
    pub period_start: i64,
    /// Period end (Unix timestamp).
    pub period_end: i64,
    /// Invoice ID if billed.
    pub invoice: Option<String>,
}

/// Manager for usage-based billing operations.
pub struct UsageManager<C: StripeUsageClient> {
    client: C,
}

impl<C: StripeUsageClient> UsageManager<C> {
    /// Create a new usage manager.
    #[must_use]
    pub fn new(client: C) -> Self {
        Self { client }
    }

    /// Report usage for a subscription item.
    ///
    /// # Arguments
    ///
    /// * `record` - The usage record to report
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Increment API call count
    /// manager.report_usage(UsageRecord {
    ///     subscription_item_id: "si_xxx".to_string(),
    ///     quantity: 1,
    ///     timestamp: None,
    ///     action: UsageAction::Increment,
    /// }).await?;
    /// ```
    pub async fn report_usage(&self, record: UsageRecord) -> Result<UsageRecordResult> {
        self.client.create_usage_record(
            &record.subscription_item_id,
            record.quantity,
            record.timestamp,
            record.action,
        ).await
    }

    /// Report multiple usage records in a batch.
    ///
    /// Reports are processed in parallel for efficiency.
    /// Returns all successful results; fails if any report fails.
    pub async fn report_usage_batch(
        &self,
        records: Vec<UsageRecord>,
    ) -> Result<Vec<UsageRecordResult>> {
        let futures: Vec<_> = records.into_iter().map(|r| self.report_usage(r)).collect();

        let results = futures::future::try_join_all(futures).await?;
        Ok(results)
    }

    /// Get usage summaries for a subscription item.
    pub async fn get_usage_records(
        &self,
        subscription_item_id: &str,
    ) -> Result<Vec<UsageRecordSummary>> {
        self.client.list_usage_records(subscription_item_id).await
    }
}

/// Helper to track usage locally before reporting.
///
/// Useful for batching usage reports to reduce API calls.
///
/// # Example
///
/// ```rust,ignore
/// let tracker = UsageTracker::new();
///
/// // Track usage throughout request handling
/// tracker.track("si_api_calls", 1);
/// tracker.track("si_storage_mb", 50);
///
/// // Flush at end of request or periodically
/// let records = tracker.flush();
/// manager.report_usage_batch(records).await?;
/// ```
#[derive(Debug, Default)]
pub struct UsageTracker {
    usage: std::sync::RwLock<std::collections::HashMap<String, u64>>,
}

impl UsageTracker {
    /// Create a new usage tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Track usage for a subscription item.
    ///
    /// Usage is accumulated until flushed.
    pub fn track(&self, subscription_item_id: &str, quantity: u64) {
        if let Ok(mut usage) = self.usage.write() {
            *usage.entry(subscription_item_id.to_string()).or_default() += quantity;
        }
    }

    /// Get current tracked usage without flushing.
    #[must_use]
    pub fn current(&self) -> std::collections::HashMap<String, u64> {
        self.usage.read().map(|u| u.clone()).unwrap_or_default()
    }

    /// Flush tracked usage and return records to report.
    ///
    /// This clears the internal tracker.
    pub fn flush(&self) -> Vec<UsageRecord> {
        let mut usage = match self.usage.write() {
            Ok(u) => u,
            Err(_) => return vec![],
        };

        let records: Vec<UsageRecord> = usage
            .drain()
            .filter(|(_, qty)| *qty > 0)
            .map(|(item_id, quantity)| UsageRecord {
                subscription_item_id: item_id,
                quantity,
                timestamp: None,
                action: UsageAction::Increment,
            })
            .collect();

        records
    }

    /// Check if there's any tracked usage.
    #[must_use]
    pub fn has_usage(&self) -> bool {
        self.usage.read().map(|u| !u.is_empty()).unwrap_or(false)
    }
}

/// Configuration for usage-based billing thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageThreshold {
    /// The subscription item ID this threshold applies to.
    pub subscription_item_id: String,
    /// Warning threshold (notify user).
    pub warning_threshold: Option<u64>,
    /// Hard limit (block usage).
    pub hard_limit: Option<u64>,
}

/// Result of checking usage against thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageCheckResult {
    /// Usage is within normal limits.
    Ok,
    /// Usage has exceeded warning threshold.
    Warning {
        current: u64,
        threshold: u64,
    },
    /// Usage has exceeded hard limit.
    Exceeded {
        current: u64,
        limit: u64,
    },
}

impl UsageCheckResult {
    /// Check if usage is allowed (not exceeded).
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        !matches!(self, Self::Exceeded { .. })
    }

    /// Check if usage is in warning state.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warning { .. })
    }
}

/// Check usage against a threshold.
#[must_use]
pub fn check_usage(current: u64, threshold: &UsageThreshold) -> UsageCheckResult {
    if let Some(limit) = threshold.hard_limit {
        if current >= limit {
            return UsageCheckResult::Exceeded {
                current,
                limit,
            };
        }
    }

    if let Some(warning) = threshold.warning_threshold {
        if current >= warning {
            return UsageCheckResult::Warning {
                current,
                threshold: warning,
            };
        }
    }

    UsageCheckResult::Ok
}

#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::{Arc, RwLock};

    /// Mock Stripe usage client for testing.
    #[derive(Default, Clone)]
    pub struct MockStripeUsageClient {
        records: Arc<RwLock<Vec<UsageRecordResult>>>,
        summaries: Arc<RwLock<Vec<UsageRecordSummary>>>,
    }

    impl MockStripeUsageClient {
        /// Create a new mock client.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Get all recorded usage.
        pub fn get_records(&self) -> Vec<UsageRecordResult> {
            self.records.read().unwrap().clone()
        }

        /// Set summaries to return from list_usage_records.
        pub fn set_summaries(&self, summaries: Vec<UsageRecordSummary>) {
            *self.summaries.write().unwrap() = summaries;
        }
    }

    #[async_trait]
    impl StripeUsageClient for MockStripeUsageClient {
        async fn create_usage_record(
            &self,
            subscription_item_id: &str,
            quantity: u64,
            timestamp: Option<i64>,
            _action: UsageAction,
        ) -> Result<UsageRecordResult> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let result = UsageRecordResult {
                id: format!("mbur_{}", uuid::Uuid::new_v4()),
                quantity,
                timestamp: timestamp.unwrap_or(now),
                subscription_item_id: subscription_item_id.to_string(),
            };

            self.records.write().unwrap().push(result.clone());
            Ok(result)
        }

        async fn list_usage_records(
            &self,
            _subscription_item_id: &str,
        ) -> Result<Vec<UsageRecordSummary>> {
            Ok(self.summaries.read().unwrap().clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::MockStripeUsageClient;

    #[tokio::test]
    async fn test_report_usage() {
        let client = MockStripeUsageClient::new();
        let manager = UsageManager::new(client.clone());

        let result = manager
            .report_usage(UsageRecord {
                subscription_item_id: "si_test".to_string(),
                quantity: 100,
                timestamp: None,
                action: UsageAction::Increment,
            })
            .await
            .unwrap();

        assert_eq!(result.quantity, 100);
        assert_eq!(result.subscription_item_id, "si_test");

        let records = client.get_records();
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn test_report_usage_batch() {
        let client = MockStripeUsageClient::new();
        let manager = UsageManager::new(client.clone());

        let records = vec![
            UsageRecord {
                subscription_item_id: "si_api".to_string(),
                quantity: 50,
                timestamp: None,
                action: UsageAction::Increment,
            },
            UsageRecord {
                subscription_item_id: "si_storage".to_string(),
                quantity: 1024,
                timestamp: None,
                action: UsageAction::Set,
            },
        ];

        let results = manager.report_usage_batch(records).await.unwrap();
        assert_eq!(results.len(), 2);

        let stored = client.get_records();
        assert_eq!(stored.len(), 2);
    }

    #[test]
    fn test_usage_tracker() {
        let tracker = UsageTracker::new();

        tracker.track("si_api", 10);
        tracker.track("si_api", 5);
        tracker.track("si_storage", 100);

        let current = tracker.current();
        assert_eq!(current.get("si_api"), Some(&15));
        assert_eq!(current.get("si_storage"), Some(&100));

        let records = tracker.flush();
        assert_eq!(records.len(), 2);

        // After flush, tracker should be empty
        assert!(!tracker.has_usage());
        assert!(tracker.current().is_empty());
    }

    #[test]
    fn test_usage_check() {
        let threshold = UsageThreshold {
            subscription_item_id: "si_test".to_string(),
            warning_threshold: Some(80),
            hard_limit: Some(100),
        };

        assert_eq!(check_usage(50, &threshold), UsageCheckResult::Ok);
        assert!(check_usage(50, &threshold).is_allowed());

        let warning = check_usage(85, &threshold);
        assert!(matches!(warning, UsageCheckResult::Warning { current: 85, threshold: 80 }));
        assert!(warning.is_allowed());
        assert!(warning.is_warning());

        let exceeded = check_usage(100, &threshold);
        assert!(matches!(exceeded, UsageCheckResult::Exceeded { current: 100, limit: 100 }));
        assert!(!exceeded.is_allowed());
    }

    #[test]
    fn test_usage_action() {
        assert_eq!(UsageAction::Increment.as_str(), "increment");
        assert_eq!(UsageAction::Set.as_str(), "set");
        assert_eq!(UsageAction::default(), UsageAction::Increment);
    }
}
