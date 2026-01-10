//! Entitlements and feature gating.
//!
//! Provides functionality for checking feature access based on subscription plans.

use crate::error::Result;
use super::plans::{Plans, LimitCheckResult};
use super::storage::BillingStore;

/// Entitlements manager for checking feature access.
///
/// Use this to gate features based on subscription plans.
pub struct EntitlementsManager<S: BillingStore> {
    store: S,
    plans: Plans,
}

impl<S: BillingStore> EntitlementsManager<S> {
    /// Create a new entitlements manager.
    #[must_use]
    pub fn new(store: S, plans: Plans) -> Self {
        Self { store, plans }
    }

    /// Get all entitlements for a billable entity.
    ///
    /// Returns the full entitlements object with features and limits.
    pub async fn get_entitlements(&self, billable_id: &str) -> Result<Entitlements> {
        let sub = self.store.get_subscription(billable_id).await?;

        match sub {
            Some(sub) => {
                let plan = self.plans.get(&sub.plan_id);

                match plan {
                    Some(plan) => Ok(Entitlements {
                        has_subscription: true,
                        is_active: sub.is_active(),
                        plan_id: Some(sub.plan_id.clone()),
                        features: plan.features.iter().cloned().collect(),
                        limits: EntitlementLimits {
                            max_projects: plan.limits.max_projects,
                            max_storage_mb: plan.limits.max_storage_mb,
                            max_api_calls_monthly: plan.limits.max_api_calls_monthly,
                            custom: plan.limits.custom.clone(),
                        },
                        total_seats: plan.included_seats + sub.extra_seats,
                    }),
                    None => Ok(Entitlements::none()),
                }
            }
            None => Ok(Entitlements::none()),
        }
    }

    /// Check if a feature is available.
    pub async fn has_feature(&self, billable_id: &str, feature: &str) -> Result<bool> {
        let entitlements = self.get_entitlements(billable_id).await?;
        Ok(entitlements.has_feature(feature))
    }

    /// Check if subscription is active.
    pub async fn is_active(&self, billable_id: &str) -> Result<bool> {
        let sub = self.store.get_subscription(billable_id).await?;
        Ok(sub.map(|s| s.is_active()).unwrap_or(false))
    }

    /// Check a limit against current usage.
    pub async fn check_limit(
        &self,
        billable_id: &str,
        limit_name: &str,
        current_usage: u64,
    ) -> Result<LimitCheckResult> {
        let entitlements = self.get_entitlements(billable_id).await?;
        Ok(entitlements.check_limit(limit_name, current_usage))
    }

    /// Get the plan for a billable entity.
    pub async fn get_plan_id(&self, billable_id: &str) -> Result<Option<String>> {
        let sub = self.store.get_subscription(billable_id).await?;
        Ok(sub.map(|s| s.plan_id))
    }
}

/// Entitlements for a subscription.
#[derive(Debug, Clone)]
#[must_use]
pub struct Entitlements {
    /// Whether the entity has a subscription.
    pub has_subscription: bool,
    /// Whether the subscription is active.
    pub is_active: bool,
    /// The plan ID (if subscribed).
    pub plan_id: Option<String>,
    /// Features available on this plan.
    pub features: Vec<String>,
    /// Resource limits.
    pub limits: EntitlementLimits,
    /// Total seats available.
    pub total_seats: u32,
}

impl Entitlements {
    /// Create entitlements for no subscription.
    #[must_use]
    pub fn none() -> Self {
        Self {
            has_subscription: false,
            is_active: false,
            plan_id: None,
            features: Vec::new(),
            limits: EntitlementLimits::default(),
            total_seats: 0,
        }
    }

    /// Check if a feature is available.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.is_active && self.features.iter().any(|f| f == feature)
    }

    /// Check a limit against current usage.
    #[must_use]
    pub fn check_limit(&self, limit_name: &str, current_usage: u64) -> LimitCheckResult {
        if !self.is_active {
            return LimitCheckResult::AtLimit { current: current_usage, max: 0 };
        }

        let limit = match limit_name {
            "projects" => self.limits.max_projects.map(|l| l as u64),
            "storage_mb" => self.limits.max_storage_mb,
            "api_calls" => self.limits.max_api_calls_monthly.map(|l| l as u64),
            custom => self.limits.custom.get(custom).copied(),
        };

        match limit {
            None => LimitCheckResult::Unlimited,
            Some(max) => {
                if current_usage < max {
                    LimitCheckResult::WithinLimit { current: current_usage, max }
                } else {
                    LimitCheckResult::AtLimit { current: current_usage, max }
                }
            }
        }
    }
}

/// Resource limits from a plan.
#[derive(Debug, Clone, Default)]
pub struct EntitlementLimits {
    /// Maximum number of projects.
    pub max_projects: Option<u32>,
    /// Maximum storage in MB.
    pub max_storage_mb: Option<u64>,
    /// Maximum API calls per month.
    pub max_api_calls_monthly: Option<u32>,
    /// Custom limits.
    pub custom: std::collections::HashMap<String, u64>,
}

/// Result of requiring a feature in middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureCheckResult {
    /// Feature is available.
    Allowed,
    /// No subscription found.
    NoSubscription,
    /// Subscription is not active.
    SubscriptionInactive,
    /// Feature not included in plan.
    FeatureNotIncluded,
}

impl FeatureCheckResult {
    /// Check if the feature is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Check a feature for use in middleware or guards.
///
/// This is a convenience function for checking feature access.
#[must_use = "feature check result must be used to enforce access control"]
pub async fn require_feature<S: BillingStore>(
    store: &S,
    plans: &Plans,
    billable_id: &str,
    feature: &str,
) -> FeatureCheckResult {
    let sub = match store.get_subscription(billable_id).await {
        Ok(Some(sub)) => sub,
        Ok(None) => return FeatureCheckResult::NoSubscription,
        Err(_) => return FeatureCheckResult::NoSubscription,
    };

    if !sub.is_active() {
        return FeatureCheckResult::SubscriptionInactive;
    }

    let plan = match plans.get(&sub.plan_id) {
        Some(p) => p,
        None => return FeatureCheckResult::FeatureNotIncluded,
    };

    if plan.has_feature(feature) {
        FeatureCheckResult::Allowed
    } else {
        FeatureCheckResult::FeatureNotIncluded
    }
}

/// Check if a seat is available for use in middleware or guards.
#[must_use = "seat check result must be used to enforce access control"]
pub async fn require_seat<S: BillingStore>(
    store: &S,
    plans: &Plans,
    billable_id: &str,
    current_member_count: u32,
) -> FeatureCheckResult {
    let sub = match store.get_subscription(billable_id).await {
        Ok(Some(sub)) => sub,
        Ok(None) => return FeatureCheckResult::NoSubscription,
        Err(_) => return FeatureCheckResult::NoSubscription,
    };

    if !sub.is_active() {
        return FeatureCheckResult::SubscriptionInactive;
    }

    let plan = match plans.get(&sub.plan_id) {
        Some(p) => p,
        None => return FeatureCheckResult::FeatureNotIncluded,
    };

    let total_seats = plan.included_seats + sub.extra_seats;
    if current_member_count < total_seats {
        FeatureCheckResult::Allowed
    } else {
        FeatureCheckResult::FeatureNotIncluded
    }
}

/// Cached entitlements manager with TTL-based caching.
///
/// Wraps an `EntitlementsManager` and caches entitlements to reduce storage calls.
/// Use this for high-traffic endpoints where entitlement checks are frequent.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{CachedEntitlementsManager, EntitlementsManager};
/// use std::time::Duration;
///
/// let inner = EntitlementsManager::new(store, plans);
/// let cached = CachedEntitlementsManager::new(inner, Duration::from_secs(60));
///
/// // First call hits storage
/// let entitlements = cached.get_entitlements("org_123").await?;
///
/// // Second call within 60 seconds uses cache
/// let entitlements = cached.get_entitlements("org_123").await?;
/// ```
pub struct CachedEntitlementsManager<S: BillingStore> {
    inner: EntitlementsManager<S>,
    cache: std::sync::Arc<std::sync::RwLock<EntitlementsCache>>,
    ttl: std::time::Duration,
    max_entries: usize,
    operation_counter: std::sync::atomic::AtomicU64,
}

/// Default maximum cache entries.
const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;

/// Cleanup interval (every N operations).
const CLEANUP_INTERVAL: u64 = 100;

struct EntitlementsCache {
    entries: std::collections::HashMap<String, CacheEntry>,
}

struct CacheEntry {
    entitlements: Entitlements,
    expires_at: std::time::Instant,
    last_accessed: std::time::Instant,
}

impl<S: BillingStore> CachedEntitlementsManager<S> {
    /// Create a new cached entitlements manager.
    ///
    /// Uses a default maximum of 10,000 cache entries.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying entitlements manager
    /// * `ttl` - How long to cache entitlements (e.g., 60 seconds)
    #[must_use]
    pub fn new(inner: EntitlementsManager<S>, ttl: std::time::Duration) -> Self {
        Self {
            inner,
            cache: std::sync::Arc::new(std::sync::RwLock::new(EntitlementsCache {
                entries: std::collections::HashMap::new(),
            })),
            ttl,
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
            operation_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a new cached entitlements manager with a custom max entries limit.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying entitlements manager
    /// * `ttl` - How long to cache entitlements
    /// * `max_entries` - Maximum number of entries to keep in cache
    #[must_use]
    pub fn with_max_entries(
        inner: EntitlementsManager<S>,
        ttl: std::time::Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            inner,
            cache: std::sync::Arc::new(std::sync::RwLock::new(EntitlementsCache {
                entries: std::collections::HashMap::new(),
            })),
            ttl,
            max_entries,
            operation_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Perform periodic maintenance (cleanup expired entries, enforce max size).
    fn maybe_cleanup(&self) {
        let count = self.operation_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % CLEANUP_INTERVAL == 0 {
            self.cleanup_expired();
            self.enforce_max_entries();
        }
    }

    /// Enforce maximum cache size by removing oldest entries.
    ///
    /// This is called automatically during periodic maintenance, but can be
    /// called manually if needed.
    pub fn enforce_max_entries(&self) {
        if let Ok(mut cache) = self.cache.write() {
            if cache.entries.len() <= self.max_entries {
                return;
            }

            // Collect entries with their last_accessed time
            let mut entries: Vec<_> = cache.entries.iter()
                .map(|(k, v)| (k.clone(), v.last_accessed))
                .collect();

            // Sort by last_accessed (oldest first)
            entries.sort_by_key(|(_, accessed)| *accessed);

            // Remove oldest entries until we're under the limit
            let to_remove = cache.entries.len() - self.max_entries;
            for (key, _) in entries.into_iter().take(to_remove) {
                cache.entries.remove(&key);
            }
        }
    }

    /// Get entitlements, using cache if available and not expired.
    pub async fn get_entitlements(&self, billable_id: &str) -> Result<Entitlements> {
        // Periodic maintenance
        self.maybe_cleanup();

        // Check cache first
        // If lock is poisoned, treat as cache miss (safe for read-only cache check)
        if let Ok(mut cache) = self.cache.write() {
            if let Some(entry) = cache.entries.get_mut(billable_id) {
                if entry.expires_at > std::time::Instant::now() {
                    // Update last accessed time
                    entry.last_accessed = std::time::Instant::now();
                    return Ok(entry.entitlements.clone());
                }
            }
        }

        // Cache miss or expired - fetch from storage
        let entitlements = self.inner.get_entitlements(billable_id).await?;

        // Update cache
        let now = std::time::Instant::now();
        if let Ok(mut cache) = self.cache.write() {
            cache.entries.insert(
                billable_id.to_string(),
                CacheEntry {
                    entitlements: entitlements.clone(),
                    expires_at: now + self.ttl,
                    last_accessed: now,
                },
            );
        } else {
            tracing::warn!(
                target: "tideway::billing",
                "Entitlements cache lock poisoned, skipping cache update"
            );
        }

        Ok(entitlements)
    }

    /// Check if a feature is available (cached).
    pub async fn has_feature(&self, billable_id: &str, feature: &str) -> Result<bool> {
        let entitlements = self.get_entitlements(billable_id).await?;
        Ok(entitlements.has_feature(feature))
    }

    /// Check if subscription is active (cached).
    pub async fn is_active(&self, billable_id: &str) -> Result<bool> {
        let entitlements = self.get_entitlements(billable_id).await?;
        Ok(entitlements.is_active)
    }

    /// Check a limit against current usage (cached).
    pub async fn check_limit(
        &self,
        billable_id: &str,
        limit_name: &str,
        current_usage: u64,
    ) -> Result<LimitCheckResult> {
        let entitlements = self.get_entitlements(billable_id).await?;
        Ok(entitlements.check_limit(limit_name, current_usage))
    }

    /// Invalidate cached entitlements for a billable entity.
    ///
    /// Call this when a subscription changes (e.g., after webhook processing).
    pub fn invalidate(&self, billable_id: &str) {
        // If lock is poisoned, the cache is in an unknown state anyway
        if let Ok(mut cache) = self.cache.write() {
            cache.entries.remove(billable_id);
        } else {
            tracing::warn!(
                target: "tideway::billing",
                billable_id = %billable_id,
                "Entitlements cache lock poisoned during invalidate"
            );
        }
    }

    /// Clear all cached entitlements.
    pub fn clear(&self) {
        // If lock is poisoned, attempt to recover by clearing
        match self.cache.write() {
            Ok(mut cache) => cache.entries.clear(),
            Err(poisoned) => {
                tracing::warn!(
                    target: "tideway::billing",
                    "Entitlements cache lock poisoned, clearing and recovering"
                );
                poisoned.into_inner().entries.clear();
            }
        }
    }

    /// Get the number of cached entries.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.read().map(|c| c.entries.len()).unwrap_or(0)
    }

    /// Remove expired entries from the cache.
    ///
    /// Call this periodically to prevent unbounded cache growth.
    pub fn cleanup_expired(&self) {
        let now = std::time::Instant::now();
        if let Ok(mut cache) = self.cache.write() {
            cache.entries.retain(|_, entry| entry.expires_at > now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::storage::{StoredSubscription, SubscriptionStatus};

    fn create_test_plans() -> Plans {
        Plans::builder()
            .plan("starter")
                .stripe_price("price_starter")
                .included_seats(3)
                .features(["reports", "email_support"])
                .max_projects(5)
                .max_storage_mb(1000)
                .done()
            .plan("pro")
                .stripe_price("price_pro")
                .included_seats(5)
                .features(["reports", "email_support", "api_access", "priority_support"])
                .max_projects(50)
                .max_storage_mb(10000)
                .max_api_calls(100000)
                .done()
            .build()
    }

    fn create_test_subscription(plan_id: &str, status: SubscriptionStatus, extra_seats: u32) -> StoredSubscription {
        StoredSubscription {
            stripe_subscription_id: "sub_123".to_string(),
            stripe_customer_id: "cus_123".to_string(),
            plan_id: plan_id.to_string(),
            status,
            current_period_start: 1700000000,
            current_period_end: 1702592000,
            extra_seats,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: None,
            seat_item_id: None,
            updated_at: 1700000000,
        }
    }

    #[tokio::test]
    async fn test_get_entitlements() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 2);
        store.save_subscription("org_123", &sub).await.unwrap();

        let manager = EntitlementsManager::new(store, plans);

        let entitlements = manager.get_entitlements("org_123").await.unwrap();
        assert!(entitlements.has_subscription);
        assert!(entitlements.is_active);
        assert_eq!(entitlements.plan_id, Some("starter".to_string()));
        assert_eq!(entitlements.total_seats, 5); // 3 included + 2 extra
        assert!(entitlements.has_feature("reports"));
        assert!(!entitlements.has_feature("api_access"));
    }

    #[tokio::test]
    async fn test_get_entitlements_no_subscription() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let manager = EntitlementsManager::new(store, plans);

        let entitlements = manager.get_entitlements("nonexistent").await.unwrap();
        assert!(!entitlements.has_subscription);
        assert!(!entitlements.is_active);
        assert!(entitlements.features.is_empty());
    }

    #[tokio::test]
    async fn test_get_entitlements_inactive() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Canceled, 0);
        store.save_subscription("org_inactive", &sub).await.unwrap();

        let manager = EntitlementsManager::new(store, plans);

        let entitlements = manager.get_entitlements("org_inactive").await.unwrap();
        assert!(entitlements.has_subscription);
        assert!(!entitlements.is_active);
        assert!(!entitlements.has_feature("reports")); // Features require active subscription
    }

    #[tokio::test]
    async fn test_has_feature() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("pro", SubscriptionStatus::Active, 0);
        store.save_subscription("org_pro", &sub).await.unwrap();

        let manager = EntitlementsManager::new(store, plans);

        assert!(manager.has_feature("org_pro", "api_access").await.unwrap());
        assert!(manager.has_feature("org_pro", "reports").await.unwrap());
        assert!(!manager.has_feature("org_pro", "nonexistent_feature").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_limit() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 0);
        store.save_subscription("org_limit", &sub).await.unwrap();

        let manager = EntitlementsManager::new(store, plans);

        // Under limit
        let result = manager.check_limit("org_limit", "projects", 3).await.unwrap();
        assert!(matches!(result, LimitCheckResult::WithinLimit { current: 3, max: 5 }));

        // At limit
        let result = manager.check_limit("org_limit", "projects", 5).await.unwrap();
        assert!(matches!(result, LimitCheckResult::AtLimit { .. }));

        // Over limit
        let result = manager.check_limit("org_limit", "projects", 10).await.unwrap();
        assert!(matches!(result, LimitCheckResult::AtLimit { .. }));
    }

    #[tokio::test]
    async fn test_require_feature() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 0);
        store.save_subscription("org_req", &sub).await.unwrap();

        // Has feature
        let result = require_feature(&store, &plans, "org_req", "reports").await;
        assert_eq!(result, FeatureCheckResult::Allowed);

        // Missing feature
        let result = require_feature(&store, &plans, "org_req", "api_access").await;
        assert_eq!(result, FeatureCheckResult::FeatureNotIncluded);

        // No subscription
        let result = require_feature(&store, &plans, "nonexistent", "reports").await;
        assert_eq!(result, FeatureCheckResult::NoSubscription);
    }

    #[tokio::test]
    async fn test_require_feature_inactive() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::PastDue, 0);
        store.save_subscription("org_past_due", &sub).await.unwrap();

        let result = require_feature(&store, &plans, "org_past_due", "reports").await;
        assert_eq!(result, FeatureCheckResult::SubscriptionInactive);
    }

    #[tokio::test]
    async fn test_require_seat() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 2);
        store.save_subscription("org_seats", &sub).await.unwrap();

        // Has seat available (5 total, 4 used)
        let result = require_seat(&store, &plans, "org_seats", 4).await;
        assert_eq!(result, FeatureCheckResult::Allowed);

        // No seat available (5 total, 5 used)
        let result = require_seat(&store, &plans, "org_seats", 5).await;
        assert_eq!(result, FeatureCheckResult::FeatureNotIncluded);
    }

    #[test]
    fn test_feature_check_result() {
        assert!(FeatureCheckResult::Allowed.is_allowed());
        assert!(!FeatureCheckResult::NoSubscription.is_allowed());
        assert!(!FeatureCheckResult::SubscriptionInactive.is_allowed());
        assert!(!FeatureCheckResult::FeatureNotIncluded.is_allowed());
    }

    #[tokio::test]
    async fn test_cached_entitlements() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 2);
        store.save_subscription("org_cache", &sub).await.unwrap();

        let inner = EntitlementsManager::new(store.clone(), plans);
        let cached = CachedEntitlementsManager::new(inner, std::time::Duration::from_secs(60));

        // First call - cache miss
        assert_eq!(cached.cache_size(), 0);
        let entitlements = cached.get_entitlements("org_cache").await.unwrap();
        assert!(entitlements.is_active);
        assert_eq!(cached.cache_size(), 1);

        // Second call - cache hit
        let entitlements = cached.get_entitlements("org_cache").await.unwrap();
        assert!(entitlements.is_active);
        assert_eq!(cached.cache_size(), 1);
    }

    #[tokio::test]
    async fn test_cached_entitlements_invalidate() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 0);
        store.save_subscription("org_inv", &sub).await.unwrap();

        let inner = EntitlementsManager::new(store.clone(), plans);
        let cached = CachedEntitlementsManager::new(inner, std::time::Duration::from_secs(60));

        // Populate cache
        let _ = cached.get_entitlements("org_inv").await.unwrap();
        assert_eq!(cached.cache_size(), 1);

        // Invalidate
        cached.invalidate("org_inv");
        assert_eq!(cached.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_cached_entitlements_clear() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub1 = create_test_subscription("starter", SubscriptionStatus::Active, 0);
        store.save_subscription("org_1", &sub1).await.unwrap();
        store.save_subscription("org_2", &sub1).await.unwrap();

        let inner = EntitlementsManager::new(store, plans);
        let cached = CachedEntitlementsManager::new(inner, std::time::Duration::from_secs(60));

        // Populate cache
        let _ = cached.get_entitlements("org_1").await.unwrap();
        let _ = cached.get_entitlements("org_2").await.unwrap();
        assert_eq!(cached.cache_size(), 2);

        // Clear all
        cached.clear();
        assert_eq!(cached.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_cached_max_entries() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        // Create subscriptions for 5 orgs
        let sub = create_test_subscription("starter", SubscriptionStatus::Active, 0);
        for i in 0..5 {
            store.save_subscription(&format!("org_{}", i), &sub).await.unwrap();
        }

        let inner = EntitlementsManager::new(store, plans);
        // Set max entries to 3
        let cached = CachedEntitlementsManager::with_max_entries(
            inner,
            std::time::Duration::from_secs(60),
            3,
        );

        // Populate cache with 5 entries
        for i in 0..5 {
            let _ = cached.get_entitlements(&format!("org_{}", i)).await.unwrap();
        }

        // Force cleanup (happens every 100 operations, so trigger manually)
        cached.enforce_max_entries();

        // Should have at most 3 entries
        assert!(cached.cache_size() <= 3);
    }

    #[tokio::test]
    async fn test_cached_has_feature() {
        let store = InMemoryBillingStore::new();
        let plans = create_test_plans();

        let sub = create_test_subscription("pro", SubscriptionStatus::Active, 0);
        store.save_subscription("org_feat", &sub).await.unwrap();

        let inner = EntitlementsManager::new(store, plans);
        let cached = CachedEntitlementsManager::new(inner, std::time::Duration::from_secs(60));

        assert!(cached.has_feature("org_feat", "api_access").await.unwrap());
        assert!(cached.has_feature("org_feat", "reports").await.unwrap());
        assert!(!cached.has_feature("org_feat", "nonexistent").await.unwrap());

        // All calls should use the same cache entry
        assert_eq!(cached.cache_size(), 1);
    }
}
