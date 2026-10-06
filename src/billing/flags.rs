//! Feature flags with per-organization overrides and percentage rollouts.
//!
//! Flags layer on top of plan [`Entitlements`]. Evaluation order:
//!
//! 1. A per-billable override (`enabled` or `disabled`) always wins.
//! 2. Otherwise the flag's [`RolloutScope`] combines the plan entitlement with a
//!    deterministic percentage rollout.
//! 3. A feature with no flag definition falls back to the plan entitlement.
//!
//! Rollout bucketing hashes `flag_key` and `billable_id`, so a billable entity stays in
//! the same bucket across processes and deploys, raising the percentage only adds
//! entities, and each flag selects an independent cohort.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::billing::{FeatureFlag, FeatureFlagManager, InMemoryFeatureFlagStore};
//!
//! let flags = FeatureFlagManager::new(InMemoryFeatureFlagStore::new());
//! // Roll the plan feature "new_reports" out to 10% of orgs whose plan includes it.
//! flags.save_flag(&FeatureFlag::new("new_reports").rollout(10).plan_subscribers_only()).await?;
//! // Let a design partner in early.
//! flags.set_override("org_partner", "new_reports", true).await?;
//!
//! let entitlements = entitlements_manager.get_entitlements("org_123").await?;
//! if flags.is_enabled("org_123", "new_reports", &entitlements).await? { /* ... */ }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::entitlements::{Entitlements, EntitlementsManager};
use super::storage::BillingStore;
use crate::error::{Result, TidewayError};

/// Which billable entities a flag's percentage rollout applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RolloutScope {
    /// Plans that include the feature always get it; the rollout additionally
    /// enables it for a percentage of everyone else.
    #[default]
    AllBillables,
    /// Only entities whose active plan includes the feature are eligible, and the
    /// rollout enables it for a percentage of them. Use this to gradually release
    /// a plan feature.
    PlanSubscribers,
}

/// A feature flag definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureFlag {
    /// Flag key. Matches the plan feature name when used with plan entitlements.
    pub key: String,
    /// Percentage of eligible entities (0-100) that get the feature.
    pub rollout_percentage: u8,
    /// Which entities the rollout applies to.
    pub scope: RolloutScope,
}

impl FeatureFlag {
    /// Create a flag with a 0% rollout scoped to all billable entities.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            rollout_percentage: 0,
            scope: RolloutScope::AllBillables,
        }
    }

    /// Set the rollout percentage. Values above 100 are clamped to 100.
    #[must_use]
    pub fn rollout(mut self, percentage: u8) -> Self {
        self.rollout_percentage = percentage.min(100);
        self
    }

    /// Restrict the rollout to entities whose plan includes this feature.
    #[must_use]
    pub fn plan_subscribers_only(mut self) -> Self {
        self.scope = RolloutScope::PlanSubscribers;
        self
    }

    /// Whether `billable_id` falls inside this flag's rollout percentage.
    #[must_use]
    pub fn in_rollout(&self, billable_id: &str) -> bool {
        rollout_bucket(&self.key, billable_id) < self.rollout_percentage
    }
}

/// Deterministic rollout bucket in `0..100` for a flag and billable entity.
#[must_use]
pub fn rollout_bucket(flag_key: &str, billable_id: &str) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(flag_key.as_bytes());
    hasher.update([0]);
    hasher.update(billable_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(bytes) % 100) as u8
}

/// Why a flag evaluated the way it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagReason {
    /// A per-billable override decided the result.
    Override,
    /// No flag is defined; the plan entitlement decided the result.
    PlanEntitlement,
    /// The entity's plan does not include the feature (plan-scoped rollout).
    NotEntitled,
    /// The entity is inside the rollout percentage.
    InRollout,
    /// The entity is outside the rollout percentage.
    OutsideRollout,
}

/// Result of evaluating a feature flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct FlagEvaluation {
    /// Whether the feature is enabled.
    pub enabled: bool,
    /// Why.
    pub reason: FlagReason,
}

/// Evaluate a flag from already-loaded inputs.
///
/// `override_value` is the per-billable override, if any. `flag` is the flag
/// definition, if any.
pub fn evaluate_flag(
    feature: &str,
    billable_id: &str,
    entitlements: &Entitlements,
    flag: Option<&FeatureFlag>,
    override_value: Option<bool>,
) -> FlagEvaluation {
    if let Some(enabled) = override_value {
        return FlagEvaluation {
            enabled,
            reason: FlagReason::Override,
        };
    }

    let entitled = entitlements.has_feature(feature);
    let Some(flag) = flag else {
        return FlagEvaluation {
            enabled: entitled,
            reason: FlagReason::PlanEntitlement,
        };
    };

    match flag.scope {
        RolloutScope::AllBillables if entitled => FlagEvaluation {
            enabled: true,
            reason: FlagReason::PlanEntitlement,
        },
        RolloutScope::PlanSubscribers if !entitled => FlagEvaluation {
            enabled: false,
            reason: FlagReason::NotEntitled,
        },
        _ if flag.in_rollout(billable_id) => FlagEvaluation {
            enabled: true,
            reason: FlagReason::InRollout,
        },
        _ => FlagEvaluation {
            enabled: false,
            reason: FlagReason::OutsideRollout,
        },
    }
}

/// Storage for flag definitions and per-billable overrides.
#[async_trait]
pub trait FeatureFlagStore: Send + Sync {
    /// Get a flag definition.
    async fn get_flag(&self, key: &str) -> Result<Option<FeatureFlag>>;
    /// Create or replace a flag definition.
    async fn save_flag(&self, flag: &FeatureFlag) -> Result<()>;
    /// Delete a flag definition. Overrides for the key are kept.
    async fn delete_flag(&self, key: &str) -> Result<()>;
    /// Get the override for a billable entity and flag, if any.
    async fn get_override(&self, billable_id: &str, key: &str) -> Result<Option<bool>>;
    /// Set an override for a billable entity and flag.
    async fn set_override(&self, billable_id: &str, key: &str, enabled: bool) -> Result<()>;
    /// Remove an override for a billable entity and flag.
    async fn clear_override(&self, billable_id: &str, key: &str) -> Result<()>;
    /// List all overrides for a billable entity, keyed by flag.
    async fn list_overrides(&self, billable_id: &str) -> Result<HashMap<String, bool>>;
}

/// In-memory [`FeatureFlagStore`].
///
/// Suitable for tests, single-instance deployments, or flags configured at startup.
/// Clones share state.
#[derive(Debug, Clone, Default)]
pub struct InMemoryFeatureFlagStore {
    inner: Arc<RwLock<InMemoryFlags>>,
}

#[derive(Debug, Default)]
struct InMemoryFlags {
    flags: HashMap<String, FeatureFlag>,
    overrides: HashMap<(String, String), bool>,
}

impl InMemoryFeatureFlagStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a store pre-populated with flag definitions.
    #[must_use]
    pub fn with_flags(flags: impl IntoIterator<Item = FeatureFlag>) -> Self {
        let store = Self::new();
        if let Ok(mut inner) = store.inner.write() {
            for flag in flags {
                inner.flags.insert(flag.key.clone(), flag);
            }
        }
        store
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, InMemoryFlags>> {
        self.inner
            .read()
            .map_err(|_| TidewayError::internal("feature flag store lock poisoned"))
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, InMemoryFlags>> {
        self.inner
            .write()
            .map_err(|_| TidewayError::internal("feature flag store lock poisoned"))
    }
}

#[async_trait]
impl FeatureFlagStore for InMemoryFeatureFlagStore {
    async fn get_flag(&self, key: &str) -> Result<Option<FeatureFlag>> {
        Ok(self.read()?.flags.get(key).cloned())
    }

    async fn save_flag(&self, flag: &FeatureFlag) -> Result<()> {
        self.write()?.flags.insert(flag.key.clone(), flag.clone());
        Ok(())
    }

    async fn delete_flag(&self, key: &str) -> Result<()> {
        self.write()?.flags.remove(key);
        Ok(())
    }

    async fn get_override(&self, billable_id: &str, key: &str) -> Result<Option<bool>> {
        Ok(self
            .read()?
            .overrides
            .get(&(billable_id.to_string(), key.to_string()))
            .copied())
    }

    async fn set_override(&self, billable_id: &str, key: &str, enabled: bool) -> Result<()> {
        self.write()?
            .overrides
            .insert((billable_id.to_string(), key.to_string()), enabled);
        Ok(())
    }

    async fn clear_override(&self, billable_id: &str, key: &str) -> Result<()> {
        self.write()?
            .overrides
            .remove(&(billable_id.to_string(), key.to_string()));
        Ok(())
    }

    async fn list_overrides(&self, billable_id: &str) -> Result<HashMap<String, bool>> {
        Ok(self
            .read()?
            .overrides
            .iter()
            .filter(|((id, _), _)| id == billable_id)
            .map(|((_, key), enabled)| (key.clone(), *enabled))
            .collect())
    }
}

/// Evaluates feature flags against plan entitlements.
pub struct FeatureFlagManager<F: FeatureFlagStore> {
    store: F,
}

impl<F: FeatureFlagStore> FeatureFlagManager<F> {
    /// Create a new feature flag manager.
    #[must_use]
    pub fn new(store: F) -> Self {
        Self { store }
    }

    /// Access the underlying store.
    pub fn store(&self) -> &F {
        &self.store
    }

    /// Evaluate a flag for a billable entity given its entitlements.
    ///
    /// Pass entitlements from [`EntitlementsManager`] or
    /// [`CachedEntitlementsManager`](super::CachedEntitlementsManager).
    pub async fn evaluate(
        &self,
        billable_id: &str,
        feature: &str,
        entitlements: &Entitlements,
    ) -> Result<FlagEvaluation> {
        let override_value = self.store.get_override(billable_id, feature).await?;
        if override_value.is_some() {
            return Ok(evaluate_flag(
                feature,
                billable_id,
                entitlements,
                None,
                override_value,
            ));
        }
        let flag = self.store.get_flag(feature).await?;
        Ok(evaluate_flag(
            feature,
            billable_id,
            entitlements,
            flag.as_ref(),
            None,
        ))
    }

    /// Whether a feature is enabled for a billable entity given its entitlements.
    pub async fn is_enabled(
        &self,
        billable_id: &str,
        feature: &str,
        entitlements: &Entitlements,
    ) -> Result<bool> {
        Ok(self
            .evaluate(billable_id, feature, entitlements)
            .await?
            .enabled)
    }

    /// Load entitlements and evaluate a flag in one call.
    pub async fn is_enabled_for<S: BillingStore>(
        &self,
        entitlements: &EntitlementsManager<S>,
        billable_id: &str,
        feature: &str,
    ) -> Result<bool> {
        let entitlements = entitlements.get_entitlements(billable_id).await?;
        self.is_enabled(billable_id, feature, &entitlements).await
    }

    /// Create or replace a flag definition.
    pub async fn save_flag(&self, flag: &FeatureFlag) -> Result<()> {
        self.store.save_flag(flag).await
    }

    /// Change a flag's rollout percentage, creating the flag if needed.
    pub async fn set_rollout(&self, key: &str, percentage: u8) -> Result<()> {
        let flag = self
            .store
            .get_flag(key)
            .await?
            .unwrap_or_else(|| FeatureFlag::new(key))
            .rollout(percentage);
        self.store.save_flag(&flag).await
    }

    /// Force a flag on or off for one billable entity.
    pub async fn set_override(&self, billable_id: &str, key: &str, enabled: bool) -> Result<()> {
        self.store.set_override(billable_id, key, enabled).await
    }

    /// Remove a per-billable override.
    pub async fn clear_override(&self, billable_id: &str, key: &str) -> Result<()> {
        self.store.clear_override(billable_id, key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::plans::Plans;
    use crate::billing::storage::test::InMemoryBillingStore;
    use crate::billing::storage::{StoredSubscription, SubscriptionStatus};

    fn entitled(features: &[&str]) -> Entitlements {
        Entitlements {
            has_subscription: true,
            is_active: true,
            plan_id: Some("pro".to_string()),
            features: features.iter().map(|f| f.to_string()).collect(),
            ..Entitlements::none()
        }
    }

    fn org_ids() -> impl Iterator<Item = String> {
        (0..10_000).map(|i| format!("org_{i}"))
    }

    #[tokio::test]
    async fn override_enables_feature_missing_from_plan() {
        let flags = FeatureFlagManager::new(InMemoryFeatureFlagStore::new());
        let starter = entitled(&["reports"]);
        assert!(!flags.is_enabled("org_a", "beta", &starter).await.unwrap());

        flags.set_override("org_a", "beta", true).await.unwrap();
        let eval = flags.evaluate("org_a", "beta", &starter).await.unwrap();
        assert_eq!(
            eval,
            FlagEvaluation {
                enabled: true,
                reason: FlagReason::Override
            }
        );
        // Other orgs are unaffected.
        assert!(!flags.is_enabled("org_b", "beta", &starter).await.unwrap());

        flags.clear_override("org_a", "beta").await.unwrap();
        assert!(!flags.is_enabled("org_a", "beta", &starter).await.unwrap());
    }

    #[tokio::test]
    async fn override_disables_plan_feature() {
        let flags = FeatureFlagManager::new(InMemoryFeatureFlagStore::new());
        let pro = entitled(&["reports"]);
        flags.set_override("org_a", "reports", false).await.unwrap();
        assert!(!flags.is_enabled("org_a", "reports", &pro).await.unwrap());
        assert!(flags.is_enabled("org_b", "reports", &pro).await.unwrap());
        assert_eq!(
            flags.store().list_overrides("org_a").await.unwrap(),
            HashMap::from([("reports".to_string(), false)])
        );
    }

    #[test]
    fn undefined_flag_falls_back_to_plan() {
        let pro = entitled(&["reports"]);
        let eval = evaluate_flag("reports", "org", &pro, None, None);
        assert!(eval.enabled);
        assert_eq!(eval.reason, FlagReason::PlanEntitlement);
        assert!(!evaluate_flag("api", "org", &pro, None, None).enabled);
    }

    #[test]
    fn rollout_enables_roughly_the_requested_percentage() {
        let flag = FeatureFlag::new("beta").rollout(10);
        let none = Entitlements::none();
        let enabled = org_ids()
            .filter(|id| evaluate_flag("beta", id, &none, Some(&flag), None).enabled)
            .count();
        assert!(
            (900..=1100).contains(&enabled),
            "enabled {enabled} of 10000"
        );
    }

    #[test]
    fn rollout_bounds() {
        let none = Entitlements::none();
        let off = FeatureFlag::new("beta");
        let on = FeatureFlag::new("beta").rollout(100);
        assert!(org_ids().all(|id| !evaluate_flag("beta", &id, &none, Some(&off), None).enabled));
        assert!(org_ids().all(|id| evaluate_flag("beta", &id, &none, Some(&on), None).enabled));
        assert_eq!(
            FeatureFlag::new("beta").rollout(250).rollout_percentage,
            100
        );
    }

    #[test]
    fn rollout_is_stable_and_monotonic() {
        let ten = FeatureFlag::new("beta").rollout(10);
        let fifty = FeatureFlag::new("beta").rollout(50);
        for id in org_ids() {
            if ten.in_rollout(&id) {
                assert!(fifty.in_rollout(&id), "{id} dropped when rollout increased");
            }
        }
        // Pin the hash so bucketing never silently changes across releases.
        assert_eq!(rollout_bucket("new_reports", "org_123"), 87);
    }

    #[test]
    fn different_flags_select_different_cohorts() {
        let a = FeatureFlag::new("a").rollout(50);
        let b = FeatureFlag::new("b").rollout(50);
        let differ = org_ids()
            .filter(|id| a.in_rollout(id) != b.in_rollout(id))
            .count();
        assert!(differ > 1000);
    }

    #[test]
    fn all_billables_scope_keeps_plan_access() {
        let pro = entitled(&["beta"]);
        let flag = FeatureFlag::new("beta");
        let eval = evaluate_flag("beta", "org", &pro, Some(&flag), None);
        assert!(eval.enabled);
        assert_eq!(eval.reason, FlagReason::PlanEntitlement);
    }

    #[test]
    fn plan_subscribers_scope_gates_plan_feature_by_rollout() {
        let flag = FeatureFlag::new("new_reports")
            .rollout(10)
            .plan_subscribers_only();
        let pro = entitled(&["new_reports"]);
        let starter = entitled(&["reports"]);

        let enabled = org_ids()
            .filter(|id| evaluate_flag("new_reports", id, &pro, Some(&flag), None).enabled)
            .count();
        assert!(
            (900..=1100).contains(&enabled),
            "enabled {enabled} of 10000"
        );

        // Entities without the plan feature never get it via rollout.
        assert!(org_ids().all(|id| {
            evaluate_flag("new_reports", &id, &starter, Some(&flag), None)
                == FlagEvaluation {
                    enabled: false,
                    reason: FlagReason::NotEntitled,
                }
        }));
    }

    #[test]
    fn inactive_subscription_is_not_entitled() {
        let mut lapsed = entitled(&["new_reports"]);
        lapsed.is_active = false;
        let flag = FeatureFlag::new("new_reports")
            .rollout(100)
            .plan_subscribers_only();
        assert!(!evaluate_flag("new_reports", "org", &lapsed, Some(&flag), None).enabled);
    }

    #[tokio::test]
    async fn integrates_with_entitlements_manager() {
        let plans = Plans::builder()
            .plan("pro")
            .stripe_price("price_pro")
            .features(["reports"])
            .done()
            .unwrap()
            .build()
            .unwrap();
        let store = InMemoryBillingStore::new();
        let sub = StoredSubscription {
            stripe_subscription_id: "sub_1".to_string(),
            stripe_customer_id: "cus_1".to_string(),
            plan_id: "pro".to_string(),
            status: SubscriptionStatus::Active,
            current_period_start: 0,
            current_period_end: 0,
            extra_seats: 0,
            trial_end: None,
            cancel_at_period_end: false,
            base_item_id: None,
            seat_item_id: None,
            updated_at: 0,
        };
        store.save_subscription("org_pro", &sub).await.unwrap();
        let entitlements = EntitlementsManager::new(store, plans);

        let flags =
            FeatureFlagManager::new(InMemoryFeatureFlagStore::with_flags([FeatureFlag::new(
                "reports",
            )
            .plan_subscribers_only()]));
        // Plan-scoped flag at 0% hides the plan feature until rolled out.
        assert!(
            !flags
                .is_enabled_for(&entitlements, "org_pro", "reports")
                .await
                .unwrap()
        );
        flags.set_rollout("reports", 100).await.unwrap();
        assert!(
            flags
                .is_enabled_for(&entitlements, "org_pro", "reports")
                .await
                .unwrap()
        );
        assert_eq!(
            flags
                .store()
                .get_flag("reports")
                .await
                .unwrap()
                .unwrap()
                .scope,
            RolloutScope::PlanSubscribers
        );
        assert!(
            !flags
                .is_enabled_for(&entitlements, "org_none", "reports")
                .await
                .unwrap()
        );
    }
}
