//! Plan configuration and definitions.
//!
//! Define your subscription plans with features, seat limits, and pricing.
//!
//! # Static Plans (Code-configured)
//!
//! Use the builder pattern for plans defined in code:
//!
//! ```rust,ignore
//! use tideway::billing::{Plans, PlanLimits};
//!
//! let plans = Plans::builder()
//!     .plan("starter")
//!         .stripe_price("price_starter_monthly")
//!         .extra_seat_price("price_extra_seat")
//!         .included_seats(3)
//!         .features(["basic_reports", "email_support"])
//!         .trial_days(14)
//!         .done()
//!     .plan("pro")
//!         .stripe_price("price_pro_monthly")
//!         .extra_seat_price("price_extra_seat")
//!         .included_seats(5)
//!         .features(["basic_reports", "advanced_reports", "api_access"])
//!         .done()
//!     .build();
//! ```
//!
//! # Dynamic Plans (Database-backed)
//!
//! Use [`PlanStore`](super::storage::PlanStore) for admin-managed plans:
//!
//! ```rust,ignore
//! use tideway::billing::{Plans, PlanStore, StoredPlan};
//!
//! // Load plans from database
//! let stored_plans = store.list_plans().await?;
//! let plans = Plans::from_stored(stored_plans);
//! ```

use std::collections::{HashMap, HashSet};

use super::storage::StoredPlan;

/// A collection of plan configurations.
#[derive(Clone, Debug, Default)]
pub struct Plans {
    plans: HashMap<String, PlanConfig>,
}

impl Plans {
    /// Create a new empty plans collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for constructing plans.
    #[must_use]
    pub fn builder() -> PlansBuilder {
        PlansBuilder::new()
    }

    /// Create a Plans collection from database-stored plans.
    ///
    /// This allows database-managed plans to be used with the existing
    /// code-configured plan system.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let stored_plans = store.list_plans().await?;
    /// let plans = Plans::from_stored(stored_plans);
    /// ```
    #[must_use]
    pub fn from_stored(stored: Vec<StoredPlan>) -> Self {
        let plans = stored
            .into_iter()
            .map(|sp| {
                let config = PlanConfig::from(sp);
                (config.id.clone(), config)
            })
            .collect();
        Self { plans }
    }

    /// Merge plans from another Plans collection.
    ///
    /// Plans from `other` will overwrite plans with the same ID.
    pub fn merge(&mut self, other: Plans) {
        self.plans.extend(other.plans);
    }

    /// Add a single plan config.
    pub fn add(&mut self, config: PlanConfig) {
        self.plans.insert(config.id.clone(), config);
    }

    /// Get a plan by ID.
    #[must_use]
    pub fn get(&self, plan_id: &str) -> Option<&PlanConfig> {
        self.plans.get(plan_id)
    }

    /// Get all plan IDs.
    #[must_use]
    pub fn plan_ids(&self) -> Vec<&str> {
        self.plans.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a plan exists.
    #[must_use]
    pub fn contains(&self, plan_id: &str) -> bool {
        self.plans.contains_key(plan_id)
    }

    /// Get the number of plans.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plans.len()
    }

    /// Check if there are no plans.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }

    /// Iterate over all plans.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PlanConfig)> {
        self.plans.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Find plan by Stripe price ID.
    #[must_use]
    pub fn find_by_stripe_price(&self, price_id: &str) -> Option<&PlanConfig> {
        self.plans
            .values()
            .find(|p| p.stripe_price_id == price_id)
    }

    /// Get all Stripe price IDs (for validation).
    #[must_use]
    pub fn all_stripe_price_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self
            .plans
            .values()
            .map(|p| p.stripe_price_id.as_str())
            .collect();

        // Also include extra seat prices
        for plan in self.plans.values() {
            if let Some(ref seat_price) = plan.extra_seat_price_id {
                ids.push(seat_price.as_str());
            }
        }

        ids
    }
}

/// Configuration for a single plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanConfig {
    /// Plan identifier (e.g., "starter", "pro").
    pub id: String,
    /// Stripe price ID for the base subscription.
    pub stripe_price_id: String,
    /// Stripe price ID for additional seats (optional).
    pub extra_seat_price_id: Option<String>,
    /// Number of seats included in the base price.
    pub included_seats: u32,
    /// Features available on this plan.
    pub features: HashSet<String>,
    /// Resource limits for this plan.
    pub limits: PlanLimits,
    /// Trial period in days (None = no trial).
    pub trial_days: Option<u32>,
    /// Display name for the plan.
    pub display_name: Option<String>,
    /// Description of the plan.
    pub description: Option<String>,
    /// Currency code (e.g., "gbp", "usd", "eur").
    /// This should match the currency of the Stripe price.
    /// Used for display purposes and validation.
    pub currency: Option<String>,
}

impl PlanConfig {
    /// Check if this plan has a specific feature.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    /// Check if this plan supports extra seats.
    #[must_use]
    pub fn supports_extra_seats(&self) -> bool {
        self.extra_seat_price_id.is_some()
    }

    /// Get the total seats for a given number of extra seats.
    #[must_use]
    pub fn total_seats(&self, extra_seats: u32) -> u32 {
        self.included_seats.saturating_add(extra_seats)
    }

    /// Check if a resource usage is within limits.
    #[must_use]
    pub fn check_limit(&self, resource: &str, current: u64) -> LimitCheckResult {
        self.limits.check(resource, current)
    }
}

impl From<StoredPlan> for PlanConfig {
    fn from(stored: StoredPlan) -> Self {
        // Convert features JSON to HashSet<String>
        let features = stored
            .features
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| {
                        if v.as_bool().unwrap_or(false) {
                            Some(k.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Convert limits JSON to PlanLimits
        let limits = PlanLimits::from_json(&stored.limits);

        Self {
            id: stored.id,
            stripe_price_id: stored.stripe_price_id,
            extra_seat_price_id: stored.stripe_seat_price_id,
            included_seats: stored.included_seats,
            features,
            limits,
            trial_days: stored.trial_days,
            display_name: Some(stored.name),
            description: stored.description,
            currency: Some(stored.currency),
        }
    }
}

/// Resource limits for a plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanLimits {
    /// Maximum number of projects.
    pub max_projects: Option<u32>,
    /// Maximum storage in megabytes.
    pub max_storage_mb: Option<u64>,
    /// Maximum API calls per month.
    pub max_api_calls_monthly: Option<u32>,
    /// Custom limits (extensible).
    pub custom: HashMap<String, u64>,
}

impl PlanLimits {
    /// Create unlimited limits.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Create PlanLimits from a JSON value.
    ///
    /// Recognizes keys: "projects", "storage_mb", "api_calls", and any custom keys.
    #[must_use]
    pub fn from_json(json: &serde_json::Value) -> Self {
        let obj = match json.as_object() {
            Some(o) => o,
            None => return Self::default(),
        };

        let mut limits = Self::default();
        let mut custom = HashMap::new();

        for (key, value) in obj {
            let num = value.as_i64().or_else(|| value.as_u64().map(|n| n as i64));
            if let Some(n) = num {
                match key.as_str() {
                    "projects" | "max_projects" => limits.max_projects = Some(n as u32),
                    "storage_mb" | "max_storage_mb" => limits.max_storage_mb = Some(n as u64),
                    "api_calls" | "max_api_calls" | "max_api_calls_monthly" => {
                        limits.max_api_calls_monthly = Some(n as u32)
                    }
                    _ => {
                        custom.insert(key.clone(), n as u64);
                    }
                }
            }
        }

        limits.custom = custom;
        limits
    }

    /// Check if a resource usage is within limits.
    #[must_use]
    pub fn check(&self, resource: &str, current: u64) -> LimitCheckResult {
        let limit = match resource {
            "projects" => self.max_projects.map(|v| v as u64),
            "storage_mb" => self.max_storage_mb,
            "api_calls" => self.max_api_calls_monthly.map(|v| v as u64),
            _ => self.custom.get(resource).copied(),
        };

        match limit {
            None => LimitCheckResult::Unlimited,
            Some(max) if current < max => LimitCheckResult::WithinLimit { current, max },
            Some(max) => LimitCheckResult::AtLimit { current, max },
        }
    }

    /// Get a specific limit value.
    #[must_use]
    pub fn get(&self, resource: &str) -> Option<u64> {
        match resource {
            "projects" => self.max_projects.map(|v| v as u64),
            "storage_mb" => self.max_storage_mb,
            "api_calls" => self.max_api_calls_monthly.map(|v| v as u64),
            _ => self.custom.get(resource).copied(),
        }
    }
}

/// Result of checking a resource limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitCheckResult {
    /// No limit on this resource.
    Unlimited,
    /// Usage is within the limit.
    WithinLimit { current: u64, max: u64 },
    /// Usage has reached or exceeded the limit.
    AtLimit { current: u64, max: u64 },
}

impl LimitCheckResult {
    /// Check if usage is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Unlimited | Self::WithinLimit { .. })
    }

    /// Check if at or over limit.
    #[must_use]
    pub fn is_at_limit(&self) -> bool {
        matches!(self, Self::AtLimit { .. })
    }
}

/// Builder for constructing a collection of plans.
#[derive(Debug, Default)]
pub struct PlansBuilder {
    plans: HashMap<String, PlanConfig>,
}

impl PlansBuilder {
    /// Create a new plans builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start defining a new plan.
    #[must_use]
    pub fn plan(self, id: &str) -> PlanBuilder {
        PlanBuilder {
            parent: self,
            id: id.to_string(),
            stripe_price_id: None,
            extra_seat_price_id: None,
            included_seats: 1,
            features: HashSet::new(),
            limits: PlanLimits::default(),
            trial_days: None,
            display_name: None,
            description: None,
            currency: None,
        }
    }

    /// Build the plans collection.
    #[must_use]
    pub fn build(self) -> Plans {
        Plans { plans: self.plans }
    }

    fn add_plan(mut self, config: PlanConfig) -> Self {
        self.plans.insert(config.id.clone(), config);
        self
    }
}

/// Builder for a single plan configuration.
#[derive(Debug)]
pub struct PlanBuilder {
    parent: PlansBuilder,
    id: String,
    stripe_price_id: Option<String>,
    extra_seat_price_id: Option<String>,
    included_seats: u32,
    features: HashSet<String>,
    limits: PlanLimits,
    trial_days: Option<u32>,
    display_name: Option<String>,
    description: Option<String>,
    currency: Option<String>,
}

impl PlanBuilder {
    /// Set the Stripe price ID for the base subscription.
    #[must_use]
    pub fn stripe_price(mut self, price_id: &str) -> Self {
        self.stripe_price_id = Some(price_id.to_string());
        self
    }

    /// Set the Stripe price ID for additional seats.
    #[must_use]
    pub fn extra_seat_price(mut self, price_id: &str) -> Self {
        self.extra_seat_price_id = Some(price_id.to_string());
        self
    }

    /// Set the number of seats included in the base price.
    #[must_use]
    pub fn included_seats(mut self, seats: u32) -> Self {
        self.included_seats = seats;
        self
    }

    /// Add features to this plan.
    #[must_use]
    pub fn features<I, S>(mut self, features: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.features.extend(features.into_iter().map(Into::into));
        self
    }

    /// Add a single feature to this plan.
    #[must_use]
    pub fn feature(mut self, feature: &str) -> Self {
        self.features.insert(feature.to_string());
        self
    }

    /// Set the maximum number of projects.
    #[must_use]
    pub fn max_projects(mut self, max: u32) -> Self {
        self.limits.max_projects = Some(max);
        self
    }

    /// Set the maximum storage in MB.
    #[must_use]
    pub fn max_storage_mb(mut self, max: u64) -> Self {
        self.limits.max_storage_mb = Some(max);
        self
    }

    /// Set the maximum API calls per month.
    #[must_use]
    pub fn max_api_calls(mut self, max: u32) -> Self {
        self.limits.max_api_calls_monthly = Some(max);
        self
    }

    /// Set a custom limit.
    #[must_use]
    pub fn custom_limit(mut self, name: &str, max: u64) -> Self {
        self.limits.custom.insert(name.to_string(), max);
        self
    }

    /// Set the full limits configuration.
    #[must_use]
    pub fn limits(mut self, limits: PlanLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the trial period in days.
    #[must_use]
    pub fn trial_days(mut self, days: u32) -> Self {
        self.trial_days = Some(days);
        self
    }

    /// Set the display name.
    #[must_use]
    pub fn display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.to_string());
        self
    }

    /// Set the description.
    #[must_use]
    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Set the currency code (e.g., "gbp", "usd", "eur").
    ///
    /// This should match the currency of your Stripe price.
    /// Used for display purposes and validation.
    #[must_use]
    pub fn currency(mut self, currency: &str) -> Self {
        self.currency = Some(currency.to_lowercase());
        self
    }

    /// Finish defining this plan and return to the parent builder.
    ///
    /// # Panics
    ///
    /// Panics if `stripe_price` was not set.
    #[must_use]
    pub fn done(self) -> PlansBuilder {
        let config = PlanConfig {
            id: self.id,
            stripe_price_id: self
                .stripe_price_id
                .expect("stripe_price is required for a plan"),
            extra_seat_price_id: self.extra_seat_price_id,
            included_seats: self.included_seats,
            features: self.features,
            limits: self.limits,
            trial_days: self.trial_days,
            display_name: self.display_name,
            description: self.description,
            currency: self.currency,
        };
        self.parent.add_plan(config)
    }
}

// =============================================================================
// Plan Upgrade/Downgrade Helpers
// =============================================================================

/// Result of comparing two plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanChangeType {
    /// Moving to a plan with more features/seats/limits.
    Upgrade,
    /// Moving to a plan with fewer features/seats/limits.
    Downgrade,
    /// Plans are equivalent (same tier).
    Lateral,
    /// Plans are the same.
    NoChange,
}

impl std::fmt::Display for PlanChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upgrade => write!(f, "upgrade"),
            Self::Downgrade => write!(f, "downgrade"),
            Self::Lateral => write!(f, "lateral"),
            Self::NoChange => write!(f, "no_change"),
        }
    }
}

/// Detailed comparison between two plans.
#[derive(Debug, Clone)]
pub struct PlanComparison {
    /// The type of change (upgrade, downgrade, etc.).
    pub change_type: PlanChangeType,
    /// Features gained by switching to the new plan.
    pub features_gained: HashSet<String>,
    /// Features lost by switching to the new plan.
    pub features_lost: HashSet<String>,
    /// Difference in included seats (positive = more seats).
    pub seat_difference: i32,
    /// Whether extra seats support changes.
    pub extra_seats_support_changed: bool,
    /// Warning messages (e.g., "Current extra seats exceed new plan's included seats").
    pub warnings: Vec<String>,
}

impl PlanComparison {
    /// Check if this change requires user confirmation.
    ///
    /// Returns true if features will be lost or warnings exist.
    #[must_use]
    pub fn requires_confirmation(&self) -> bool {
        !self.features_lost.is_empty() || !self.warnings.is_empty()
    }

    /// Check if this is a safe change (no features lost, no warnings).
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.features_lost.is_empty() && self.warnings.is_empty()
    }
}

/// Compare two plans to determine upgrade/downgrade status.
///
/// This function analyzes the differences between plans based on:
/// - Feature count
/// - Included seats
/// - Resource limits
///
/// # Arguments
///
/// * `from_plan` - The current plan
/// * `to_plan` - The target plan
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{compare_plans, PlanChangeType};
///
/// let comparison = compare_plans(current_plan, new_plan);
/// match comparison.change_type {
///     PlanChangeType::Upgrade => println!("Upgrading!"),
///     PlanChangeType::Downgrade => {
///         if !comparison.features_lost.is_empty() {
///             println!("Warning: You will lose: {:?}", comparison.features_lost);
///         }
///     }
///     _ => {}
/// }
/// ```
#[must_use]
pub fn compare_plans(from_plan: &PlanConfig, to_plan: &PlanConfig) -> PlanComparison {
    // Check for no change
    if from_plan.id == to_plan.id {
        return PlanComparison {
            change_type: PlanChangeType::NoChange,
            features_gained: HashSet::new(),
            features_lost: HashSet::new(),
            seat_difference: 0,
            extra_seats_support_changed: false,
            warnings: vec![],
        };
    }

    // Calculate feature differences
    let features_gained: HashSet<String> = to_plan
        .features
        .difference(&from_plan.features)
        .cloned()
        .collect();
    let features_lost: HashSet<String> = from_plan
        .features
        .difference(&to_plan.features)
        .cloned()
        .collect();

    // Calculate seat difference
    let seat_difference = to_plan.included_seats as i32 - from_plan.included_seats as i32;

    // Check extra seats support change
    let extra_seats_support_changed =
        from_plan.supports_extra_seats() != to_plan.supports_extra_seats();

    // Generate warnings
    let mut warnings = vec![];
    if extra_seats_support_changed && from_plan.supports_extra_seats() {
        warnings.push(
            "New plan does not support extra seats. Extra seats will be removed.".to_string(),
        );
    }
    if seat_difference < 0 {
        warnings.push(format!(
            "New plan has {} fewer included seats.",
            -seat_difference
        ));
    }

    // Determine change type based on heuristics
    let feature_score = features_gained.len() as i32 - features_lost.len() as i32;

    let change_type = if feature_score > 0 || seat_difference > 0 {
        PlanChangeType::Upgrade
    } else if feature_score < 0 || seat_difference < 0 || !features_lost.is_empty() {
        PlanChangeType::Downgrade
    } else {
        PlanChangeType::Lateral
    };

    PlanComparison {
        change_type,
        features_gained,
        features_lost,
        seat_difference,
        extra_seats_support_changed,
        warnings,
    }
}

/// Check if a plan can be downgraded given current usage.
///
/// # Arguments
///
/// * `from_plan` - The current plan
/// * `to_plan` - The target plan
/// * `current_extra_seats` - Number of extra seats currently in use
/// * `current_total_members` - Total members currently using the subscription
///
/// # Returns
///
/// Returns `Ok(())` if the downgrade is allowed, or `Err` with a reason if not.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::can_downgrade;
///
/// match can_downgrade(current_plan, new_plan, extra_seats, total_members) {
///     Ok(()) => println!("Downgrade allowed"),
///     Err(reason) => println!("Cannot downgrade: {}", reason),
/// }
/// ```
pub fn can_downgrade(
    from_plan: &PlanConfig,
    to_plan: &PlanConfig,
    current_extra_seats: u32,
    current_total_members: u32,
) -> Result<(), PlanDowngradeError> {
    // Check if new plan has enough seats
    let new_total_seats = if to_plan.supports_extra_seats() {
        to_plan.included_seats + current_extra_seats
    } else {
        to_plan.included_seats
    };

    if current_total_members > new_total_seats {
        return Err(PlanDowngradeError::InsufficientSeats {
            current_members: current_total_members,
            new_seats: new_total_seats,
        });
    }

    // Check if extra seats are needed but not supported
    if current_extra_seats > 0 && !to_plan.supports_extra_seats() {
        let min_needed = current_total_members.saturating_sub(to_plan.included_seats);
        if min_needed > 0 {
            return Err(PlanDowngradeError::ExtraSeatsRequired {
                extra_needed: min_needed,
            });
        }
    }

    Ok(())
}

/// Error type for plan downgrade validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanDowngradeError {
    /// Not enough seats on the new plan.
    InsufficientSeats {
        current_members: u32,
        new_seats: u32,
    },
    /// Extra seats are needed but the new plan doesn't support them.
    ExtraSeatsRequired {
        extra_needed: u32,
    },
}

impl std::fmt::Display for PlanDowngradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientSeats { current_members, new_seats } => {
                write!(
                    f,
                    "Cannot downgrade: you have {} members but the new plan only supports {} seats",
                    current_members, new_seats
                )
            }
            Self::ExtraSeatsRequired { extra_needed } => {
                write!(
                    f,
                    "Cannot downgrade: you need {} extra seats but the new plan doesn't support extra seats",
                    extra_needed
                )
            }
        }
    }
}

impl std::error::Error for PlanDowngradeError {}

/// Get a list of suggested plans for an upgrade.
///
/// Returns plans that have more features than the current plan,
/// sorted by feature count (most additional features first).
///
/// # Example
///
/// ```rust,ignore
/// let suggestions = plans.suggest_upgrades(current_plan);
/// for plan in suggestions {
///     println!("Consider upgrading to: {}", plan.id);
/// }
/// ```
impl Plans {
    /// Suggest upgrade options from the current plan.
    ///
    /// Returns plans that have strictly more features, sorted by the number
    /// of additional features (descending).
    #[must_use]
    pub fn suggest_upgrades(&self, current_plan: &PlanConfig) -> Vec<&PlanConfig> {
        let mut upgrades: Vec<(&PlanConfig, usize)> = self
            .plans
            .values()
            .filter(|p| {
                // Different plan
                p.id != current_plan.id
                    // Has more features
                    && p.features.is_superset(&current_plan.features)
                    && p.features.len() > current_plan.features.len()
            })
            .map(|p| {
                let additional = p.features.len() - current_plan.features.len();
                (p, additional)
            })
            .collect();

        // Sort by additional features (descending)
        upgrades.sort_by(|a, b| b.1.cmp(&a.1));

        upgrades.into_iter().map(|(p, _)| p).collect()
    }

    /// Find the next tier up from the current plan.
    ///
    /// Returns the upgrade with the fewest additional features (minimal upgrade).
    #[must_use]
    pub fn next_tier_up(&self, current_plan: &PlanConfig) -> Option<&PlanConfig> {
        self.plans
            .values()
            .filter(|p| {
                p.id != current_plan.id
                    && p.features.is_superset(&current_plan.features)
                    && p.features.len() > current_plan.features.len()
            })
            .min_by_key(|p| p.features.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_plans() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .included_seats(3)
            .features(["reports", "email_support"])
            .trial_days(14)
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .extra_seat_price("price_seat")
            .included_seats(5)
            .features(["reports", "api_access", "priority_support"])
            .max_projects(100)
            .done()
            .build();

        assert_eq!(plans.len(), 2);
        assert!(plans.contains("starter"));
        assert!(plans.contains("pro"));
    }

    #[test]
    fn test_plan_features() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .features(["reports"])
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .features(["reports", "api_access"])
            .done()
            .build();

        let starter = plans.get("starter").unwrap();
        assert!(starter.has_feature("reports"));
        assert!(!starter.has_feature("api_access"));

        let pro = plans.get("pro").unwrap();
        assert!(pro.has_feature("reports"));
        assert!(pro.has_feature("api_access"));
    }

    #[test]
    fn test_plan_seats() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .included_seats(3)
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .extra_seat_price("price_seat")
            .included_seats(5)
            .done()
            .build();

        let starter = plans.get("starter").unwrap();
        assert_eq!(starter.included_seats, 3);
        assert!(!starter.supports_extra_seats());
        assert_eq!(starter.total_seats(0), 3);

        let pro = plans.get("pro").unwrap();
        assert_eq!(pro.included_seats, 5);
        assert!(pro.supports_extra_seats());
        assert_eq!(pro.total_seats(3), 8);
    }

    #[test]
    fn test_plan_limits() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .max_projects(10)
            .max_storage_mb(1024)
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .max_projects(100)
            .custom_limit("widgets", 500)
            .done()
            .build();

        let starter = plans.get("starter").unwrap();
        assert!(starter.check_limit("projects", 5).is_allowed());
        assert!(starter.check_limit("projects", 10).is_at_limit());
        assert!(starter.check_limit("projects", 15).is_at_limit());

        let pro = plans.get("pro").unwrap();
        assert_eq!(
            pro.check_limit("widgets", 400),
            LimitCheckResult::WithinLimit {
                current: 400,
                max: 500
            }
        );
    }

    #[test]
    fn test_unlimited_limits() {
        let plans = Plans::builder()
            .plan("enterprise")
            .stripe_price("price_enterprise")
            .done()
            .build();

        let enterprise = plans.get("enterprise").unwrap();
        assert_eq!(
            enterprise.check_limit("projects", 10000),
            LimitCheckResult::Unlimited
        );
    }

    #[test]
    fn test_find_by_stripe_price() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_abc123")
            .done()
            .plan("pro")
            .stripe_price("price_xyz789")
            .done()
            .build();

        let found = plans.find_by_stripe_price("price_abc123");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "starter");

        let not_found = plans.find_by_stripe_price("price_unknown");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_all_stripe_price_ids() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .extra_seat_price("price_seat")
            .done()
            .build();

        let ids = plans.all_stripe_price_ids();
        assert!(ids.contains(&"price_starter"));
        assert!(ids.contains(&"price_pro"));
        assert!(ids.contains(&"price_seat"));
    }

    #[test]
    fn test_trial_days() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .trial_days(14)
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .done()
            .build();

        let starter = plans.get("starter").unwrap();
        assert_eq!(starter.trial_days, Some(14));

        let pro = plans.get("pro").unwrap();
        assert_eq!(pro.trial_days, None);
    }

    #[test]
    fn test_compare_plans_upgrade() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .included_seats(3)
            .features(["reports"])
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .included_seats(5)
            .features(["reports", "api_access", "priority_support"])
            .done()
            .build();

        let starter = plans.get("starter").unwrap();
        let pro = plans.get("pro").unwrap();

        let comparison = compare_plans(starter, pro);
        assert_eq!(comparison.change_type, PlanChangeType::Upgrade);
        assert!(comparison.features_gained.contains("api_access"));
        assert!(comparison.features_gained.contains("priority_support"));
        assert!(comparison.features_lost.is_empty());
        assert_eq!(comparison.seat_difference, 2);
        assert!(comparison.is_safe());
    }

    #[test]
    fn test_compare_plans_downgrade() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .included_seats(3)
            .features(["reports"])
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .included_seats(5)
            .features(["reports", "api_access"])
            .done()
            .build();

        let starter = plans.get("starter").unwrap();
        let pro = plans.get("pro").unwrap();

        let comparison = compare_plans(pro, starter);
        assert_eq!(comparison.change_type, PlanChangeType::Downgrade);
        assert!(comparison.features_lost.contains("api_access"));
        assert!(comparison.features_gained.is_empty());
        assert_eq!(comparison.seat_difference, -2);
        assert!(comparison.requires_confirmation());
    }

    #[test]
    fn test_compare_plans_no_change() {
        let plans = Plans::builder()
            .plan("starter")
            .stripe_price("price_starter")
            .features(["reports"])
            .done()
            .build();

        let starter = plans.get("starter").unwrap();

        let comparison = compare_plans(starter, starter);
        assert_eq!(comparison.change_type, PlanChangeType::NoChange);
    }

    #[test]
    fn test_compare_plans_lateral() {
        let plans = Plans::builder()
            .plan("monthly")
            .stripe_price("price_monthly")
            .included_seats(5)
            .features(["reports", "api_access"])
            .done()
            .plan("yearly")
            .stripe_price("price_yearly")
            .included_seats(5)
            .features(["reports", "api_access"])
            .done()
            .build();

        let monthly = plans.get("monthly").unwrap();
        let yearly = plans.get("yearly").unwrap();

        let comparison = compare_plans(monthly, yearly);
        assert_eq!(comparison.change_type, PlanChangeType::Lateral);
    }

    #[test]
    fn test_can_downgrade_allowed() {
        let plans = Plans::builder()
            .plan("pro")
            .stripe_price("price_pro")
            .extra_seat_price("price_seat")
            .included_seats(5)
            .done()
            .plan("starter")
            .stripe_price("price_starter")
            .included_seats(3)
            .done()
            .build();

        let pro = plans.get("pro").unwrap();
        let starter = plans.get("starter").unwrap();

        // 3 members, 0 extra seats - fits in starter's 3 included seats
        assert!(can_downgrade(pro, starter, 0, 3).is_ok());
    }

    #[test]
    fn test_can_downgrade_insufficient_seats() {
        let plans = Plans::builder()
            .plan("pro")
            .stripe_price("price_pro")
            .extra_seat_price("price_seat")
            .included_seats(10)
            .done()
            .plan("starter")
            .stripe_price("price_starter")
            .included_seats(3)
            .done()
            .build();

        let pro = plans.get("pro").unwrap();
        let starter = plans.get("starter").unwrap();

        // 8 members won't fit in starter's 3 seats
        let result = can_downgrade(pro, starter, 0, 8);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PlanDowngradeError::InsufficientSeats { current_members: 8, new_seats: 3 }
        ));
    }

    #[test]
    fn test_can_downgrade_with_extra_seats_that_fit() {
        let plans = Plans::builder()
            .plan("pro")
            .stripe_price("price_pro")
            .extra_seat_price("price_seat")
            .included_seats(5)
            .done()
            .plan("basic")
            .stripe_price("price_basic")
            .included_seats(10) // More included seats, but no extra seats support
            .done()
            .build();

        let pro = plans.get("pro").unwrap();
        let basic = plans.get("basic").unwrap();

        // Currently on pro with 2 extra seats, 5 members
        // Downgrading to basic (10 included) - 5 members easily fits
        let result = can_downgrade(pro, basic, 2, 5);
        assert!(result.is_ok());

        // 10 members would also fit
        let result = can_downgrade(pro, basic, 5, 10);
        assert!(result.is_ok());

        // 11 members wouldn't fit
        let result = can_downgrade(pro, basic, 6, 11);
        assert!(result.is_err());
    }

    #[test]
    fn test_suggest_upgrades() {
        let plans = Plans::builder()
            .plan("free")
            .stripe_price("price_free")
            .features(["basic"])
            .done()
            .plan("starter")
            .stripe_price("price_starter")
            .features(["basic", "reports"])
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .features(["basic", "reports", "api_access"])
            .done()
            .plan("enterprise")
            .stripe_price("price_enterprise")
            .features(["basic", "reports", "api_access", "sso", "audit"])
            .done()
            .build();

        let free = plans.get("free").unwrap();
        let suggestions = plans.suggest_upgrades(free);

        // All plans are supersets of free, sorted by feature count desc
        assert_eq!(suggestions.len(), 3);
        assert_eq!(suggestions[0].id, "enterprise"); // Most features
        assert_eq!(suggestions[1].id, "pro");
        assert_eq!(suggestions[2].id, "starter"); // Fewest additional features
    }

    #[test]
    fn test_next_tier_up() {
        let plans = Plans::builder()
            .plan("free")
            .stripe_price("price_free")
            .features(["basic"])
            .done()
            .plan("starter")
            .stripe_price("price_starter")
            .features(["basic", "reports"])
            .done()
            .plan("pro")
            .stripe_price("price_pro")
            .features(["basic", "reports", "api_access"])
            .done()
            .build();

        let free = plans.get("free").unwrap();
        let next = plans.next_tier_up(free);

        assert!(next.is_some());
        assert_eq!(next.unwrap().id, "starter"); // Minimal upgrade
    }

    #[test]
    fn test_plan_change_type_display() {
        assert_eq!(PlanChangeType::Upgrade.to_string(), "upgrade");
        assert_eq!(PlanChangeType::Downgrade.to_string(), "downgrade");
        assert_eq!(PlanChangeType::Lateral.to_string(), "lateral");
        assert_eq!(PlanChangeType::NoChange.to_string(), "no_change");
    }

    #[test]
    fn test_plan_downgrade_error_display() {
        let err = PlanDowngradeError::InsufficientSeats {
            current_members: 10,
            new_seats: 3,
        };
        assert!(err.to_string().contains("10 members"));
        assert!(err.to_string().contains("3 seats"));

        let err = PlanDowngradeError::ExtraSeatsRequired { extra_needed: 5 };
        assert!(err.to_string().contains("5 extra seats"));
    }
}
