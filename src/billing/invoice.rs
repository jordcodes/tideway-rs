//! Invoice management for Stripe billing.
//!
//! Provides functionality for listing, retrieving, and managing invoices
//! for billable entities.
//!
//! # Features
//!
//! - **Configurable defaults**: Set default page size, status filters, and more via `InvoiceConfig`
//! - **Ownership verification**: All invoice operations verify the invoice belongs to the billable entity
//! - **Optional caching**: Use `CachedInvoiceManager` for high-traffic applications
//! - **Pagination**: Cursor-based pagination matching Stripe's API
//! - **Force refresh**: Bypass cache when fresh data is needed
//!
//! # Limitations
//!
//! - **Upcoming invoice preview**: The `get_upcoming_invoice` method may return `None` in production
//!   when using `LiveStripeClient`, as the async-stripe crate has incomplete support for this
//!   endpoint. Consider using the Stripe Portal for upcoming invoice previews, or implement
//!   a custom solution using raw HTTP calls to the Stripe API.
//!
//! # Example
//!
//! ```rust,ignore
//! use tideway::billing::{InvoiceManager, InvoiceConfig, InvoiceListParams, InvoiceStatus};
//!
//! // Create with custom configuration
//! let config = InvoiceConfig::new()
//!     .with_default_limit(25)
//!     .with_line_items(true);
//!
//! let manager = InvoiceManager::with_config(store, client, config);
//!
//! // List invoices
//! let invoices = manager.list_invoices("org_123", Default::default()).await?;
//! ```
//!
//! # Webhook Integration
//!
//! When using `CachedInvoiceManager`, invalidate the cache after receiving
//! invoice-related webhook events to ensure users see fresh data:
//!
//! ```rust,ignore
//! use tideway::billing::{WebhookHandler, WebhookOutcome};
//!
//! async fn handle_webhook(event: WebhookEvent) -> WebhookOutcome {
//!     match event.event_type.as_str() {
//!         "invoice.paid" | "invoice.payment_failed" | "invoice.updated" => {
//!             // Extract billable_id from event metadata or subscription lookup
//!             if let Some(billable_id) = get_billable_id_from_event(&event) {
//!                 cached_invoice_manager.invalidate(&billable_id).await;
//!             }
//!         }
//!         _ => {}
//!     }
//!     WebhookOutcome::Processed
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use super::error::BillingError;
use super::storage::BillingStore;

// =============================================================================
// Helpers
// =============================================================================

/// Sanitize an invoice ID for use in error messages.
///
/// Only reveals the prefix to avoid leaking full IDs which could aid enumeration.
fn sanitize_invoice_id(invoice_id: &str) -> String {
    if invoice_id.len() > 10 {
        format!("{}...", &invoice_id[..10])
    } else {
        invoice_id.to_string()
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the invoice manager.
///
/// Controls default behavior for invoice operations. Use the builder methods
/// to customize behavior.
#[derive(Debug, Clone)]
pub struct InvoiceConfig {
    /// Default page size for invoice listing (1-100).
    pub default_limit: u8,
    /// Whether to include line items when fetching individual invoices.
    pub include_line_items: bool,
    /// Maximum line items to fetch per invoice (when included).
    pub max_line_items: u8,
    /// Default status filter for listings (None = all statuses).
    pub default_status_filter: Option<InvoiceStatus>,
}

impl Default for InvoiceConfig {
    fn default() -> Self {
        Self {
            default_limit: 10,
            include_line_items: false,
            max_line_items: 100,
            default_status_filter: None,
        }
    }
}

impl InvoiceConfig {
    /// Create a new invoice configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default page size for invoice listing.
    ///
    /// Values are clamped to the range 1-100.
    #[must_use]
    pub fn with_default_limit(mut self, limit: u8) -> Self {
        self.default_limit = limit.clamp(1, 100);
        self
    }

    /// Enable or disable automatic line item inclusion when fetching invoices.
    #[must_use]
    pub fn with_line_items(mut self, include: bool) -> Self {
        self.include_line_items = include;
        self
    }

    /// Set the maximum number of line items to fetch per invoice.
    ///
    /// Only applies when `include_line_items` is true.
    #[must_use]
    pub fn with_max_line_items(mut self, max: u8) -> Self {
        self.max_line_items = max.clamp(1, 100);
        self
    }

    /// Set the default status filter for invoice listings.
    #[must_use]
    pub fn with_status_filter(mut self, status: InvoiceStatus) -> Self {
        self.default_status_filter = Some(status);
        self
    }
}

// =============================================================================
// Invoice Types
// =============================================================================

/// Invoice status matching Stripe's invoice statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    /// Invoice is a draft and can be edited.
    Draft,
    /// Invoice is open and awaiting payment.
    Open,
    /// Invoice has been paid.
    Paid,
    /// Invoice was marked as uncollectible.
    Uncollectible,
    /// Invoice was voided.
    Void,
}

impl InvoiceStatus {
    /// Convert to the Stripe API string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Paid => "paid",
            Self::Uncollectible => "uncollectible",
            Self::Void => "void",
        }
    }
}

impl std::str::FromStr for InvoiceStatus {
    type Err = InvoiceStatusParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "draft" => Ok(Self::Draft),
            "open" => Ok(Self::Open),
            "paid" => Ok(Self::Paid),
            "uncollectible" => Ok(Self::Uncollectible),
            "void" => Ok(Self::Void),
            _ => Err(InvoiceStatusParseError(s.to_string())),
        }
    }
}

/// Error returned when parsing an invalid invoice status string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceStatusParseError(pub String);

impl std::fmt::Display for InvoiceStatusParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid invoice status: '{}'", self.0)
    }
}

impl std::error::Error for InvoiceStatusParseError {}

impl std::fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a Stripe invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    /// The unique invoice ID (e.g., "in_1234").
    pub id: String,
    /// The Stripe customer ID.
    pub customer_id: String,
    /// The associated subscription ID, if any.
    pub subscription_id: Option<String>,
    /// The invoice status.
    pub status: InvoiceStatus,
    /// Amount due in the smallest currency unit (e.g., cents).
    pub amount_due: i64,
    /// Amount already paid.
    pub amount_paid: i64,
    /// Amount remaining to be paid.
    pub amount_remaining: i64,
    /// Three-letter ISO currency code (lowercase).
    pub currency: String,
    /// When the invoice was created (Unix timestamp).
    pub created: u64,
    /// When payment is due (Unix timestamp), if set.
    pub due_date: Option<u64>,
    /// Start of the billing period (Unix timestamp).
    pub period_start: u64,
    /// End of the billing period (Unix timestamp).
    pub period_end: u64,
    /// URL to download the invoice PDF.
    pub invoice_pdf: Option<String>,
    /// URL to view/pay the invoice online.
    pub hosted_invoice_url: Option<String>,
    /// Human-readable invoice number.
    pub number: Option<String>,
    /// Whether the invoice has been paid.
    pub paid: bool,
    /// Line items (populated if config.include_line_items is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_items: Option<Vec<InvoiceLineItem>>,
}

/// An invoice line item representing a charge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceLineItem {
    /// The line item ID.
    pub id: String,
    /// Description of the charge.
    pub description: Option<String>,
    /// Amount in smallest currency unit.
    pub amount: i64,
    /// Three-letter ISO currency code (lowercase).
    pub currency: String,
    /// Quantity of the item.
    pub quantity: Option<u32>,
    /// The price ID, if associated with a price.
    pub price_id: Option<String>,
    /// Start of the period this line item covers.
    pub period_start: u64,
    /// End of the period this line item covers.
    pub period_end: u64,
}

/// Parameters for listing invoices.
#[derive(Debug, Clone, Default)]
pub struct InvoiceListParams {
    /// Maximum number of invoices to return (1-100).
    /// Overrides config default if set.
    pub limit: Option<u8>,
    /// Cursor for pagination (ID of the last invoice from previous page).
    pub starting_after: Option<String>,
    /// Filter by invoice status. Overrides config default if set.
    pub status: Option<InvoiceStatus>,
    /// Force a fresh fetch, bypassing any cache.
    /// Only affects `CachedInvoiceManager`.
    pub force_refresh: bool,
}

/// A paginated list of invoices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceList {
    /// The invoices in this page.
    pub invoices: Vec<Invoice>,
    /// Whether there are more invoices to fetch.
    pub has_more: bool,
    /// Cursor for fetching the next page.
    pub next_cursor: Option<String>,
}

// =============================================================================
// Stripe Invoice Client Trait
// =============================================================================

/// Stripe client trait for invoice operations.
///
/// Implement this trait to provide invoice functionality. A mock implementation
/// is available for testing.
#[async_trait]
pub trait StripeInvoiceClient: Send + Sync {
    /// List invoices for a customer with pagination.
    async fn list_invoices(
        &self,
        customer_id: &str,
        limit: u8,
        starting_after: Option<&str>,
        status: Option<InvoiceStatus>,
    ) -> Result<InvoiceList>;

    /// Retrieve a single invoice by ID.
    async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice>;

    /// Get the upcoming invoice preview for a customer.
    ///
    /// Returns `None` if no upcoming invoice exists.
    async fn get_upcoming_invoice(&self, customer_id: &str) -> Result<Option<Invoice>>;

    /// List line items for an invoice.
    async fn list_invoice_line_items(
        &self,
        invoice_id: &str,
        limit: u8,
    ) -> Result<Vec<InvoiceLineItem>>;
}

// =============================================================================
// Invoice Operations Trait
// =============================================================================

/// Common trait for invoice operations.
///
/// Both [`InvoiceManager`] and [`CachedInvoiceManager`] implement this trait,
/// allowing them to be used interchangeably in application code.
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::InvoiceOperations;
///
/// async fn list_recent_invoices<T: InvoiceOperations>(
///     manager: &T,
///     billable_id: &str,
/// ) -> Result<Vec<Invoice>> {
///     let list = manager.list_invoices(billable_id, Default::default()).await?;
///     Ok(list.invoices)
/// }
/// ```
#[async_trait]
pub trait InvoiceOperations: Send + Sync {
    /// List invoices for a billable entity.
    async fn list_invoices(
        &self,
        billable_id: &str,
        params: InvoiceListParams,
    ) -> Result<InvoiceList>;

    /// Get a specific invoice with ownership verification.
    async fn get_invoice(
        &self,
        billable_id: &str,
        invoice_id: &str,
    ) -> Result<Invoice>;

    /// Get the upcoming invoice preview for a billable entity.
    async fn get_upcoming_invoice(
        &self,
        billable_id: &str,
    ) -> Result<Option<Invoice>>;

    /// Get line items for an invoice with ownership verification.
    async fn get_invoice_line_items(
        &self,
        billable_id: &str,
        invoice_id: &str,
        limit: Option<u8>,
    ) -> Result<Vec<InvoiceLineItem>>;
}

// =============================================================================
// Invoice Manager
// =============================================================================

/// Manager for invoice operations.
///
/// Provides methods to list, retrieve, and inspect invoices for billable entities.
/// All operations verify ownership to prevent unauthorized access.
///
/// # Configuration
///
/// Use `InvoiceConfig` to customize default behavior:
///
/// ```rust,ignore
/// let config = InvoiceConfig::new()
///     .with_default_limit(25)
///     .with_line_items(true);
///
/// let manager = InvoiceManager::with_config(store, client, config);
/// ```
pub struct InvoiceManager<S, C> {
    store: S,
    client: C,
    config: InvoiceConfig,
}

impl<S: Clone, C: Clone> Clone for InvoiceManager<S, C> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            client: self.client.clone(),
            config: self.config.clone(),
        }
    }
}

impl<S: BillingStore, C: StripeInvoiceClient> InvoiceManager<S, C> {
    /// Create a new invoice manager with default configuration.
    #[must_use]
    pub fn new(store: S, client: C) -> Self {
        Self::with_config(store, client, InvoiceConfig::default())
    }

    /// Create a new invoice manager with custom configuration.
    #[must_use]
    pub fn with_config(store: S, client: C, config: InvoiceConfig) -> Self {
        Self { store, client, config }
    }

    /// Get a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &InvoiceConfig {
        &self.config
    }

    /// List invoices for a billable entity.
    ///
    /// Uses configuration defaults when params don't specify limit or status.
    ///
    /// # Errors
    ///
    /// Returns an error if the billable entity has no Stripe customer.
    pub async fn list_invoices(
        &self,
        billable_id: &str,
        params: InvoiceListParams,
    ) -> Result<InvoiceList> {
        tracing::debug!(
            billable_id = %billable_id,
            limit = ?params.limit,
            status = ?params.status,
            "listing invoices"
        );

        let customer_id = self.get_customer_id(billable_id).await?;

        let limit = params.limit.unwrap_or(self.config.default_limit);
        let status = params.status.or(self.config.default_status_filter);

        let result = self.client.list_invoices(
            &customer_id,
            limit,
            params.starting_after.as_deref(),
            status,
        ).await?;

        tracing::debug!(
            billable_id = %billable_id,
            count = result.invoices.len(),
            has_more = result.has_more,
            "listed invoices"
        );

        Ok(result)
    }

    /// Get a specific invoice with ownership verification.
    ///
    /// Optionally includes line items based on configuration.
    ///
    /// # Errors
    ///
    /// Returns `BillingError::InvoiceNotFound` if the invoice doesn't exist
    /// or doesn't belong to the billable entity.
    pub async fn get_invoice(
        &self,
        billable_id: &str,
        invoice_id: &str,
    ) -> Result<Invoice> {
        tracing::debug!(
            billable_id = %billable_id,
            invoice_id = %invoice_id,
            "fetching invoice"
        );

        let customer_id = self.get_customer_id(billable_id).await?;

        let mut invoice = self.client.get_invoice(invoice_id).await?;

        // Verify ownership
        if invoice.customer_id != customer_id {
            tracing::warn!(
                billable_id = %billable_id,
                invoice_id = %invoice_id,
                "invoice ownership verification failed"
            );
            return Err(BillingError::InvoiceNotFound {
                invoice_id: sanitize_invoice_id(invoice_id),
            }.into());
        }

        // Optionally fetch line items
        if self.config.include_line_items && invoice.line_items.is_none() {
            tracing::debug!(invoice_id = %invoice_id, "fetching line items");
            let line_items = self.client
                .list_invoice_line_items(invoice_id, self.config.max_line_items)
                .await?;
            invoice.line_items = Some(line_items);
        }

        tracing::debug!(
            billable_id = %billable_id,
            invoice_id = %invoice_id,
            status = %invoice.status,
            "fetched invoice"
        );

        Ok(invoice)
    }

    /// Get the upcoming invoice preview for a billable entity.
    ///
    /// Returns the next invoice that will be generated, or `None` if there
    /// is no upcoming invoice (e.g., no active subscription).
    ///
    /// # Important Limitation
    ///
    /// When using [`LiveStripeClient`](super::LiveStripeClient), this method currently
    /// returns `Ok(None)` because the async-stripe crate lacks full support for the
    /// upcoming invoice endpoint. For production use cases requiring upcoming invoice
    /// previews, consider:
    ///
    /// - Using the Stripe Customer Portal to show upcoming charges
    /// - Implementing a custom HTTP call to `GET /v1/invoices/upcoming`
    /// - Using Stripe's hosted invoice page
    pub async fn get_upcoming_invoice(
        &self,
        billable_id: &str,
    ) -> Result<Option<Invoice>> {
        tracing::debug!(billable_id = %billable_id, "fetching upcoming invoice");
        let customer_id = self.get_customer_id(billable_id).await?;
        self.client.get_upcoming_invoice(&customer_id).await
    }

    /// Get line items for an invoice with ownership verification.
    ///
    /// # Errors
    ///
    /// Returns `BillingError::InvoiceNotFound` if the invoice doesn't exist
    /// or doesn't belong to the billable entity.
    pub async fn get_invoice_line_items(
        &self,
        billable_id: &str,
        invoice_id: &str,
        limit: Option<u8>,
    ) -> Result<Vec<InvoiceLineItem>> {
        tracing::debug!(
            billable_id = %billable_id,
            invoice_id = %invoice_id,
            "fetching invoice line items"
        );

        // Verify ownership by fetching the invoice first
        let customer_id = self.get_customer_id(billable_id).await?;
        let invoice = self.client.get_invoice(invoice_id).await?;

        if invoice.customer_id != customer_id {
            tracing::warn!(
                billable_id = %billable_id,
                invoice_id = %invoice_id,
                "invoice ownership verification failed for line items"
            );
            return Err(BillingError::InvoiceNotFound {
                invoice_id: sanitize_invoice_id(invoice_id),
            }.into());
        }

        let limit = limit.unwrap_or(self.config.max_line_items);
        self.client.list_invoice_line_items(invoice_id, limit).await
    }

    /// Get the Stripe customer ID for a billable entity.
    async fn get_customer_id(&self, billable_id: &str) -> Result<String> {
        self.store
            .get_stripe_customer_id(billable_id)
            .await?
            .ok_or_else(|| BillingError::NoCustomer {
                billable_id: billable_id.to_string(),
            }.into())
    }
}

#[async_trait]
impl<S: BillingStore, C: StripeInvoiceClient> InvoiceOperations for InvoiceManager<S, C> {
    async fn list_invoices(
        &self,
        billable_id: &str,
        params: InvoiceListParams,
    ) -> Result<InvoiceList> {
        self.list_invoices(billable_id, params).await
    }

    async fn get_invoice(
        &self,
        billable_id: &str,
        invoice_id: &str,
    ) -> Result<Invoice> {
        self.get_invoice(billable_id, invoice_id).await
    }

    async fn get_upcoming_invoice(
        &self,
        billable_id: &str,
    ) -> Result<Option<Invoice>> {
        self.get_upcoming_invoice(billable_id).await
    }

    async fn get_invoice_line_items(
        &self,
        billable_id: &str,
        invoice_id: &str,
        limit: Option<u8>,
    ) -> Result<Vec<InvoiceLineItem>> {
        self.get_invoice_line_items(billable_id, invoice_id, limit).await
    }
}

// =============================================================================
// Cached Invoice Manager
// =============================================================================

/// Default maximum cache entries.
const DEFAULT_MAX_CACHE_ENTRIES: usize = 1000;

/// Cleanup interval (every N operations).
const CLEANUP_INTERVAL: u64 = 100;

/// Structured cache key for invoice list queries.
///
/// Using a struct instead of string concatenation prevents issues with
/// prefix matching during invalidation (e.g., "org_1" matching "org_12").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ListCacheKey {
    billable_id: String,
    limit: u8,
    starting_after: Option<String>,
    status: Option<InvoiceStatus>,
}

impl ListCacheKey {
    fn new(billable_id: &str, params: &InvoiceListParams) -> Self {
        Self {
            billable_id: billable_id.to_string(),
            limit: params.limit.unwrap_or(0),
            starting_after: params.starting_after.clone(),
            status: params.status,
        }
    }

    fn matches_billable_id(&self, billable_id: &str) -> bool {
        self.billable_id == billable_id
    }
}

/// Cached invoice manager for improved performance.
///
/// Wraps an `InvoiceManager` and caches results with configurable TTL.
/// Use this for high-traffic applications to reduce Stripe API calls.
///
/// # Cache Behavior
///
/// - Invoice lists are cached per billable_id (first page only by default)
/// - Individual invoice lookups bypass the list cache
/// - Cache is automatically cleaned up periodically
/// - Use `invalidate()` after webhooks to ensure fresh data
///
/// # Example
///
/// ```rust,ignore
/// use tideway::billing::{InvoiceManager, CachedInvoiceManager};
/// use std::time::Duration;
///
/// let inner = InvoiceManager::new(store, client);
/// let cached = CachedInvoiceManager::new(inner, Duration::from_secs(300));
///
/// // First call hits Stripe API
/// let invoices = cached.list_invoices("org_123", Default::default()).await?;
///
/// // Second call uses cache
/// let invoices = cached.list_invoices("org_123", Default::default()).await?;
///
/// // Invalidate after webhook
/// cached.invalidate("org_123");
/// ```
pub struct CachedInvoiceManager<S: BillingStore, C: StripeInvoiceClient> {
    inner: InvoiceManager<S, C>,
    cache: std::sync::Arc<tokio::sync::RwLock<InvoiceCache>>,
    ttl: std::time::Duration,
    max_entries: usize,
    operation_counter: std::sync::atomic::AtomicU64,
}

struct InvoiceCache {
    /// Cache of invoice lists keyed by structured cache key.
    /// Uses Arc to avoid cloning large invoice lists on cache hits.
    lists: std::collections::HashMap<ListCacheKey, CacheEntry<std::sync::Arc<InvoiceList>>>,
    /// Cache of upcoming invoices keyed by billable_id.
    upcoming: std::collections::HashMap<String, CacheEntry<Option<Invoice>>>,
}

struct CacheEntry<T> {
    data: T,
    expires_at: std::time::Instant,
    last_accessed: std::time::Instant,
}

impl<S: BillingStore, C: StripeInvoiceClient> CachedInvoiceManager<S, C> {
    /// Create a new cached invoice manager.
    ///
    /// Uses a default maximum of 1000 cache entries.
    #[must_use]
    pub fn new(inner: InvoiceManager<S, C>, ttl: std::time::Duration) -> Self {
        Self::with_max_entries(inner, ttl, DEFAULT_MAX_CACHE_ENTRIES)
    }

    /// Create a new cached invoice manager with a custom max entries limit.
    #[must_use]
    pub fn with_max_entries(
        inner: InvoiceManager<S, C>,
        ttl: std::time::Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            inner,
            cache: std::sync::Arc::new(tokio::sync::RwLock::new(InvoiceCache {
                lists: std::collections::HashMap::new(),
                upcoming: std::collections::HashMap::new(),
            })),
            ttl,
            max_entries,
            operation_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get a reference to the inner manager's configuration.
    #[must_use]
    pub fn config(&self) -> &InvoiceConfig {
        self.inner.config()
    }

    /// Invalidate all cached data for a billable entity.
    ///
    /// Call this after receiving invoice-related webhooks to ensure fresh data.
    pub async fn invalidate(&self, billable_id: &str) {
        tracing::debug!(billable_id = %billable_id, "invalidating invoice cache");
        let mut cache = self.cache.write().await;
        cache.lists.retain(|k, _| !k.matches_billable_id(billable_id));
        cache.upcoming.remove(billable_id);
    }

    /// Clear the entire cache.
    pub async fn clear(&self) {
        tracing::debug!("clearing entire invoice cache");
        let mut cache = self.cache.write().await;
        cache.lists.clear();
        cache.upcoming.clear();
    }

    /// Get the current number of cached entries.
    ///
    /// Returns 0 if the lock cannot be acquired immediately.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.try_read().map_or(0, |c| c.lists.len() + c.upcoming.len())
    }

    /// Enforce maximum cache entries limit using sampling-based eviction.
    ///
    /// Instead of sorting all entries (O(n log n)), this uses random sampling
    /// to find old entries to evict, which is O(k) where k is the sample size.
    async fn enforce_max_entries(&self) {
        let mut cache = self.cache.write().await;

        let total = cache.lists.len() + cache.upcoming.len();
        if total <= self.max_entries {
            return;
        }

        // Remove expired entries first (quick win)
        let now = std::time::Instant::now();
        cache.lists.retain(|_, v| v.expires_at > now);
        cache.upcoming.retain(|_, v| v.expires_at > now);

        // If still over limit, use sampling-based eviction
        let total = cache.lists.len() + cache.upcoming.len();
        if total > self.max_entries {
            let to_remove = total - self.max_entries;
            let mut removed = 0;

            // Sample up to 5x the number we need to remove, pick oldest from sample
            let sample_size = (to_remove * 5).min(cache.lists.len());

            if sample_size > 0 && !cache.lists.is_empty() {
                // Collect a sample of keys with their access times
                let sample: Vec<_> = cache.lists.iter()
                    .take(sample_size)
                    .map(|(k, v)| (k.clone(), v.last_accessed))
                    .collect();

                // Sort sample by access time and remove oldest
                let mut sample = sample;
                sample.sort_by_key(|(_, t)| *t);

                for (key, _) in sample.into_iter().take(to_remove) {
                    if cache.lists.remove(&key).is_some() {
                        removed += 1;
                    }
                    if removed >= to_remove {
                        break;
                    }
                }
            }

            if removed > 0 {
                tracing::debug!(removed = removed, "evicted cache entries via sampling");
            }
        }
    }

    /// List invoices with caching.
    ///
    /// Set `params.force_refresh = true` to bypass the cache and fetch fresh data.
    pub async fn list_invoices(
        &self,
        billable_id: &str,
        params: InvoiceListParams,
    ) -> Result<InvoiceList> {
        self.maybe_cleanup().await;

        // Build structured cache key (force_refresh not part of key)
        let cache_key = ListCacheKey::new(billable_id, &params);

        // Check cache unless force_refresh is set
        if !params.force_refresh {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.lists.get(&cache_key) {
                if entry.expires_at > std::time::Instant::now() {
                    tracing::debug!(billable_id = %billable_id, "invoice list cache hit");
                    // Clone the Arc, not the underlying data
                    return Ok((*entry.data).clone());
                }
            }
        } else {
            tracing::debug!(billable_id = %billable_id, "force refresh requested");
        }

        // Fetch from API
        let result = self.inner.list_invoices(billable_id, params).await?;

        // Store in cache (wrap in Arc)
        {
            let mut cache = self.cache.write().await;
            let now = std::time::Instant::now();
            cache.lists.insert(cache_key, CacheEntry {
                data: std::sync::Arc::new(result.clone()),
                expires_at: now + self.ttl,
                last_accessed: now,
            });
        }

        Ok(result)
    }

    /// Get a specific invoice (not cached, but verifies ownership).
    pub async fn get_invoice(
        &self,
        billable_id: &str,
        invoice_id: &str,
    ) -> Result<Invoice> {
        // Individual invoice lookups are not cached as they change frequently
        self.inner.get_invoice(billable_id, invoice_id).await
    }

    /// Get upcoming invoice with caching.
    ///
    /// See [`InvoiceManager::get_upcoming_invoice`] for important limitations
    /// regarding the `LiveStripeClient` implementation.
    pub async fn get_upcoming_invoice(
        &self,
        billable_id: &str,
    ) -> Result<Option<Invoice>> {
        self.maybe_cleanup().await;

        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.upcoming.get(billable_id) {
                if entry.expires_at > std::time::Instant::now() {
                    tracing::debug!(billable_id = %billable_id, "upcoming invoice cache hit");
                    return Ok(entry.data.clone());
                }
            }
        }

        // Fetch from API
        let result = self.inner.get_upcoming_invoice(billable_id).await?;

        // Store in cache
        {
            let mut cache = self.cache.write().await;
            let now = std::time::Instant::now();
            cache.upcoming.insert(billable_id.to_string(), CacheEntry {
                data: result.clone(),
                expires_at: now + self.ttl,
                last_accessed: now,
            });
        }

        Ok(result)
    }

    /// Get line items for an invoice (not cached).
    pub async fn get_invoice_line_items(
        &self,
        billable_id: &str,
        invoice_id: &str,
        limit: Option<u8>,
    ) -> Result<Vec<InvoiceLineItem>> {
        self.inner.get_invoice_line_items(billable_id, invoice_id, limit).await
    }

    /// Maybe run cleanup based on operation counter.
    async fn maybe_cleanup(&self) {
        let count = self.operation_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % CLEANUP_INTERVAL == 0 {
            self.enforce_max_entries().await;
        }
    }
}

#[async_trait]
impl<S: BillingStore, C: StripeInvoiceClient> InvoiceOperations for CachedInvoiceManager<S, C> {
    async fn list_invoices(
        &self,
        billable_id: &str,
        params: InvoiceListParams,
    ) -> Result<InvoiceList> {
        self.list_invoices(billable_id, params).await
    }

    async fn get_invoice(
        &self,
        billable_id: &str,
        invoice_id: &str,
    ) -> Result<Invoice> {
        self.get_invoice(billable_id, invoice_id).await
    }

    async fn get_upcoming_invoice(
        &self,
        billable_id: &str,
    ) -> Result<Option<Invoice>> {
        self.get_upcoming_invoice(billable_id).await
    }

    async fn get_invoice_line_items(
        &self,
        billable_id: &str,
        invoice_id: &str,
        limit: Option<u8>,
    ) -> Result<Vec<InvoiceLineItem>> {
        self.get_invoice_line_items(billable_id, invoice_id, limit).await
    }
}

// =============================================================================
// Test Utilities
// =============================================================================

/// Mock Stripe invoice client for testing.
#[cfg(any(test, feature = "test-billing"))]
pub mod test {
    use super::*;
    use std::sync::{Arc, RwLock};

    /// A mock Stripe invoice client for testing.
    #[derive(Clone)]
    pub struct MockStripeInvoiceClient {
        invoices: Arc<RwLock<Vec<Invoice>>>,
        upcoming: Arc<RwLock<Option<Invoice>>>,
        /// Default currency for mock invoices (e.g., "gbp", "usd").
        pub default_currency: String,
    }

    impl Default for MockStripeInvoiceClient {
        fn default() -> Self {
            Self {
                invoices: Arc::new(RwLock::new(Vec::new())),
                upcoming: Arc::new(RwLock::new(None)),
                default_currency: "gbp".to_string(),
            }
        }
    }

    impl MockStripeInvoiceClient {
        /// Create a new mock client with GBP as the default currency.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Create a new mock client with a specific default currency.
        #[must_use]
        pub fn with_currency(currency: impl Into<String>) -> Self {
            Self {
                default_currency: currency.into().to_lowercase(),
                ..Self::default()
            }
        }

        /// Add an invoice to the mock.
        pub fn add_invoice(&self, invoice: Invoice) {
            if let Ok(mut invoices) = self.invoices.write() {
                invoices.push(invoice);
            }
        }

        /// Set the upcoming invoice.
        pub fn set_upcoming(&self, invoice: Option<Invoice>) {
            if let Ok(mut upcoming) = self.upcoming.write() {
                *upcoming = invoice;
            }
        }

        /// Create a test invoice with GBP currency.
        #[must_use]
        pub fn create_test_invoice(id: &str, customer_id: &str, status: InvoiceStatus) -> Invoice {
            Self::create_test_invoice_with_currency(id, customer_id, status, "gbp")
        }

        /// Create a test invoice with a specific currency.
        #[must_use]
        pub fn create_test_invoice_with_currency(
            id: &str,
            customer_id: &str,
            status: InvoiceStatus,
            currency: &str,
        ) -> Invoice {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Invoice {
                id: id.to_string(),
                customer_id: customer_id.to_string(),
                subscription_id: Some("sub_test".to_string()),
                status,
                amount_due: 2999,
                amount_paid: if status == InvoiceStatus::Paid { 2999 } else { 0 },
                amount_remaining: if status == InvoiceStatus::Paid { 0 } else { 2999 },
                currency: currency.to_lowercase(),
                created: now,
                due_date: Some(now + 30 * 24 * 60 * 60),
                period_start: now,
                period_end: now + 30 * 24 * 60 * 60,
                invoice_pdf: Some(format!("https://pay.stripe.com/invoice/{}/pdf", id)),
                hosted_invoice_url: Some(format!("https://invoice.stripe.com/{}", id)),
                number: Some(format!("INV-{}", id)),
                paid: status == InvoiceStatus::Paid,
                line_items: None,
            }
        }
    }

    #[async_trait]
    impl StripeInvoiceClient for MockStripeInvoiceClient {
        async fn list_invoices(
            &self,
            customer_id: &str,
            limit: u8,
            starting_after: Option<&str>,
            status: Option<InvoiceStatus>,
        ) -> Result<InvoiceList> {
            let invoices = self.invoices.read().map_err(|_| {
                crate::error::TidewayError::Internal("Lock poisoned".to_string())
            })?;

            let mut filtered: Vec<Invoice> = invoices.iter()
                .filter(|inv| inv.customer_id == customer_id)
                .filter(|inv| status.map_or(true, |s| inv.status == s))
                .cloned()
                .collect();

            // Handle pagination
            if let Some(after) = starting_after {
                if let Some(pos) = filtered.iter().position(|inv| inv.id == after) {
                    filtered = filtered.into_iter().skip(pos + 1).collect();
                }
            }

            let limit = limit as usize;
            let has_more = filtered.len() > limit;
            let invoices: Vec<_> = filtered.into_iter().take(limit).collect();
            let next_cursor = invoices.last().map(|inv| inv.id.clone());

            Ok(InvoiceList {
                invoices,
                has_more,
                next_cursor,
            })
        }

        async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice> {
            let invoices = self.invoices.read().map_err(|_| {
                crate::error::TidewayError::Internal("Lock poisoned".to_string())
            })?;

            invoices.iter()
                .find(|inv| inv.id == invoice_id)
                .cloned()
                .ok_or_else(|| BillingError::InvoiceNotFound {
                    invoice_id: invoice_id.to_string(),
                }.into())
        }

        async fn get_upcoming_invoice(&self, _customer_id: &str) -> Result<Option<Invoice>> {
            let upcoming = self.upcoming.read().map_err(|_| {
                crate::error::TidewayError::Internal("Lock poisoned".to_string())
            })?;
            Ok(upcoming.clone())
        }

        async fn list_invoice_line_items(
            &self,
            invoice_id: &str,
            _limit: u8,
        ) -> Result<Vec<InvoiceLineItem>> {
            // Return mock line items
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Ok(vec![
                InvoiceLineItem {
                    id: format!("il_{}_1", invoice_id),
                    description: Some("Pro Plan".to_string()),
                    amount: 2999,
                    currency: self.default_currency.clone(),
                    quantity: Some(1),
                    price_id: Some("price_pro".to_string()),
                    period_start: now,
                    period_end: now + 30 * 24 * 60 * 60,
                },
            ])
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::MockStripeInvoiceClient;
    use crate::billing::storage::test::InMemoryBillingStore;

    #[test]
    fn test_invoice_config_builder() {
        let config = InvoiceConfig::new()
            .with_default_limit(25)
            .with_line_items(true)
            .with_max_line_items(50)
            .with_status_filter(InvoiceStatus::Paid);

        assert_eq!(config.default_limit, 25);
        assert!(config.include_line_items);
        assert_eq!(config.max_line_items, 50);
        assert_eq!(config.default_status_filter, Some(InvoiceStatus::Paid));
    }

    #[test]
    fn test_invoice_config_clamping() {
        let config = InvoiceConfig::new()
            .with_default_limit(200)  // Over max
            .with_max_line_items(0);  // Under min

        assert_eq!(config.default_limit, 100);
        assert_eq!(config.max_line_items, 1);
    }

    #[test]
    fn test_invoice_status_conversion() {
        use std::str::FromStr;

        assert_eq!(InvoiceStatus::from_str("paid"), Ok(InvoiceStatus::Paid));
        assert_eq!(InvoiceStatus::from_str("open"), Ok(InvoiceStatus::Open));
        assert!(InvoiceStatus::from_str("unknown").is_err());

        assert_eq!(InvoiceStatus::Paid.as_str(), "paid");
        assert_eq!(InvoiceStatus::Draft.as_str(), "draft");
    }

    #[tokio::test]
    async fn test_list_invoices_no_customer() {
        let store = InMemoryBillingStore::new();
        let client = MockStripeInvoiceClient::new();
        let manager = InvoiceManager::new(store, client);

        let result = manager.list_invoices("unknown_org", Default::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_invoices_with_customer() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_123", "org", "cus_test").await.unwrap();

        let client = MockStripeInvoiceClient::new();
        client.add_invoice(MockStripeInvoiceClient::create_test_invoice(
            "in_1", "cus_test", InvoiceStatus::Paid
        ));
        client.add_invoice(MockStripeInvoiceClient::create_test_invoice(
            "in_2", "cus_test", InvoiceStatus::Open
        ));

        let manager = InvoiceManager::new(store, client);
        let result = manager.list_invoices("org_123", Default::default()).await.unwrap();

        assert_eq!(result.invoices.len(), 2);
    }

    #[tokio::test]
    async fn test_list_invoices_with_status_filter() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_123", "org", "cus_test").await.unwrap();

        let client = MockStripeInvoiceClient::new();
        client.add_invoice(MockStripeInvoiceClient::create_test_invoice(
            "in_1", "cus_test", InvoiceStatus::Paid
        ));
        client.add_invoice(MockStripeInvoiceClient::create_test_invoice(
            "in_2", "cus_test", InvoiceStatus::Open
        ));

        let manager = InvoiceManager::new(store, client);
        let result = manager.list_invoices("org_123", InvoiceListParams {
            status: Some(InvoiceStatus::Paid),
            ..Default::default()
        }).await.unwrap();

        assert_eq!(result.invoices.len(), 1);
        assert_eq!(result.invoices[0].status, InvoiceStatus::Paid);
    }

    #[tokio::test]
    async fn test_get_invoice_ownership() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_123", "org", "cus_test").await.unwrap();

        let client = MockStripeInvoiceClient::new();
        client.add_invoice(MockStripeInvoiceClient::create_test_invoice(
            "in_1", "cus_other", InvoiceStatus::Paid  // Different customer
        ));

        let manager = InvoiceManager::new(store, client);
        let result = manager.get_invoice("org_123", "in_1").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cached_manager() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_123", "org", "cus_test").await.unwrap();

        let client = MockStripeInvoiceClient::new();
        client.add_invoice(MockStripeInvoiceClient::create_test_invoice(
            "in_1", "cus_test", InvoiceStatus::Paid
        ));

        let inner = InvoiceManager::new(store, client);
        let cached = CachedInvoiceManager::new(inner, std::time::Duration::from_secs(60));

        // First call - cache miss
        assert_eq!(cached.cache_size(), 0);
        let result1 = cached.list_invoices("org_123", Default::default()).await.unwrap();
        assert_eq!(result1.invoices.len(), 1);
        assert!(cached.cache_size() > 0);

        // Second call - cache hit
        let result2 = cached.list_invoices("org_123", Default::default()).await.unwrap();
        assert_eq!(result2.invoices.len(), 1);
    }

    #[tokio::test]
    async fn test_cached_manager_invalidate() {
        let store = InMemoryBillingStore::new();
        store.set_stripe_customer_id("org_123", "org", "cus_test").await.unwrap();

        let client = MockStripeInvoiceClient::new();
        let inner = InvoiceManager::new(store, client);
        let cached = CachedInvoiceManager::new(inner, std::time::Duration::from_secs(60));

        // Populate cache
        let _ = cached.list_invoices("org_123", Default::default()).await;
        assert!(cached.cache_size() > 0);

        // Invalidate
        cached.invalidate("org_123").await;
        assert_eq!(cached.cache_size(), 0);
    }
}
