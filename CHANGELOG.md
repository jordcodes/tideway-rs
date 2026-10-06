# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release owners: copy a short DX gate summary into the release notes and use `docs/dx_metrics_snapshot.md` as the source of record for DX reporting.

## [0.9.0] - Unreleased

> **Breaking changes for apps on `^0.8`.** Tideway 0.9.0 is not a drop-in update: applications
> using the APIs below stop compiling, so `cargo update` keeps `^0.8` applications on 0.8.x.
> Change the dependency to `0.9.0` and follow `docs/upgrading.md#08x-to-090-breaking-changes`.
>
> - `ImpersonationRequest` and `DeletionRequest` no longer derive `Deserialize`. Deserialize
>   `ImpersonationRequestBody` / `DeletionRequestBody` and call `into_request` with the
>   authenticated actor ID.
> - `WebSocketHandler::on_upgrade` is now `on_upgrade(&self, req: &mut UpgradeRequest, ctx: &AppContext)`.
>   Overrides must use the new signature.
> - `tideway::prelude` exports `DatabaseConnectionTrait` instead of `DatabaseConnection`. Rename
>   prelude references, or import `tideway::DatabaseConnection` directly.
> - `CachedInvoiceManager::list_invoices` returns `Arc<InvoiceList>` instead of `InvoiceList`, and
>   `CachedInvoiceManager::get_upcoming_invoice` returns `Option<Arc<Invoice>>` instead of
>   `Option<Invoice>`.
>
> Also breaking, see below: `SecureRefundManager::get_refund` takes the billable ID,
> `CreateRefundRequest` has a new `idempotency_key` field,
> `BillingEvent::OneTimeCheckoutCompleted`, `BillingEvent::InvoicePaid`,
> `BillingEvent::InvoicePaymentFailed`, and `Refund` have new fields, `CreditTransactionKind` is
> `#[non_exhaustive]`, `JobsConfig` has a new field, and `credits-seaorm` apps need a database
> migration.

- Added resource-level authorization policies in `tideway::policy`: a deny-by-default
  `Policy<Actor, Resource>` trait (`view_any`, `view`, `create`, `update`, `delete`, and a
  `before` hook), `RolePermissions` for attaching permission strings (with `*` and `resource.*`
  wildcards) to roles, and an `OrgActor` subject for organization-scoped records. On SaaS
  scaffolds, `tideway resource` with the `api`, `tenant`, or `owned` profile now generates
  `src/policies/<name>.rs` and authorizes every handler through it. By default, members can no
  longer delete `api`/`tenant` records; edit the generated grants to change this. Existing
  generated resources are unchanged. See `docs/organizations.md#resource-authorization-policies`.
- `ConfigBuilder::from_env()` now applies environment variables on top of existing builder
  values instead of replacing configured settings with defaults. Values set on the builder
  survive when the corresponding environment variables are absent; present environment
  variables still override them. Applications upgrading to 0.9.0 that relied on `from_env()`
  resetting settings should explicitly reset those values or start with `ConfigBuilder::new()`.
- Stripe 4xx errors no longer expose Stripe's message (for example "No such price…" or test/live
  mode mismatches) when converted to `TidewayError`. The full error is logged on the
  `tideway::billing::stripe` target instead. Stripe 404 now maps to HTTP 404, 429 to HTTP 429, and
  other 4xx statuses to HTTP 400 with a generic message. Stripe 402 card errors are the exception:
  users see Stripe's message (for example "Your card's security code is incorrect.") and the
  response `code` is Stripe's code (for example `incorrect_cvc`).
- Stripe API errors now convert to the new `TidewayError::Billing { public, source }` variant, so
  apps can read the original `BillingError::StripeApiError` (`message`, `code`, `http_status`)
  with `TidewayError::billing_error()`, including from `LiveStripeClient` calls. Code that matched
  Stripe failures as `TidewayError::NotFound`, `Internal`, and so on should match on
  `err.public_error()` instead. `StripeApiError::code` is now Stripe's snake_case code
  (`incorrect_cvc`) instead of the Rust variant name (`IncorrectCvc`). See `docs/upgrading.md`.
- `LiveStripeClient`'s circuit breaker now counts only provider failures (Stripe 5xx, 429 after
  retries, timeouts, and connection errors). Previously every failed call counted, so five
  consecutive card declines (`failure_threshold` default) opened the circuit and failed all Stripe
  calls for `open_duration_seconds`. A Stripe 4xx now resets the failure count and closes a
  half-open circuit, because Stripe answered.
- Added `OrganizationManager::transfer_ownership`, which also sets the organization's owner to the
  new owner. `MembershipManager::transfer_ownership` only swapped membership roles and left
  `owner_id` unchanged, so `max_orgs_per_user` kept counting a transferred organization against
  its former owner. The `MembershipManager` method is now deprecated. Organizations transferred
  with it keep the stale `owner_id`; see `docs/upgrading.md` to find and fix them. With the
  SeaORM store, `OrganizationManager::transfer_ownership_atomic` (backed by
  `SeaOrmOrgStore::transfer_ownership_atomic`) does the whole transfer in one transaction. Both
  methods return `MaxOrgsReached` if the new owner is already at `max_orgs_per_user`.
- `RedisCache::clear()` no longer runs `FLUSHDB`. It previously wiped the whole Redis database,
  including `RedisJobQueue` jobs when the cache and job queue shared a database. `RedisCache`
  now stores keys under a `cache:` prefix (configurable with `with_prefix`), and `clear()`
  deletes only keys with that prefix. Entries written by earlier versions without the prefix
  are no longer read and expire on their TTL, so expect a cold cache after upgrading. During a
  rolling deploy, invalidations on one version do not reach the other version's keys, so stale
  values can be served for up to one TTL. See `docs/upgrading.md`.
- `RedisCache` sets TTLs in milliseconds (`PSETEX`). Previously TTLs under one second were
  truncated to `SETEX 0`, which Redis rejects, so those writes failed.
- **Breaking:** `SecureRefundManager::get_refund` now takes the billable ID
  (`get_refund(billable_id, refund_id)`) and returns `RefundNotFound` (404) unless the refund's
  charge or payment intent belongs to that entity's Stripe customer. Previously it returned any
  refund by ID, so one organization could read another's refunds. See `docs/upgrading.md`.
- **Breaking:** `CreateRefundRequest` has a new `idempotency_key: Option<String>` field.
  Direct struct literals must add `idempotency_key: None`, use `..Default::default()`, or
  switch to the `for_charge` / `for_payment_intent` builders. With `None`, a key is derived
  from the charge/payment intent, amount, and reason and sent to Stripe to deduplicate refund
  retries. Identical partial refunds within Stripe's 24-hour key window collapse into one;
  use a distinct explicit key for each intentional repeat refund via `idempotency_key: Some(...)`
  or `.with_idempotency_key(...)`, and reuse that key when retrying the same refund.
- **Breaking:** `Refund` has a new `replayed` field, true when Stripe returned a cached refund
  for a repeated idempotency key (its `Idempotent-Replayed` header) instead of issuing a new one.
  Previously an identical refund within 24 hours silently returned the first refund. Struct
  literals and custom `StripeRefundClient`s must set it. `LiveStripeClient::create_refund` now
  calls Stripe's REST API directly to read the header.
- **Breaking:** `JobsConfig` has a new `shutdown_timeout_seconds` field (default 25, env
  `TIDEWAY_JOBS_SHUTDOWN_TIMEOUT_SECONDS`); struct literals must set it or use
  `..Default::default()`. On SIGTERM, `App::serve()` now stops accepting HTTP connections
  immediately and shuts down job workers in parallel, aborting jobs still running after the
  timeout. Previously it kept serving until every running job finished, with no limit, so under
  Kubernetes a slow job could get the pod SIGKILLed mid-request. Added
  `WorkerPool::shutdown_with_timeout`. See `docs/upgrading.md`.
- `AccountDeletionFlow` no longer deletes an account when a cleanup step (session or refresh
  token revocation, trusted device removal, MFA or lockout clearing) fails. Previously these
  errors were silently ignored, so a store failure could leave sessions and refresh tokens valid
  after the account was deleted. Immediate deletions now return the error; scheduled deletions
  stay pending and are retried by the next `process_due_deletions` run.
- `WebhookRouter::process` now returns a `ServiceUnavailable` (503) error for a duplicate
  delivery of an event that is still being processed in the same instance. It previously
  returned `Ok` (200), so the provider stopped retrying and the event was lost if the first
  attempt then failed. A delivery whose future is cancelled (for example on client disconnect)
  now releases its event ID; previously the ID stayed in the in-flight set and every later
  delivery of that event was silently skipped until restart.
- JWKS-backed `JwtVerifier`s now re-fetch keys in the background on a schedule (hourly by
  default; configure with `with_jwks_refresh_interval` or opt out with
  `without_scheduled_jwks_refresh`) so rotated and revoked keys take effect. Previously keys
  were only fetched at startup or for an unknown `kid`, so a revoked key stayed trusted forever.
  `JwkSet` now skips non-RSA (`EC`, `OKP`, `oct`) and malformed keys instead of failing to
  parse the whole set; a JWKS with keys but no valid RSA keys still fails to load, and a refresh
  that returns one keeps the current keys. RSA decoding keys are built once per fetch instead of
  per request. See `docs/upgrading.md`.

- **Breaking:** the database prelude now exports `DatabaseConnectionTrait` instead of
  `DatabaseConnection` to avoid ambiguous imports with SeaORM. Code importing
  `tideway::prelude::DatabaseConnection` no longer compiles. Update prelude trait references to
  the new alias or explicitly import `tideway::DatabaseConnection`; the original trait paths are
  unchanged.
- **Breaking:** `CachedInvoiceManager::list_invoices` now returns `Arc<InvoiceList>` and
  `CachedInvoiceManager::get_upcoming_invoice` returns `Option<Arc<Invoice>>`, so cache hits
  share the cached value instead of copying it. Callers that bind the result to an owned
  `InvoiceList` or `Invoice`, or move fields out of it, must borrow instead
  (`for invoice in &invoices.invoices`), serialize with `invoices.as_ref()`, or clone explicitly.
  The `InvoiceOperations` trait keeps its owned return types. See `docs/upgrading.md` and
  `docs/billing.md`.
- The rate-limit middleware now sustains `max_requests` per `window_seconds`. Previously it
  allowed a burst of `max_requests` and then refilled only one request per window, so the
  default "100 per 60s" became 1 request per minute after the first burst (server-wide in
  `global` mode). Clients now receive many more requests over time than before. If you tuned
  `max_requests` or `window_seconds` around the old behavior, review those values. See
  `docs/rate_limiting.md` for burst semantics.

- Routes added with `App::merge_router` now pass through Tideway's middleware stack in
  `serve()` and `into_router_with_middleware()`: rate limiting, request timeouts, body size
  limits, compression, security headers, request logging, tracing, and metrics. Previously the
  stack was applied before merged routers were added, so they only received request IDs, CORS,
  and global layers. This affects the CLI template's billing routes (including
  `/billing/webhook` and `/admin/billing`), OpenAPI routers, and WebSocket routers. Merged routes
  share the application's rate-limit budget; in `global` rate-limit mode, Stripe webhook
  deliveries count against the same limit as other traffic, so review `max_requests` and
  `window_seconds` if webhook volume is high. Layers added with `App::layer` still apply only to
  registered modules. See `docs/upgrading.md`.

- **Breaking:** the built-in metrics route (`/metrics` by default, or a custom metrics path) now
  requires a bearer token and returns 404 unless one is configured. Set
  `TIDEWAY_METRICS_BEARER_TOKEN` (fallback: `METRICS_BEARER_TOKEN`) or
  `MetricsConfig::builder().bearer_token(...)`, and send the same token in your scraper's
  `Authorization: Bearer` header. Requests with a missing or wrong token get 401. Metrics are
  still collected when no token is set, but they cannot be scraped. Unknown HTTP methods are now
  labelled `OTHER`. See `docs/upgrading.md`.
- **Breaking:** `allow_admin_impersonation` no longer overrides a user's opt-out.
  `ImpersonationManager::start_impersonation` now always enforces
  `ImpersonationStore::can_be_impersonated`, returning `Forbidden` when it returns `false`,
  even with `allow_admin_impersonation(true)`. The setting only permits admin targets;
  admin status is checked separately with `is_admin`. Custom stores must remove admin-only
  restrictions from `can_be_impersonated` if they rely on this setting, while preserving
  per-user eligibility checks. See
  [the upgrade guide](docs/upgrading.md#08x-to-090-impersonation-opt-out-always-enforced).
- **Breaking:** the `imp_blocked` claim built by `ImpersonationClaims::from_session` now uses
  the same action names as `validate_session` and `BlockedAction::matches`: `delete_account`,
  `change_password`, `change_mfa`, `change_email`, `modify_billing`, `export_data`,
  `make_purchase`, and `send_messages`. It previously held the lowercased variant names
  (`deleteaccount`, `changepassword`, `changemfa`, ...), and custom actions appeared as
  `custom("name")`. Custom actions are now the name as given, with its case preserved. Frontends
  that read `imp_blocked` (for example `token.imp_blocked.includes("deleteaccount")`) to hide
  actions during impersonation must switch to the new names, or they will stop hiding those
  actions. Tokens issued before the upgrade still carry the old values until they expire, so
  check for both forms during the rollout.
- `RedisJobQueue` workers no longer use the blocking `BRPOPLPUSH`, which stalled the shared
  Redis connection. An idle worker now sends `RPOPLPUSH` every 100 ms for up to 5 seconds per
  dequeue, which works out to about 8–10 Redis commands per second per idle worker. Previously
  it sent about one command every 6 seconds. With the default 4 workers, an idle instance now
  sends about 35 commands per second (roughly 3 million per day) instead of under 1. If your
  Redis provider bills per command or request, lower `worker_count`
  (`TIDEWAY_JOBS_WORKER_COUNT`) on instances that do not need it, or run fewer job-processing
  replicas.

> **Billing behavior change:** `LiveStripeClient` usage-record errors now report Stripe's HTTP
> status instead of a generic internal error. Applications using metered billing should review
> the Compatibility notes below and `docs/upgrading.md`.

### Security

- Admin impersonation in apps generated by `tideway new --preset saas` and `tideway backend` is
  rebuilt on `ImpersonationManager`. Previously `POST /admin/users/{user_id}/impersonate` issued
  the target's normal access and refresh tokens: the advertised one-hour expiry was not enforced,
  the refresh token outlived the session, admins could impersonate other admins, a reason was
  optional, and `POST /admin/impersonation/end` only logged. Now the endpoint takes an
  `ImpersonationRequestBody` (`target_user_id`, required `reason`, optional `duration_secs`) and
  uses `ImpersonationConfig::default()`, which requires a reason and rejects admin targets. It
  returns a single access token carrying `imp_session`/`imp_admin`/`imp_blocked` claims that
  expires with the session, and no `refresh_token`. The generated `RequestActor` rejects that
  token once its session has ended or expired, or the admin has lost admin access, and
  impersonation tokens cannot use admin routes. `/admin/impersonation/end` ends the caller's
  session, so the token stops working immediately. Sessions and audit entries are stored by a
  generated SeaORM `DbImpersonationStore` (`src/auth/impersonation.rs`) in tables created by the
  new `m017_create_impersonation_sessions` migration. Existing apps keep their old handlers; to
  adopt the fix, copy these files from a freshly generated app, register the migration, and
  update clients to send `target_user_id` and a reason and to stop expecting a refresh token.
- Impersonation session IDs now use 256 bits of OS randomness, replacing the timestamp and
  non-cryptographic hash suffix. The `imp_` prefix remains, followed by an unpadded base64url
  token. Treat session IDs as opaque strings rather than parsing the previous format.
- `SessionManager` can now revoke refresh tokens along with sessions. Attach the refresh token
  store shared with `TokenRefreshFlow` via `SessionManager::with_refresh_token_store`, and
  `revoke_session`, `revoke_other_sessions`, `revoke_all_sessions`, and session-limit eviction
  will revoke the matching refresh token families. Previously, a revoked session's refresh
  token could keep minting access tokens. `RefreshTokenStore` is now implemented for
  `Arc<T>` so one store can be shared.
- Added `EmailVerificationFlow::resend_for_user`, which sends the verification email to the
  address stored on the account (via the new `VerificationStore::verification_email`). The old
  `resend` is deprecated: it mailed the token to the caller-supplied `ResendVerificationRequest`
  email, so a user could verify their account with an address they do not own. Implement
  `verification_email` on your `VerificationStore` and switch callers to `resend_for_user`.
- `LoginFlow::verify_mfa` now rejects verification while the account is locked. Previously, MFA
  tokens minted before a lockout could keep guessing codes and complete login after the account
  locked.
- `ImpersonationRequest` and `DeletionRequest` no longer derive `Deserialize`. When a handler bound
  either type directly to a request body, the client controlled the acting admin (`admin_id`) or
  the account being deleted (`user_id`). That allowed impersonation through any admin's identity,
  and deletion of arbitrary accounts when password verification was disabled.
- A `LoginFlow` with a rate limiter no longer skips rate limiting when no client IP is supplied.
  Plain `login()` calls (and `login_with_ip(req, None)`) are now limited per normalized email
  address. Direct `OptionalRateLimiter::check_rate_limit(None)` calls now share one bucket
  instead of always being allowed.
- `SeatManager` seat changes no longer lose updates under concurrency. Previously two concurrent
  `add_seats` calls could both report success while only one seat was added in Stripe. Changes to
  the same billable entity are now serialized in-process, and each change reserves its new count
  in the store (via `compare_and_save_subscription`) before calling Stripe. A failed Stripe call
  releases the reservation. If the reservation keeps losing to concurrent changes, the call
  returns `Conflict`.
- Seat counts that would overflow `u32` (`extra_seats + count`, or included plus extra seats) are
  now rejected with `BadRequest` before Stripe is called, instead of panicking or wrapping. Seat
  totals computed from stored data saturate.
- `CreditTopUpEventSink` now takes back prepaid credits when Stripe reports a refund
  (`charge.refunded`) or dispute (`charge.dispute.created`). Previously customers kept the credits
  after getting their money back. Refunds revoke the refunded share of the pack, rounded up;
  disputes revoke the whole pack.
- `CreditTopUpEventSink` no longer grants credits for checkouts with `payment_status`
  `no_payment_required`, so a 100%-off promotion code no longer buys credits for free.
- `MembershipManager::add_member`, `InvitationManager::invite`, and `InvitationManager::accept` no
  longer create organization owners. Previously they only checked that the actor could manage
  members, so an admin could add or invite a member with the owner role. Owners can now only be
  created through `transfer_ownership`. Accepting an owner-role invitation fails and revokes it.

### Fixed

- `ListOrgsParams::default()`, `AuditLogParams::default()`, and
  `ListPlatformInvitesParams::default()` now return `page: 1, per_page: 20`, matching
  deserialization and `ListUsersParams`. They previously returned `page: 0, per_page: 0`.
- `WebSocketHandler::on_upgrade` is now called before a WebSocket upgrade is accepted. It was
  never called before, so overriding it to authenticate connections had no effect. The hook now
  takes an `UpgradeRequest` with the request headers, cookies, and URI
  (`on_upgrade(&self, req: &mut UpgradeRequest, ctx: &AppContext)`). An error rejects the
  upgrade and is sent as the HTTP response. A user ID or metadata set on the request is copied
  to the `Connection`, and `Connection` now exposes `headers`, `header`, `cookie`, and `uri`.
  Update any `on_upgrade` overrides to the new signature.
- Concurrent first checkouts for the same billable entity no longer create duplicate Stripe
  customers. `CustomerManager::get_or_create_customer` keeps the first customer link and deletes
  the redundant Stripe customer it created.
- `CheckoutManager::create_checkout_session` returns `TidewayError::Conflict` when the entity
  already has a subscription that has not ended. Previously it started a checkout that created a
  second, separately billed subscription.
- Creating a subscription checkout now expires the customer's other open subscription checkout
  sessions, so paying in two tabs can no longer create two subscriptions.
- A webhook for a second live subscription no longer silently replaces the stored subscription.
  Tideway keeps the stored one and emits `BillingEvent::DuplicateSubscription`.
- A `customer.subscription.updated` webhook that Stripe delivers after
  `customer.subscription.deleted` no longer recreates the deleted subscription as active (or
  overwrites the entity's newer subscription). `SubscriptionManager::delete_subscription` now
  records the deletion, and later syncs of that subscription are skipped. Only deletions processed
  after upgrading are recorded; existing stored subscriptions are unchanged. Applications that
  call `delete_subscription` directly (for example to clear a cached row) can no longer restore
  that subscription with `sync_from_stripe`; its later syncs return
  `SubscriptionSyncOutcome::Deleted`.
- Stripe webhook verification now checks every `v1` signature in the `Stripe-Signature` header.
  It previously kept only the last one, so webhooks were rejected during a Stripe secret roll.
- `LiveStripeClient::create_usage_record` sends one `Idempotency-Key` across all retry attempts,
  so a request that timed out after reaching Stripe can no longer be recorded (and billed) twice.
- Usage-record calls now retry HTTP 429 and 5xx responses, matching timeouts and every other
  `LiveStripeClient` operation. Other 4xx responses still fail immediately.
- Usage-record calls reuse one pooled HTTP client instead of building a new client per attempt.

### Added

- `JwtIssuer::issue_access_token_expiring_at` issues an access token with an explicit expiry, for
  tokens bound to a server-side session such as impersonation. `JwtVerifier::with_claims` reuses a
  verifier's keys and validation rules to decode another claims type, e.g. reading
  `ImpersonationClaims` with `AccessTokenClaims<ImpersonationClaims>`.
- Observability: the `otel` feature exports traces over OTLP/HTTP when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set, with no code changes for apps that call
  `init_tracing*` and `App::serve`. Requests become server spans named after their route.
  They continue incoming W3C `traceparent` headers, and 5xx errors are recorded as span
  exceptions. `observability::inject_trace_context` propagates the trace to outgoing calls,
  and `shutdown_tracing` flushes spans for apps that serve manually. Separately, an
  `ErrorReporter` registered with `AppContextBuilder::with_error_reporter` receives every 5xx
  response (with the full internal message and client `error_id`), handler panics, and failed
  jobs, for forwarding to an error tracker. Request spans now use the `tideway::request`
  tracing target. See `docs/observability.md`.
- Sentry: the `sentry` feature adds `observability::SentryReporter`, and `App` registers it
  automatically when `SENTRY_DSN` is set and the context has no reporter. Errors become Sentry
  issues with the route as transaction, the client `error_id` and request ID as tags, and the
  OpenTelemetry trace ID as trace context. `App::serve` flushes them on shutdown. The new
  `ErrorReporter::flush` method has a default implementation, so existing reporters still
  compile.
- `tideway new` now generates a multi-stage production `Dockerfile` (cargo-chef dependency
  caching, slim non-root Debian runtime listening on `$PORT`) and `.dockerignore` for every
  scaffold. The new `docs/deployment.md` covers building the image and deploying to Fly.io and
  Railway.
- File storage: the `storage` feature adds a `FileStorage` trait over `object_store` with a
  `LocalStorage` backend (HMAC-signed presigned URLs served by `LocalStorage::router()`) and an
  in-memory backend for tests; `storage-s3` adds `ObjectStorage::s3` and `ObjectStorage::r2`
  with SigV4 presigned URLs. `UploadPolicy` presets for avatars, logos, and attachments validate
  declared uploads, generate safe keys, presign a content-type-bound `PUT`, and `confirm` stored
  size after upload. Register a backend with `AppContextBuilder::with_storage` and read it with
  `AppContext::storage`. See `docs/storage.md`.
- Recurring jobs: `jobs::JobScheduler` enqueues existing `Job` values on cron schedules (UTC,
  five- or six-field expressions) and `App::start_scheduler` runs it alongside the workers. Each
  occurrence is claimed through a `SchedulerLock` before it is enqueued, so only one instance runs
  it; `RedisSchedulerLock` (or `RedisJobQueue::scheduler_lock`) uses Redis `SET NX PX`. The `jobs`
  feature now depends on the `cron` crate.
- Default, overridable lifecycle emails (`tideway::email::lifecycle`): templates for email
  verification, password reset, organization invitation, trial ending, payment failed, and
  receipt, rendered through an `EmailTemplates`/`EmailLayout` pair that applications can override
  per email or wholesale. `LifecycleEmailer::queued` delivers them through the new
  `SendEmailJob` (`register_email_jobs`) when the `jobs` feature is enabled. `Email` now derives
  `Serialize`, `Deserialize`, `PartialEq`, and `Eq`.
- `billing::LifecycleEmailBillingSink` (with `email`) sends the trial-ending, payment-failed, and
  receipt lifecycle emails from Stripe webhooks, resolving recipients from the invoice's customer
  email or an application `BillingEmailRecipients`. The webhook handler now processes
  `customer.subscription.trial_will_end` as `BillingEvent::TrialWillEnd`, and invoice events carry
  an `InvoiceSummary` (number, customer email, amounts, currency, hosted invoice URL).
- `ImpersonationRequestBody` and `DeletionRequestBody` are safe deserializable request bodies with
  no actor field and `deny_unknown_fields`. Their `into_request(actor_id)` method combines the body
  with the authenticated user's ID.
- `billing::WebhookHandler` supports multiple Stripe webhook signing secrets through
  `with_additional_secret` and `with_secrets`, so secrets can be rotated without downtime.
- `BillingStore::link_stripe_customer_if_absent` links a Stripe customer only when none is linked
  and returns the winning ID. The in-memory and SeaORM stores implement it atomically. Custom
  stores inherit a non-atomic default and should override it.
- `SubscriptionStatus::is_ended` reports `canceled` and `incomplete_expired` subscriptions.
- `StripeCheckoutClient::expire_open_subscription_checkouts`, implemented by the live client.
  Custom clients inherit a no-op default.
- `BillingEvent::DuplicateSubscription`, plus `SubscriptionManager::sync_from_stripe_checked`
  and `SubscriptionSyncOutcome` for callers that sync subscriptions themselves.
- `SubscriptionSyncOutcome::Deleted`, plus `BillingStore::mark_subscription_deleted` and
  `BillingStore::is_subscription_deleted`. The default implementations store a
  `tideway:subscription_deleted:<id>` marker in processed-event storage, so no migration is
  needed. `cleanup_old_events` also removes these markers, so keep its retention longer than
  Stripe's webhook retry window (about three days).
- `SubscriptionManager::cancel_duplicate_subscription` immediately cancels a reported duplicate.
  It never cancels the stored subscription or another entity's subscription, and does not refund.
- `BillingEvent::ChargeRefunded` and `BillingEvent::ChargeDisputed`, emitted for Stripe
  `charge.refunded` and `charge.dispute.created` webhooks.
- `CreditManager::revoke` / `CreditStore::revoke` with `RevokeCredits`, `RevocationAmount`, and
  `CreditRevocation`, plus `CreditTransactionKind::Revoke`. Revocation amounts are cumulative, so
  retries are idempotent. Credits held by open reservations are taken back when the reservation is
  released; credits already spent are reported as `unrecovered_amount`. Custom `CreditStore`s
  inherit a default that logs a warning and returns `None`, so refund and dispute webhooks still
  succeed but revoke nothing until the store overrides `revoke`.
- CLI: `migrations/m015_add_credit_revocation` adds the revocation columns, an index, and the
  `revoke` transaction kind. `tideway new` with `credits-seaorm` and `tideway add credits` generate
  it; rerunning `tideway add credits` on an existing app adds only this migration.
- `InvitationStore::invitation_grants_owner` lets `InvitationManager::invite` reject owner-role
  invitations at creation. The in-memory and SeaORM stores implement it. Custom stores inherit a
  default that returns `false`; owner invitations from those stores are still rejected at `accept`.
- `RefundManager::refund(request)` and `SecureRefundManager::refund(billable_id, request)` take a
  full `CreateRefundRequest`, so callers can set `with_idempotency_key`. The convenience refund
  methods derive their key from the target, amount, and reason, so an identical refund within
  Stripe's 24-hour window returns the original refund with `replayed` set; use a distinct key for
  intentional repeat refunds. The secure variant verifies ownership of both the charge and the payment intent.

### Changed

- CLI: the generated `src/billing/events.rs` logs a warning for `BillingEvent::DuplicateSubscription`
  with a TODO for the cancel-and-refund policy. It requires the next Tideway release, so ship it
  with the CLI release that targets that version.

### Compatibility

- This is a minor-version compatibility boundary for the pre-1.0 framework. The breaking changes
  listed at the top of this release mean it cannot ship as a 0.8.x patch release.
- `BillingEvent::OneTimeCheckoutCompleted` has a new `payment_intent_id` field. Code that
  constructs it, or destructures it without `..`, must be updated.
- `BillingEvent::InvoicePaid` and `BillingEvent::InvoicePaymentFailed` have a new
  `invoice: InvoiceSummary` field. Code that constructs them, or destructures them without `..`,
  must be updated. `InvoiceSummary` is `#[non_exhaustive]` and implements `Default`.
- `CreditTransactionKind` has a new `Revoke` variant and is now `#[non_exhaustive]`. Exhaustive
  matches on it must add a wildcard arm; later kinds will not be breaking.
- `CreditTopUpEventSink` now keys grants by `stripe-payment-intent:{id}` instead of
  `stripe-event:{event_id}`. Top-ups granted before this release cannot be found by refund or
  dispute webhooks and are left unchanged.
- `WebhookHandler` now processes `charge.refunded` and `charge.dispute.created` instead of
  returning `WebhookOutcome::Ignored`. It records them as handled and passes them to the event
  sink, so custom sinks receive `BillingEvent::ChargeRefunded` and `BillingEvent::ChargeDisputed`
  even when credits are not used.
- A paid top-up checkout without a `payment_intent` now fails, so Stripe retries it, instead of
  granting credits. Stripe includes one for every paid payment-mode session.
- The usage-record fix has no public API or signature changes.
- Non-2xx responses from `create_usage_record` and `list_usage_records` now return
  `BillingError::StripeApiError { http_status, message, code }` instead of
  `BillingError::Internal("HTTP client error: HTTP …")`. Through the existing `TidewayError`
  mapping, Stripe 4xx errors (including 401/403, and 429 after retries are exhausted) now surface
  as `BadRequest` (HTTP 400) with Stripe's message instead of `Internal` (HTTP 500) with a hidden
  message. 5xx errors remain `Internal`.
- Rate-limited or 5xx usage-record calls now take longer to fail: up to `max_retries` additional
  attempts with exponential backoff (4 attempts total by default).
- The organization owner fix has no signature changes, and `invitation_grants_owner` has a default,
  so custom `InvitationStore` implementations still compile. `add_member` and `invite` with an
  owner role now return `InsufficientPermission` for every actor, including owners.
- **Breaking:** `WebSocketHandler::on_upgrade` now takes `&mut UpgradeRequest` before
  `&AppContext`, so overrides written for 0.8 no longer compile. Handlers that do not override it
  still compile unchanged. `Connection` gains accessors only, and its
  public constructor `Connection::channel` is unchanged.

### Migration Notes

- **Logging / alerting:** `TidewayError` 4xx responses (including 401, 403, and 429) now log
  at `WARN` instead of `ERROR`; 5xx responses remain at `ERROR`. Review log filters and
  alerting rules that relied on `ERROR`-level logs for these client errors and include `WARN`
  where needed. Stripe upstream 4xx diagnostics also log at `WARN` on the
  `tideway::billing::stripe` target, except upstream 401/403 credential or permission failures,
  which remain at `ERROR` and map to HTTP 500.
- **Breaking:** apps that scrape metrics must set `TIDEWAY_METRICS_BEARER_TOKEN` and configure
  the scraper to send it before deploying, or scrapes get 404 and dashboards go blank.
- **Breaking:** callers of `CachedInvoiceManager::list_invoices` and `get_upcoming_invoice` must
  handle the `Arc` return types.
- **Breaking:** frontends that read the `imp_blocked` claim must compare against the snake_case
  action names (`delete_account`, not `deleteaccount`).
- Metered Redis users: expect many more commands from idle `RedisJobQueue` workers (about
  8–10 per second per worker). Review `worker_count` before deploying.
- **Breaking:** handlers using `Json<ImpersonationRequest>` or `Json<DeletionRequest>` no longer
  compile. Switch them to the `*Body` types and pass the authenticated actor ID to `into_request`.
  See `docs/upgrading.md`.
- Checkout endpoints now return 409 for entities with a live subscription. Send existing
  subscribers to plan changes or the customer portal instead.
- Handle `BillingEvent::DuplicateSubscription` in your event sink to cancel or refund duplicates.
  The duplicate's later `customer.subscription.updated` events emit it again; deduplicate by
  subscription ID.
- **Breaking:** apps using `credits-seaorm` must apply a database migration before deploying.
  `SeaOrmCreditStore` reads the new `credit_buckets.revoked_amount` and
  `credit_buckets.pending_revocation` columns, so grants, reservations, and balance reads fail
  until it runs. Run `tideway add credits` to generate the additive migration. Apps using Stripe
  top-ups must also subscribe the webhook endpoint to `charge.refunded` and
  `charge.dispute.created`. See `docs/upgrading.md`.
- **Breaking:** code that constructs `BillingEvent::OneTimeCheckoutCompleted`, or destructures it
  without `..`, must handle the new `payment_intent_id` field.
- **Breaking:** exhaustive matches on `CreditTransactionKind` must add a wildcard arm.
- **Breaking:** `WebSocketHandler::on_upgrade` overrides must use the new signature
  `on_upgrade(&self, req: &mut UpgradeRequest, ctx: &AppContext)`. The hook now runs on every
  upgrade, so rejection logic that was previously dead code takes effect. See `docs/upgrading.md`.
- **Breaking:** replace `tideway::prelude::DatabaseConnection` with `DatabaseConnectionTrait`, or
  import `tideway::DatabaseConnection` directly.
- **Breaking:** code that takes owned values from `CachedInvoiceManager::list_invoices` or
  `get_upcoming_invoice` must borrow through the returned `Arc` or clone explicitly. See
  `docs/upgrading.md`.
- Before deploying an app that uses `CreditTopUpEventSink`, check Stripe for failed top-up
  webhooks waiting to be retried. If one was already granted before the upgrade, its retry is
  granted again under the new key. Let retries finish first, or reverse the duplicate grant.
- Pending owner-role invitations created before this release fail when accepted and are revoked.
  Code that used `add_member` to create co-owners must use `transfer_ownership` instead. See
  `docs/upgrading.md`.

## [tideway-cli 0.9.0] - Unreleased

### Added

- `tideway seed` loads development/demo data with one command: it loads `.env`, validates
  `DATABASE_URL`, and runs the app's `seed` binary (`cargo run --bin seed`; `--bin` selects
  another). New database-backed apps include an idempotent `src/bin/seed.rs` that applies pending
  migrations and reuses the app's SeaORM entities; the API preset seeds sample todos. Their
  `Cargo.toml` sets `default-run`, and `tideway dev` watch mode now honours `default-run` when
  an app has more than one binary. Existing apps can adopt the convention by adding
  `src/bin/seed.rs` and `default-run`; see `docs/cli.md#tideway-seed`.
- `tideway generate client --spec openapi.json` generates a typed, dependency-free TypeScript
  client (`./src/api/client.ts` by default) from an app's OpenAPI document: an interface or type
  per `components.schemas` entry and one typed function per operation, with path/query/body
  arguments, a bearer-token hook, and an `ApiError` for non-2xx responses. Re-running the command
  overwrites a previously generated client; other files at the target path still need `--force`.
- `tideway generate auth --framework react` and `--framework next` generate React auth components
  (`LoginForm`, `RegisterForm`, `ForgotPassword`, `ResetPassword`, `MfaVerify`), a `useAuth` hook,
  and shared `lib/api.ts`/`types/index.ts` helpers styled with Tailwind classes. The Next.js variant
  adds `'use client'` and reads `NEXT_PUBLIC_API_URL`; the React variant reads `VITE_API_URL`.
  Billing, organization, and admin components remain Vue-only.

### Changed

- The `api`, `saas`, and `worker` presets and backend presets enable Tideway's `otel` and
  `sentry` features. Their `.env.example` documents `OTEL_*`, `SENTRY_DSN`, and
  `SENTRY_ENVIRONMENT`, so generated apps can export traces to an OTLP backend and errors to
  Sentry by setting those variables. Both features are also accepted by `--features` and
  offered in the custom feature picker.

- The CLI now shares the framework's major.minor version: tideway-cli 0.9.0 follows 0.1.48 and
  is released alongside Tideway 0.9.0. CLI 0.9.x targets Tideway 0.9.x; patch releases stay
  independent, so CLI fixes can ship without a framework release. Newly generated applications
  use Tideway 0.9.0.
- New database-backed auth apps (the API preset, or `--features auth,database`) send email
  verification and password-reset emails out of the box. The generated `DbUserStore` implements
  `VerificationStore` (reusing the `auth_tokens` table) and queues Tideway's default lifecycle
  templates; `main.rs` starts background workers to deliver them. The new `src/email.rs` selects
  the provider from `EMAIL_PROVIDER`/`EMAIL_FROM`/`APP_URL` and holds the `AppEmailTemplates`
  override point. `/auth/email/verify` and `/auth/email/verification/resend` are mounted with the
  password-reset routes when email delivery is configured. These apps now enable the `email` and
  `jobs` features, and `AuthModule::with_email_delivery` takes the `AppEmails` handle. Existing
  applications are unaffected; see `docs/email.md` to adopt the same wiring by hand.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.9.0 --locked`, then run
  `tideway --json doctor --upgrade` before updating each application.

## [tideway-cli 0.1.48] - 2026-08-04

> **Existing applications:** install this CLI and run `tideway --json doctor --upgrade` before
> updating Tideway. Do not regenerate or overwrite application-owned auth files.

### Changed

- Newly generated applications use Tideway 0.8.0 and include the atomic password-reset lifecycle,
  reset-request throttling, password-policy metadata, and immediate access-token revocation.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.48 --locked`, then run
  `tideway --json doctor --upgrade` before updating each application.
- After applying every reported migration and source change, require a clean result with
  `tideway --json doctor --upgrade --deny-warnings`.

## [0.8.0] - 2026-08-04

> **Migration release — action required.** Tideway 0.8.0 is not a drop-in update for existing
> applications using auth/password reset. Apply the additive database migration and source changes
> in `docs/upgrading.md` before deploying 0.8.0. Applications staying on 0.7.x are unaffected.

### Added

- Password reset errors now expose stable machine-readable codes, and generated auth APIs expose
  the active password policy at `GET /auth/password-policy`.
- Upgrade doctor reports non-atomic reset stores, incomplete access-token invalidation, and missing
  reset-token hash uniqueness even when custom stores live outside `src/auth`.
- Access tokens carry a monotonic session version. Generated authentication providers compare it
  with the user row, allowing a completed password reset to revoke already-issued access tokens.

### Fixed

- Password hashing failures no longer consume reset tokens. Newly generated SeaORM stores complete
  password replacement, login/MFA lockout clearing, reset-token invalidation, access-session
  version advancement, and refresh-session revocation in one transaction.
- Failed reset-email delivery discards only the undelivered token and leaves previously delivered
  reset links usable. Concurrent completion is explicitly first-writer-wins.
- Generated reset-request handlers use enumeration-safe responses, trusted-proxy-aware rate limits,
  and move token creation plus delivery off the response path to avoid account-existence timing.
- Password policy limits count Unicode scalar values consistently with their documented
  character-based contract.

### Compatibility

- This is a minor-version compatibility boundary for the pre-1.0 framework. `TidewayError` is now
  non-exhaustive and has a coded bad-request variant; downstream exhaustive matches must add a
  wildcard arm.
- `PasswordResetStore` now requires the preflight, delivery cleanup, and atomic completion methods;
  the unsafe sequential compatibility fallback has been removed.
- Existing database-backed auth applications need additive `users.session_version` and unique
  reset-token-hash migrations, plus the generated claim issuance and authentication check. See
  `docs/upgrading.md`; do not overwrite application-owned generated files.

### DX Gate

- Regression coverage injects a session-revocation failure and proves the entire reset transaction
  rolls back, then verifies lockout clearing, all-token invalidation, access-session advancement,
  and exactly one winner under concurrent completion.

## [tideway-cli 0.1.47] - 2026-07-24

### Changed

- Newly generated applications use Tideway 0.7.31.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.47 --locked`.
- Existing generated files require no changes for this release.

## [0.7.31] - 2026-07-24

### Fixed

- Adding the first paid seat now creates the missing Stripe subscription item with the plan's
  configured extra-seat price and quantity.
- Newly created seat items carry explicit Tideway metadata, so Stripe response parsing does not
  depend on subscription item ordering.
- A missing seat price now returns a clear error instead of allowing an empty subscription update.

### Compatibility

- No database migration or application source change is required.
- Applications using a Git revision containing the provisional fix can return to the crates.io
  release.
- `UpdateSubscriptionRequest` has a new optional `seat_price_id`; builder and
  `..Default::default()` construction remain compatible.

### DX Gate

- Subscription item construction is covered for existing seats, first-seat creation, zero seats,
  missing configuration, and combined plan-and-seat changes.
- The feature-enabled billing suite, complete workspace tests, CLI tests, and repository
  guardrails pass before publication.

## [tideway-cli 0.1.46] - 2026-07-23

### Added

- Fresh API and SaaS scaffolds make public registration opt-in, apply separate trusted-proxy-aware
  limits to registration and refresh, return `Retry-After` on generated auth throttling responses,
  and keep the OpenAPI document aligned with the mounted registration route.
- PostgreSQL scaffolds include a CI service and `TEST_DATABASE_URL`; generated auth and organization
  tests use isolated schemas and cover role denial, tenant boundaries, and concurrent invitation
  constraints against the real application migrations.
- Upgrade doctor reports focused registration-policy and endpoint-limiter findings for historical
  generated auth routes, with explicit audit markers for equivalent custom or gateway controls.
- The generated Vue registration form is disabled unless its prop or
  `VITE_ALLOW_PUBLIC_REGISTRATION` explicitly enables it.

### Fixed

- Auth-only and OpenAPI-only feature selections now compile cleanly with warnings denied.
- Fresh CI bootstraps a missing `Cargo.lock` without replacing a committed lockfile.
- Empty OpenAPI documents remain compatible with later `tideway resource` wiring.

### DX Gate

- Generated minimal, API, auth/MFA, SaaS, auth-only, and OpenAPI-only applications compile and test
  against the workspace framework with strict warnings.
- A fresh generated SaaS application passes its auth, role, tenant, invitation, and concurrency
  suite against PostgreSQL 16.
- The complete CLI suite, strict Clippy, docs drift, filesystem-write, and public-API guardrails
  pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.46 --locked`; newly generated projects use
  Tideway 0.7.30.
- Existing generated files remain application-owned and are never overwritten. Run
  `tideway doctor --upgrade` and follow the `0.7.29 to 0.7.30` section in `docs/upgrading.md` to
  adopt registration policy, endpoint limits, PostgreSQL CI tests, and the optional Vue setting.

## [0.7.30] - 2026-07-23

### Added

- `AuthRateLimitConfig` and `AuthRateLimiter` provide reusable keyed throttling for registration,
  refresh, reset, and other authentication endpoints. The existing `LoginRateLimitConfig` and
  `LoginRateLimiter` names remain backwards-compatible aliases.

### Fixed

- Authentication quota construction now treats the configured window as the time to replenish the
  full burst. The previous construction replenished only one attempt per complete window after a
  burst, making recovery much stricter than the documented policy.

### Compatibility

- The framework change is additive and requires no database migration.
- Existing login limiter source continues to compile through the compatibility aliases.
- Application route policy, generated CI, tests, and frontend components are application-owned and
  require the focused adoption steps in `docs/upgrading.md`; a dependency update does not rewrite
  them.

### DX Gate

- The feature-enabled auth and billing suite passes with 655 tests, including quota recovery,
  refresh concurrency, and access-token purpose checks.
- Full workspace tests, strict Clippy, generated-project tests, and repository guardrails pass
  before publication.

## [tideway-cli 0.1.45] - 2026-07-17

### Added

- `tideway add billing-schema` creates an idempotent additive repair unless that forward repair is
  already registered. It does not trust edits to a historical migration as proof that a deployed
  database was repaired.
- Upgrade doctor reports `TW-UPGRADE-BILLING-CUSTOMER-SCHEMA` with the focused remediation command
  and confirms compatible migration source without connecting to the database.

### Fixed

- Fresh billing scaffolds now include `billing_customers.billable_type` and `updated_at`, matching
  the framework store contract.
- CLI-generated resource and credits migrations now preserve each application's established
  sequential or SeaORM timestamp naming convention. Mixed histories follow the last registered
  migration when it is unambiguous and fail before modifying project files instead of guessing;
  commented registrations and examples outside `Migrator::migrations()` are ignored.

### DX Gate

- Sequential, timestamp, mixed-history, idempotency, non-mutation, fresh-scaffold, repair, and
  doctor remediation regressions pass.
- The complete CLI suite passes, including generated minimal, API, auth/MFA, and SaaS application
  compilation, localhost golden paths, strict Clippy, and repository guardrails.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.45`; newly generated projects use Tideway
  0.7.29.
- Existing `billing-seaorm` applications should run `tideway doctor --upgrade`, then
  `tideway add billing-schema` only when warned. Review and apply the additive migration before
  deploying Tideway 0.7.29; do not edit an already-applied migration.

## [0.7.29] - 2026-07-17

### Added

- `SeaOrmBillingStore::validate_schema` provides a read-only PostgreSQL and SQLite schema
  contract check with precise missing-table and missing-column diagnostics for startup and CI.

### Fixed

- Customer upserts now refresh `billable_type` as well as the Stripe customer ID and timestamp,
  allowing rows repaired with the neutral `legacy` value to acquire the application's real type.

### Compatibility

- Custom billing stores and applications without `billing-seaorm` are unchanged.
- The framework API addition is backwards compatible. The required customer columns were already
  part of the published SeaORM model; this patch supplies the missing fresh and forward migration
  paths rather than changing their meaning.

### DX Gate

- Real SeaORM customer persistence and schema mismatch diagnostics pass against SQLite, alongside
  the existing billing claim and subscription concurrency regressions.
- Full workspace tests, all-feature strict Clippy, package dry runs, and repository release guards
  pass before publication.

## [tideway-cli 0.1.44] - 2026-07-16

### Added

- `tideway add credits` enables the persistent credits module and creates an application-owned
  ledger migration without generating public routes or replacing application business logic.
- New custom projects selecting `credits-seaorm` include and register the ledger schema.

### Fixed

- Existing applications receive the next available migration number, starting at `m013`; Tideway
  never renames, renumbers, or overwrites existing migration history, including with `--force`.
- Repeated `tideway add credits` runs detect the existing ledger migration and remain idempotent.
- Older migration crates gain SeaORM's required `with-json` feature without losing their existing
  database features.

### DX Gate

- Collision, dynamic numbering, migration-width preservation, idempotent rerun, and fresh-project
  schema tests pass.
- The complete CLI suite passes, including generated minimal, API, auth/MFA, and SaaS application
  compilation, alongside strict Clippy and repository guardrails.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.44`; newly generated projects use Tideway
  0.7.28.
- Existing applications are unchanged unless they opt in. Upgrade Tideway first, then run
  `tideway add credits`, inspect the additive migration, apply it before deploying credits-backed
  code, and follow `docs/upgrading.md` for authorization, testing, and rollback guidance.

## [0.7.28] - 2026-07-16

### Added

- Provider-neutral `credits` and `credits-seaorm` modules provide integer allowances, persistent
  top-ups, atomic reservations, idempotent grants and consumption, release/refund handling,
  bounded history, and account-scoped balances.
- The optional `credits-stripe` adapter creates payment-mode Checkout Sessions from immutable,
  server-owned pack definitions and fulfils paid top-ups through idempotent billing events.
- Billing lifecycle hooks expose completed one-time payment Checkout Sessions, including delayed
  payment success, through the existing non-exhaustive `BillingEvent` API.

### Security

- Credit operations require explicit account IDs, fail closed across tenant boundaries, validate
  amounts, identifiers, metadata size, reservation TTLs, and idempotency reuse, and never generate
  unauthorised public balance or history routes.
- Stripe fulfilment accepts only signed payment-mode events with paid or no-payment-required
  status and resolves both price and granted quantity from the server-owned pack catalog.
- Expired reservation cleanup is bounded and scoped to one account and credit type in request paths;
  explicit maintenance handles larger backlogs without sweeping unrelated tenants.

### DX Gate

- Memory, SQLite SeaORM, and real PostgreSQL concurrency regressions confirm that concurrent
  reservations cannot overspend and that idempotent retry, expiry, commit, and release semantics
  remain consistent.
- All-feature framework tests, the default workspace suite, strict Clippy, public API, docs, and
  filesystem-write guardrails pass.

### Migration Notes

- This release is additive. Existing applications do not create tables or change billing behavior
  unless they enable a credits feature.
- Applications adopting `credits-seaorm` must apply the four-table ledger migration before
  constructing `SeaOrmCreditStore`. Retain ledger tables during application rollback because they
  contain balances, reservations, idempotency records, and audit history.
- Stripe pack IDs are immutable versions. Create a new ID when changing a price, credit type, or
  amount, and retain old definitions while webhook deliveries may still be retried.

## [tideway-cli 0.1.43] - 2026-07-16

### Fixed

- Generated billing and generic webhook stores now use explicit `processing` and `processed`
  states, so a process termination after claiming no longer leaves an event permanently skipped.
- Generated Stripe price handlers complete successful claims and return a retryable error while a
  fresh claim is owned by another worker.

- Generated API and SaaS applications use explicit `JWT_ISSUER` and `JWT_AUDIENCE` settings instead
  of coupling token identity to a display-facing application name.
- Built-in protected modules in new API and SaaS projects receive verifiers derived from one
  startup-created `JwtAuth` configuration instead of reconstructing policy from a raw secret.
- Generated auth tests now complete login and call a protected route with an application display
  name deliberately different from the JWT issuer.

### Added

- Fresh projects include an additive webhook-claim lifecycle migration with ownership tokens and
  claim timestamps; upgrade diagnostics identify applications that still have the old table shape.

- `tideway doctor --upgrade` reports `TW-UPGRADE-JWT-IDENTITY-DRIFT` when older generated code
  issues tokens with the application name but verifies against the Cargo package name.

### DX Gate

- Generated API and SaaS projects compile and test with a display name distinct from their stable
  JWT identity, and the SaaS auth test exercises a protected organization route.
- Strict workspace formatting, Clippy, the complete CLI suite, downstream upgrade contract, and
  repository guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.43`; newly generated projects use Tideway
  0.7.27.
- Existing application-owned files are not rewritten. Preserve established production issuer and
  audience values, configure issuance and verification together, and expect incompatible tokens to
  require reauthentication if those values change.
- Before using Tideway 0.7.27's built-in database webhook stores, add and run an application-owned
  migration equivalent to generated `m012_add_webhook_claim_lifecycle`.

## [0.7.27] - 2026-07-16

### Added

- `JwtAuthConfig` and `JwtAuth` create compatible JWT issuers and verifiers from one source of
  truth. Audience validation is required, HS256 secrets retain minimum-strength checks, and RS256
  requires explicit private signing and public verification keys.

### Security

- The paired JWT API prevents issuer, audience, algorithm, and key drift between token issuance and
  verification, validates that RS256 keys form a working pair, and retains fail-closed behaviour.
- Webhook claim completion and release are conditional on an opaque ownership token; stale workers
  cannot mutate a newer lease, and abandoned processing can be retried after the configured TTL.

### DX Gate

- HS256 and RS256 issuance-to-verification, required-audience, invalid-key, and mismatched-RSA-key
  regressions pass.
- Existing JWT APIs remain available and the downstream upgrade contract compiles unchanged.

### Migration Notes

- This is additive. Existing `JwtIssuer` and `JwtVerifier` integrations remain supported.
- Applications can adopt `JwtAuth` without rotating their signing key; preserve existing issuer and
  audience values to avoid invalidating active tokens.

## [tideway-cli 0.1.42] - 2026-07-15

### Fixed

- Generated SaaS auth tests are compiled and run, use the current auth API, and exercise
  registration and login against the generated migrations on SQLite.
- Billing plan JSON is emitted as typed JSON values and generated migration crates enable
  SeaORM's JSON support, so PostgreSQL accepts the seeded `jsonb` columns.
- Organization admin columns are added and removed in separate statements for SQLite
  compatibility.
- Fresh SaaS projects use a syntactically valid local-only Stripe test key, while generated
  applications reject that placeholder outside development and test environments.
- `tideway doctor` recognizes direct `Migrator::up` calls instead of reporting that generated
  migrations are not run automatically.
- Database-backed projects are Cargo workspaces, so the application and migration crate share one
  root lockfile.
- Generated Compose files no longer use the obsolete top-level `version` field.

### DX Gate

- The complete CLI suite passes, including a warning-free generated SaaS application compiled and
  tested across all targets against Tideway 0.7.26.
- The generated SaaS auth lifecycle runs every migration on SQLite and verifies registration and
  login, preventing orphaned or stale scaffold tests from passing silently.
- Strict workspace formatting, Clippy, and repository guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.42`; newly generated projects continue to
  use Tideway 0.7.26.
- Existing applications are not rewritten. They may adopt the workspace, migration dependency,
  SQLite migration, and local Stripe placeholder changes selectively where relevant.

## [tideway-cli 0.1.41] - 2026-07-15

### Added

- Fresh API and SaaS scaffolds include provider-neutral transactional email delivery with console,
  SMTP, and Resend configuration. Generated verification, password-reset, and invitation flows send
  working application-owned email templates.
- Greenfield SaaS and B2B scaffolds include application-owned organization invitation routes,
  persistence, migrations, email delivery, and an authenticated Vue acceptance flow. Invitations
  remain optional through `--without-invitations`.
- Organization administrators can resend a pending invitation through an organization-scoped,
  rate-limited endpoint that rotates the bearer token and refreshes its expiry.

### Security

- Generated invitations store token digests, verify the accepting account's email, enforce
  organization-scoped administration, reject owner-role grants, claim tokens atomically, and clean
  up failed email delivery safely.
- Invitation issuance and acceptance serialize organization membership changes and enforce billing
  seat availability, including concurrent requests for the final seat.

### Fixed

- Generated B2C checkout sessions use the authenticated database user's ID and email instead of an
  empty Stripe customer email placeholder.

### DX Gate

- The complete CLI suite passes, including warning-free generated minimal, API, auth/MFA, and SaaS
  applications compiled and tested against Tideway 0.7.26.
- Strict workspace Clippy, formatting, generated-app behavioral tests, and repository guardrails
  pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.41`; newly generated projects use Tideway
  0.7.26.
- Existing generated applications remain application-owned and are not modified by upgrade checks.
  Adopt the invitation security checklist in `docs/organizations.md` with schema-compatible edits.
- Existing email templates and delivery wiring remain application-owned; use `docs/email.md` to opt
  into Resend or the provider-neutral generated configuration without overwriting custom designs.

## [0.7.26] - 2026-07-15

### Added

- `ResendMailer` and `ResendConfig` provide a first-party HTTPS adapter with bounded request
  timeouts, redacted configuration output, and provider-neutral `Mailer` integration.
- `InvitationRateLimitProvider` lets applications replace the zero-configuration, process-local
  invitation limiter with an application-owned shared provider before deploying multiple replicas.

### Fixed

- Invitation quotas replenish the configured allowance evenly across the window instead of
  replenishing only one permit per complete window after the initial burst.

### DX Gate

- Auth, billing, SeaORM billing, email, and invitation rate-limit feature tests pass alongside the
  default framework suite.
- Strict workspace Clippy, formatting, documentation drift, filesystem-write, and public-API
  guardrails pass.

### Migration Notes

- This is an additive framework update with no required database migration. Existing `Mailer`
  implementations and `SmtpMailer` integrations remain compatible.
- The in-memory limiter remains the default and requires no Redis configuration. Applications using
  multiple API replicas should provide a shared `InvitationRateLimitProvider`.

## [tideway-cli 0.1.40] - 2026-07-14

### Fixed

- Fresh SaaS applications now compile their shared modules once through the generated library crate, eliminating warning noise without suppressing useful compiler diagnostics.
- `tideway resource` adds modules to `lib.rs` for library-based SaaS applications and registers the resource through the application crate, preserving auth visibility and warning-free compilation.
- The generated SaaS compile regression now treats warnings as errors.

### DX Gate

- The complete CLI suite passes, including warning-free SaaS generation and the `new SaaS` → `resource` → compile workflow.
- Strict CLI Clippy, formatting, and repository guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.40`; generated projects continue to use Tideway 0.7.25.
- Existing applications do not require changes; this release affects newly generated files and future resource wiring.

## [tideway-cli 0.1.39] - 2026-07-14

### Added

- New SaaS backends include an application-owned `BillingEventSink` for provisioning, email, analytics, dunning, and durable job dispatch without changing Tideway's core billing state machine.
- `tideway doctor --upgrade` warns when a custom production billing store relies on the non-atomic compatibility implementation of `compare_and_save_subscription`.

### DX Gate

- The complete CLI suite passes, including clean generated minimal, API, auth/MFA, and SaaS projects compiled against Tideway 0.7.25.
- CLI packaging and repository documentation, filesystem-write, and public-API guardrails pass.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.39`; generated projects use Tideway 0.7.25.
- Existing generated applications remain application-owned and are not overwritten. They may opt into lifecycle hooks with `WebhookHandler::with_event_sink`.

## [0.7.25] - 2026-07-14

### Added

- `BillingEventSink` provides typed, application-owned hooks after checkout, subscription, and invoice webhook processing, with a backward-compatible no-op default.

### Fixed

- Subscription compare-and-save operations now advance their optimistic-lock version, and the built-in SeaORM store performs subscription updates atomically so concurrent seat changes cannot silently overwrite each other.
- Billing lifecycle sink failures release the webhook claim for provider retry while retaining Tideway's successfully synchronized core subscription state.

### DX Gate

- The 641-test auth and billing feature suite, full workspace suite, formatting, and Cargo packaging verification pass.

### Migration Notes

- Custom production billing stores that support seat changes must implement atomic `compare_and_save_subscription` and advance the stored version after every successful write.
- Lifecycle event sinks must make side effects idempotent using the Stripe event ID and should enqueue slow work rather than performing it in the webhook request.

## [tideway-cli 0.1.38] - 2026-07-14

### Added

- `tideway doctor --upgrade` warns when a downstream custom `BillingStore` is missing the atomic `claim_event` or retry-safe `release_event_claim` override.
- The upgrade guide documents the required built-in SeaORM migration and the claim lifecycle contract for custom stores.
- Upgrade JSON now includes stable finding codes, affected paths, and documentation links; `--deny-warnings` provides a strict CI and agent exit status without modifying files.
- New backend scaffolds include an additive `billing_processed_events` migration with a primary-key event ID, and upgrade checks detect missing or incomplete versions of that migration.

### Migration Notes

- Install with `cargo install tideway-cli --version 0.1.38`; its upgrade checks target Tideway 0.7.24.

## [0.7.24] - 2026-07-14

### Fixed

- `SeaOrmBillingStore` now distinguishes inserted webhook claims from conflict results, preventing concurrent duplicate deliveries from both running handler side effects.
- Empty claim inserts fail closed, and a database-backed concurrency regression test verifies that exactly one caller wins.

### Migration Notes

- Built-in `SeaOrmBillingStore` users must add the `billing_processed_events` migration unless their application already has that table with `event_id` as its primary key.
- Custom `BillingStore` implementations must provide atomic `claim_event` and retry-safe `release_event_claim` implementations.

## [tideway-cli 0.1.37] - 2026-07-13

### Added

- `tideway dev` now watches Rust sources, migrations, Cargo manifests, and `.env`, then rebuilds and restarts the application after successful changes.
- Compile failures keep the last working server available, while superseded builds are cancelled and rapid editor saves are coalesced.
- `--no-watch` preserves the one-shot `cargo run` workflow, and a second `--` separates application arguments from Cargo arguments.

### Fixed

- Watch mode validates the configured host and port before compiling, with actionable guidance when the port is unavailable.
- `.env` changes are reloaded on restart, shell values retain precedence, and Ctrl-C or termination signals clean up child process trees.

### DX Gate

- A generated API was dogfooded through successful edits, compile failure and recovery, `.env` reload, save bursts, argument forwarding, health checks, and process cleanup.
- The CLI golden-path suite and repository DX guardrails pass without manually triggering hosted workflows.

### Migration Notes

- `tideway dev` now watches by default; use `tideway dev --no-watch` for the previous one-shot behaviour.
- Install with `cargo install tideway-cli --version 0.1.37`; generated projects use Tideway 0.7.23.

## [0.7.23] - 2026-07-13

### Fixed

- Graceful shutdown now hands control to Axum immediately instead of delaying connection draining by a fixed five seconds, substantially reducing development restart latency.
- The locked dependency graph uses the non-yanked `spin` 0.9.9 patch release.

### DX Gate

- The framework library suite, shutdown regression, generated-app health tests, and downstream smoke-project tests pass.
- Real-project incremental builds complete in roughly one second, with restart occurring immediately after graceful shutdown begins.

### Migration Notes

- No public APIs or generated source paths changed.
- Upgrade to `tideway = "0.7.23"`; applications receive the corrected shutdown behaviour without code changes.

## [tideway-cli 0.1.36] - 2026-07-13

### Fixed

- `tideway new --features mfa` now normalizes to the supported `auth-mfa` feature and generates the complete MFA entity, migration, route, and test scaffold.
- Unknown feature names fail before any files are written, with the supported feature list and a nearby suggestion when available.
- Existing shell environment variables now take precedence over `.env` for dev preflight, displayed URLs, and the Cargo child process.
- `tideway dev --no-migrate` explicitly sets `DATABASE_AUTO_MIGRATE=false` for the run, even when the shell or `.env` enables it.

### DX Gate

- Full CLI and workspace tests, strict all-feature Clippy, formatting, and all repository DX guardrails pass.
- A published-framework clean-room app booted on a shell-provided port that differed from `.env`, reported the effective URLs, honored `--no-migrate`, and returned a healthy response.

### Migration Notes

- No generated source paths or public framework APIs changed.
- Install with `cargo install tideway-cli --version 0.1.36`; generated projects continue to use Tideway 0.7.22.

## [0.7.22] - 2026-07-13

### Security

- Trusted-proxy resolution now accepts forwarded client IPs only from explicitly configured proxy networks and safely handles malformed or untrusted forwarding chains.
- Generated database-backed auth includes production-shaped registration, login, refresh rotation, logout, email verification, password reset, and access-token purpose checks.
- Generated MFA setup encrypts TOTP secrets at rest, hashes single-use backup codes, prevents secret disclosure through logs or caches, and verifies the complete enrollment and recovery lifecycle.
- Generated API onboarding uses secure environment defaults and makes authentication boundaries explicit in the starter routes and OpenAPI output.

### Fixed

- Fresh database-backed projects now include a runnable migration binary and automatically run migrations during local development when `DATABASE_AUTO_MIGRATE=true`.
- `tideway migrate` reuses the application target directory by default, avoiding a redundant migration build while preserving an explicitly configured `CARGO_TARGET_DIR`.
- Generated repository/service resources and auth extension hooks compile cleanly under strict Clippy without broad warning suppression.

### Changed

- `tideway-cli` 0.1.35 scaffolds Tideway 0.7.22.
- Database-enabled presets now generate a consistent entities and migration structure, including worker presets.
- The documented API workflow consistently follows `new` -> `dev --fix-env` -> `resource` -> `migrate`.

### DX Gate

- Quickstart parity, documentation drift, scaffold idempotency, golden-path integration, CLI filesystem policy, and public API checks pass.
- Fresh generated API projects compile, test, pass strict Clippy, start with an initialized database, and expose working health, resource, auth, OpenAPI, and Swagger routes.

### Migration Notes

- No public API removals or intentional breaking changes are included.
- Upgrade the framework to `tideway = "0.7.22"` and install `tideway-cli` 0.1.35 for newly generated projects.
- Existing generated applications are not rewritten automatically; adopt the new migration runner and hardened auth scaffolding deliberately when upgrading.
- Applications behind reverse proxies should configure trusted proxy networks explicitly before relying on forwarded client IP headers.

## [0.7.21] - 2026-07-11

### Security

- Access-token verification now rejects refresh tokens and enforces issuer/audience checks in generated auth paths.
- HS256 issuer and verifier setup now provides checked constructors that reject short and known-placeholder secrets; unchecked constructors are deprecated.
- Credentialed CORS configurations now reject wildcard origins and headers.
- Request logging redacts sensitive headers, query parameters, and structured body fields, and bounds body preview work.
- Generated billing webhooks claim events atomically before side effects and release retryable claims safely.
- Organization invitations are claimed atomically and cannot be consumed more than once.

### Fixed

- Per-IP rate limiting no longer trusts forwarded headers by default and uses a shared fallback bucket when client IP data is unavailable.
- In-memory job dequeue/retry coordination and WebSocket broadcasts avoid lock contention and stale membership cleanup races.
- Generated billing redirects are validated and billing route access boundaries are explicit.
- CLI dependency editing returns actionable errors for malformed `Cargo.toml` tables and feature arrays instead of panicking.

### Added

- Hot-path Criterion benchmarks and a manual-only end-to-end HTTP/WebSocket load-test workflow with artifact upload.
- Dependency auditing, formatting, all-feature Clippy, and MSRV checks in CI.
- Immutable SHA pinning and least-privilege permissions for GitHub Actions workflows.

### Changed

- Minimum supported Rust version is now 1.88 so the dependency graph includes the security-fixed `time` release.
- `tideway-cli` 0.1.34 scaffolds Tideway 0.7.21 with safer auth and billing defaults.

### Performance

- Reduced allocation and lock hold time in request logging, rate limiting, jobs, and WebSocket hot paths.
- Added reproducible microbenchmarks and integration load-test baselines for future regression tracking.

### DX Gate

- Quickstart parity, documentation drift, scaffold idempotency, golden-path integration, CLI filesystem policy, and public API checks pass.
- Generated API and SaaS presets compile and test against the workspace source.

### Migration Notes

- Install Rust 1.88 or newer before upgrading.
- Replace `JwtIssuerConfig::with_secret` with `with_secure_secret` and `JwtVerifier::from_secret` with `from_secret_checked`.
- Credentialed CORS must list explicit origins and headers rather than using `*`.
- No public API removals are included; deprecated JWT constructors remain available for compatibility.

## [0.7.19] - 2026-05-04

### Changed

- README and getting-started quickstarts now use `tideway dev --fix-env`, matching the enforced onboarding guardrails.
- Docs taxonomy checks now match the current Vue-focused advanced CLI helper wording.
- `tideway-cli` now scaffolds Tideway `0.7.19`.

### Notes

- This release includes `tideway-cli` `0.1.31`.
- No semver-breaking public API changes were introduced.

## [0.7.18] - 2026-04-27

### Added

- API-first scaffold refinements, including a seeded todo resource following the entity -> repository -> service path.
- Agent- and CI-friendly plan output plumbing across mutating CLI commands.
- SaaS resource generation improvements for auth-scoped resources, ownership checks, audit hooks, and service-owned validation.
- Testcontainers-backed Postgres helper support behind `test-containers`.

### Changed

- `tideway-cli` now scaffolds Tideway `0.7.18`.
- CLI onboarding now promotes the tested API path first, with advanced frontend/backend presets one step deeper.
- Dev-mode diagnostics, request dumping, doctor findings, and generated service errors are more explicit.

### Notes

- This release includes `tideway-cli` `0.1.30`.

## [0.7.17] - 2026-03-17

### Added

- `App::into_make_service_with_connect_info()` to mirror `serve()` when manually calling `axum::serve`.

### Changed

- Request logging body previews are now disabled by default (`body_preview_size = 0`).
- Manual-serve docs now use the same `ConnectInfo<SocketAddr>` path as `serve()` for per-IP middleware parity.

### Fixed

- Cookie session stores now reject expired sessions on load and set cookie `Max-Age` from the actual session expiry.
- Auth extractors now reuse cached users without redundant `validate_user()` calls.
- Testing body assertions preserve response status and headers for subsequent assertions.
- In-memory job workers now use queue wakeups instead of polling idle loops.
- `tideway doctor` now accepts valid `sqlite:...` URLs generated by Tideway itself.
- `tideway dev` no longer treats `dev-dependencies` and `build-dependencies` as runtime database requirements.
- `tideway setup` now exits non-zero on real setup failures and safely updates Vite alias config.

### Notes

- No semver-breaking public API changes were introduced in this batch. This should ship as a patch release.
- Two rollout-sensitive behavior changes are worth calling out in release notes:
  - `tideway setup` now returns a non-zero exit code when frontend setup fails instead of reporting success.
  - Request logging no longer captures body previews by default; set `body_preview_size` explicitly if you relied on that output.

## [0.7.9] - 2026-01-26

### Added

- `ensure!` guard macro for concise precondition checks.
- `module!` macro for route groups plus OpenAPI module helpers.
- Alba-style testing helpers (`TestApp`, JSON helpers, `post_json`, status/header assertions).
- Auth extractor caching for users and claims (`ClaimsRef`) to avoid duplicate verification.
- Expanded docs and README examples for auth extractors, testing helpers, OpenAPI modules, and CLI flags.

## [0.7.8] - 2026-01-23

### Changed

- Metrics and request logging now prefer route templates when available, reducing label cardinality.
- Request logging skips formatting work when the configured log level is disabled.
- Feature matrix added to README; install snippet updated.
- Added optional `feature-gate-warnings` and `feature-gate-errors` for clearer feature diagnostics.
- Added tests covering MatchedPath metrics and logging guard behavior.

## [0.7.7] - 2026-01-23

### Changed

- Seat add-ons via Checkout are now rejected; use `SeatManager::add_seats` (proration-safe).
- `create_seat_checkout_session` is deprecated in favor of `SeatManager::add_seats`.

## [0.7.6] - 2026-01-23

### Security

- Password reset and email verification tokens now use OS CSPRNG for generation.
- MFA tokens are hashed before storage and consumption in the login flow.
- Trusted-device verification now rejects missing fingerprints when fingerprint validation is enabled.

## [0.7.1] - 2025-12-12

### Fixed

- **Compilation fix**: Updated `tower-http` minimum version to 0.6.7 to ensure `TimeoutLayer::with_status_code()` method is available. Version 0.7.0 would fail to compile with older tower-http versions.

## [0.7.0] - 2025-12-12

### Security

This release contains important security hardening for enterprise deployments.

- **ConsoleMailer now redacts email content by default.** Email body content is no longer printed to stdout to prevent sensitive data (tokens, PII, verification links) from being captured in container logs.

- **Webhook signature prefix is now strictly enforced.** When using `HmacSha256Verifier::new_with_prefix()`, signatures missing the required prefix are now rejected instead of silently accepting unprefixed signatures.

- **Database credentials protected in all output.** Both `Debug` and `Serialize` implementations for `DatabaseConfig` now redact the password, preventing credential leakage in logs, JSON serialization, and error messages.

- **JWT warning spam eliminated.** Security warnings for missing issuer/audience validation now fire only once per verifier instance using `OnceLock`.

### Added

- `RedisJobQueue::shutdown()` - Gracefully stop the background scheduler task
- `RedisJobQueue::ping()` - Async health check that updates cached status
- `InMemoryJobQueue::shutdown()` - Gracefully stop the background scheduler task
- `InMemoryJobQueue::with_history_limit()` - Create queue with custom completed/failed history size
- `RedisCache::ping()` - Async health check that updates cached status
- `SeaOrmPool::ping()` - Async health check that updates cached status
- `ConnectionManager::reconcile_counter()` - Detect and correct connection counter drift
- `ConsoleMailer::with_full_output()` - Opt-in to see full email content (development only)
- Configuration validation warnings for invalid environment variables (compression, timeout, session configs)

### Changed

- **BREAKING**: `ConsoleMailer` now redacts email body content by default. Use `.with_full_output(true)` to see full content.
- **BREAKING**: `HmacSha256Verifier::new_with_prefix()` now rejects signatures missing the required prefix (was silently accepting).
- `InMemoryJobQueue` completed/failed lists are now bounded (default 10,000) to prevent unbounded memory growth.
- `is_healthy()` methods on `RedisCache`, `RedisJobQueue`, `InMemoryJobQueue`, and `SeaOrmPool` now return cached status from `ping()` instead of blocking.
- Database pool configuration now validates limits: `max_connections` (1-1000), `connect_timeout` (1-300 seconds).
- Signal handlers in `App::serve()` use fallback instead of panicking on failure.
- Shutdown grace period increased from 2 to 5 seconds.

### Fixed

- **Blocking I/O in async context**: `InMemoryJobQueue::is_healthy()` used `blocking_lock()` which could deadlock the async runtime. Now uses `AtomicBool`.
- **Resource leak**: Background scheduler tasks in `RedisJobQueue` and `InMemoryJobQueue` now have proper shutdown mechanisms.
- **Unbounded memory growth**: `InMemoryJobQueue` completed/failed job lists now have configurable size limits.
- **Panic in production**: Removed `expect()` calls in `App::serve()` that could panic on invalid config or signal handler failures.
- **WebSocket connection counter drift**: Added `reconcile_counter()` to detect and correct atomic counter drift.

### Migration Guide

#### ConsoleMailer (Breaking Change)

If you use `ConsoleMailer` for development and need to see full email content:

```rust
// Before (0.6.x) - full content shown by default
let mailer = ConsoleMailer::new();

// After (0.7.0) - content redacted by default
let mailer = ConsoleMailer::new();  // Shows: "[TEXT] 42 bytes [REDACTED]"

// To see full content (development only):
let mailer = ConsoleMailer::new().with_full_output(true);
```

#### Webhook Signature Verification (Breaking Change)

If you use `HmacSha256Verifier::new_with_prefix()`, signatures **must** now include the prefix:

```rust
// Verifier configured with prefix
let verifier = HmacSha256Verifier::new_with_prefix(secret, "sha256=");

// Before (0.6.x) - both would pass:
verifier.verify_signature(payload, "sha256=abc123...").await  // OK
verifier.verify_signature(payload, "abc123...").await         // Also OK (wrong!)

// After (0.7.0) - prefix is required:
verifier.verify_signature(payload, "sha256=abc123...").await  // OK
verifier.verify_signature(payload, "abc123...").await         // FAILS (correct!)
```

#### Job Queue Shutdown (Recommended)

For clean resource cleanup, call `shutdown()` before dropping job queues:

```rust
// Redis job queue
let queue = RedisJobQueue::new("redis://localhost", None, 3, 5)?;
// ... use queue ...
queue.shutdown().await;  // NEW: Clean shutdown

// In-memory job queue
let queue = InMemoryJobQueue::new(3, 60);
// ... use queue ...
queue.shutdown().await;  // NEW: Clean shutdown
```

#### Health Check Pattern (Recommended)

For accurate health status, run periodic `ping()` calls:

```rust
// Database pool
let pool = SeaOrmPool::from_config(&config).await?;
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        pool.ping().await;  // Updates cached health status
    }
});

// is_healthy() now returns cached status (non-blocking)
if pool.is_healthy() { /* ... */ }
```

## [0.6.0] - 2025-12-12

### Security

**Cookie sessions are now properly encrypted.** Previously, session data was stored as plaintext JSON despite having an encryption key configured. This version implements authenticated encryption using XChaCha20-Poly1305 via the `cookie` crate's private cookies.

### Changed
- **BREAKING**: Cookie session encryption key must now be 64 bytes (128 hex characters), not 32 bytes. Generate with: `openssl rand -hex 64`
- Session cookies are now encrypted and authenticated - tampered cookies are rejected
- Added `encrypt()` and `decrypt()` public methods to `CookieSessionStore` for direct use
- Updated session documentation with correct key size requirements

### Migration Guide

If you were using cookie sessions, regenerate your encryption key:

```bash
# Old (no longer works):
# openssl rand -hex 32

# New (required):
openssl rand -hex 64
export SESSION_ENCRYPTION_KEY=your-128-char-hex-key
```

**Important:** Existing sessions will be invalidated when you upgrade, as the encryption format has changed.

## [0.5.0] - 2025-12-12

### Security

This release contains important security fixes. Users are strongly encouraged to upgrade.

- **Webhook HMAC verification**: Implemented proper HMAC-SHA256 signature verification with timing-safe comparison using the `subtle` crate. Previously, the webhook verifier accepted any non-empty signature.

- **Session encryption key requirement**: Cookie sessions now require an explicit encryption key. Without it, `CookieSessionStore::new()` returns an error. Use `allow_insecure_key: true` for development only.

- **Error information disclosure (CWE-209)**: Server errors (5xx) now hide internal details in production, preventing leakage of database credentials, internal hostnames, SQL queries, and stack traces.

- **Rate limiter IP spoofing**: Added `trust_proxy` configuration (default: `false`). X-Forwarded-For headers are now ignored by default to prevent IP spoofing attacks.

- **CORS disabled by default**: CORS is now disabled by default and must be explicitly enabled.

### Added
- `HmacSha256Verifier` for webhook signature verification with support for hex, base64, and prefixed signatures
- `trust_proxy` configuration for rate limiting
- `allow_insecure_key` configuration for session development mode
- `safe_message()` method on `TidewayError` for production-safe error messages
- Comprehensive test suite (200+ tests)
- Webhook documentation (`docs/webhooks.md`)

### Changed
- **BREAKING**: CORS `enabled` now defaults to `false` (was `true`)
- **BREAKING**: Rate limiter `trust_proxy` defaults to `false` - X-Forwarded-For is no longer trusted by default
- **BREAKING**: Cookie sessions require `encryption_key` or `allow_insecure_key: true`
- Session encryption key error now returns `Result` instead of panicking
- Updated `sessions.md`, `rate_limiting.md`, and `error_handling.md` documentation

### Dependencies
- Added `subtle` crate for timing-safe cryptographic operations
- `hmac` and `sha2` crates (already present) now used for webhook verification

### Migration Guide

#### CORS Configuration

CORS is now disabled by default. To enable:

```rust
// Option 1: Use permissive() for development
let cors = CorsConfig::permissive();

// Option 2: Explicitly enable with origins
let cors = CorsConfig::builder()
    .enabled(true)
    .allow_origin("https://example.com")
    .build();
```

#### Session Configuration

Cookie sessions now require a 64-byte encryption key (128 hex characters):

```bash
# Generate a key
openssl rand -hex 64

# Set environment variable
export SESSION_ENCRYPTION_KEY=your-128-char-hex-key
```

Or for development only:
```rust
let config = SessionConfig {
    allow_insecure_key: true,  // WARNING: Never use in production!
    ..Default::default()
};
```

#### Rate Limiting Behind a Proxy

If your application is behind nginx, AWS ALB, or Cloudflare:

```rust
let rate_limit = RateLimitConfig::builder()
    .enabled(true)
    .per_ip()
    .trust_proxy(true)  // Enable this if behind a trusted proxy
    .build();
```

Or via environment:
```bash
export RATE_LIMIT_TRUST_PROXY=true
```

## [0.4.0] - 2025-12-11

### Added
- Comprehensive test coverage for core modules

### Changed
- **BREAKING**: `SeaOrmPool::as_ref()` renamed to `SeaOrmPool::inner()` to avoid confusion with `std::convert::AsRef` trait
- **BREAKING**: `DatabaseConnection::as_ref()` renamed to `DatabaseConnection::inner()`
- **BREAKING**: `TestUser::default()` renamed to `TestUser::generate()` to avoid confusion with `std::default::Default` trait

### Fixed
- Fixed deprecated `TimeoutLayer::new` usage (now uses `with_status_code`)
- Fixed all clippy warnings across the codebase
- Improved code quality with idiomatic Rust patterns

### Migration Guide

#### Database Connection Changes

If you were using `as_ref()` to get the inner SeaORM connection:

```rust
// Before (0.3.x)
let conn = sea_orm_pool.as_ref();

// After (0.4.0)
let conn = sea_orm_pool.inner();
```

#### TestUser Changes

If you were using `TestUser::default()` in tests:

```rust
// Before (0.3.x)
let user = TestUser::default();

// After (0.4.0)
let user = TestUser::generate();
```

The rename to `generate()` better reflects that this creates a new user with randomly generated fake data, not a "default" user with empty/zero values.

## [0.3.0] - 2025-12-11

### Added
- **Email support** with `Mailer` trait for sending transactional emails
- `ConsoleMailer` for development (prints emails to stdout)
- `SmtpMailer` using lettre for production SMTP
- `SmtpConfig` with builder pattern and `from_env()` for configuration
- `AppContext::with_mailer()` builder method for dependency injection
- Documentation for third-party email services (Resend, SendGrid, Postmark, AWS SES)
- Email example and comprehensive test suite

## [0.2.1] - 2025-12-11

### Fixed
- Various bug fixes and improvements

## [0.2.0] - 2025-12-11

### Added
- Background jobs system with `JobQueue` trait
- WebSocket support with connection management
- In-memory and Redis-backed job queues

## [0.1.0] - Initial Release

### Added
- Core framework with Axum integration
- Route modules and modular architecture
- Database support with SeaORM
- Cache and session traits
- Request validation
- Health checks
- Prometheus metrics
- Compression and security middleware
- Alba-style testing utilities
