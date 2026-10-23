# Tideway 0.9.0

## Release

- Version: 0.9.0 (`tideway`). `tideway-cli` 0.9.0 is not part of this release.
- Date: 2026-10-23
- Release owner: Jord

## Summary

Tideway 0.9.0 collects about 130 changes since 0.8.0: security fixes across auth, impersonation,
organizations, billing, OpenAPI, sessions, and WebSockets; new framework features (authorization policies, OpenTelemetry and
Sentry, file storage, recurring jobs, lifecycle emails); and faster PostgreSQL tests. It is **not**
a drop-in update from 0.8: some APIs changed, so `cargo update` keeps `^0.8` apps on 0.8.x. Change
the dependency to `tideway = "0.9.0"` and follow
[`docs/upgrading.md`](../../docs/upgrading.md#08x-to-090-breaking-changes).

## Breaking changes since 0.8

These stop compiling:

- `ImpersonationRequest` and `DeletionRequest` no longer derive `Deserialize`. Deserialize
  `ImpersonationRequestBody` / `DeletionRequestBody` and call `into_request(actor_id)`.
- `WebSocketHandler::on_upgrade` is now `on_upgrade(&self, req: &mut UpgradeRequest, ctx: &AppContext)`.
- `tideway::prelude` exports `DatabaseConnectionTrait` instead of `DatabaseConnection`.
- `CachedInvoiceManager::list_invoices` returns `Arc<InvoiceList>`, and `get_upcoming_invoice`
  returns `Option<Arc<Invoice>>`.
- `SecureRefundManager::get_refund` takes the billable ID: `get_refund(billable_id, refund_id)`.
- New fields break struct literals and exhaustive patterns: `CreateRefundRequest::idempotency_key`,
  `Refund::replayed`, `JobsConfig::shutdown_timeout_seconds`, `MetricsConfig::bearer_token`,
  `BillingEvent::OneTimeCheckoutCompleted::payment_intent_id`, and `invoice` on
  `BillingEvent::InvoicePaid` / `InvoicePaymentFailed`, and `RefreshTokenClaims::session_version`.
- `CreditTransactionKind` is `#[non_exhaustive]`.
- `SessionManager` and `RedisCache` are no longer `UnwindSafe` / `RefUnwindSafe`.

These compile but change behavior a deployment may rely on:

- The metrics route returns 404 until `TIDEWAY_METRICS_BEARER_TOKEN` is set; scrapers must send it.
- The `imp_blocked` claim uses snake_case action names (`delete_account`, not `deleteaccount`).
- `allow_admin_impersonation` no longer overrides a user's impersonation opt-out.
- `ConfigBuilder::from_env()` keeps builder values when the environment variable is absent.
- Stripe errors convert to `TidewayError::Billing` and map to 400/404/429 instead of 500, without
  exposing Stripe's message (card errors excepted).
- `credits-seaorm` apps must run a database migration before deploying.
- `RedisCache` keys gain a `cache:` prefix (expect a cold cache), merged routers now get the full
  middleware stack (including rate limiting), and the rate limiter now sustains `max_requests` per
  window.
- `LoginFlow` returns "Invalid credentials" instead of `423` for locked accounts.
- `PasswordChangeFlow` and `AccountDeletionFlow` allow 5 current-password attempts per user per 15
  minutes, then return `TooManyRequests`.
- `Claims` and `ClaimsRef` load and validate the user, so revoked tokens are rejected.
- `OrganizationConfig::require_verified_email` defaults to `false`; `true` needs an
  `EmailVerificationChecker`.
- `OPENAPI_VISIBILITY=public` hides operations tagged `internal` from the served spec.

Deprecated: `MembershipManager::transfer_ownership` (use `OrganizationManager::transfer_ownership`)
and `EmailVerificationFlow::resend` (use `resend_for_user`).

## Highlights

- **Faster PostgreSQL tests.** `TestDb::new_postgres_with_migrator` migrates once into a
  `test_tpl_<hash>` template and copies it for each test instead of running every migration per
  test. Databases left behind by crashed or killed runs are swept on the next run.
  `TIDEWAY_TEST_KEEP_DBS=1` still keeps databases. See `docs/testing.md`.
- **Security.** Impersonation tokens are session-bound and respect opt-outs. Revoking a session
  revokes its refresh tokens, and refresh tokens are bound to the session version. Account lockout
  and re-authentication resist password guessing. Verification resend only mails the stored
  address. Admins can no longer create owners. Organization and seat limits hold under
  concurrency. Stripe syncs use the billed price and live subscription state. Refund lookups are
  scoped to the billable entity. Credits are reversed on refund or dispute. JWKS keys refresh on a
  schedule. See the Security section of `CHANGELOG.md`.
- **New features.** `tideway::policy` resource authorization; OpenTelemetry export and Sentry error
  reporting; `FileStorage` (local, S3, R2); a cron `JobScheduler`; default lifecycle emails; Stripe
  webhook secret rotation.
- **Reliability.** Bounded job shutdown on SIGTERM, idempotent refunds and usage records,
  duplicate-subscription protection, and no more `FLUSHDB` from `RedisCache::clear()`.

## DX Metrics

### DX Gate Status

- [x] quickstart parity (`bash scripts/check_quickstart_parity.sh`)
- [x] docs drift (`bash scripts/check_docs_drift.sh`)
- [x] scaffold idempotency (`cargo test -p tideway-cli --test plan_mode_mutating_commands_test` and `cargo test -p tideway-cli --test resource_command_test`)
- [x] golden path integration tests (`cargo test -p tideway-cli --test dx_golden_path_test`)
- [x] downstream upgrade contract (`bash scripts/check_downstream_upgrade.sh`)

Also passing: `cargo test -p tideway` with default and all features, PostgreSQL `TestDb` tests
(`cargo test --test it test_db -- --include-ignored`), `tideway-macros`, feature-gate checks, and
the public API surface check, the full `tideway-cli` suite, and `cargo audit`.

### Metrics Snapshot

- Metrics snapshot file: `docs/dx_metrics_snapshot.md`
- Latest `tideway-dx-benchmark` workflow run/artifact: not re-run for this release
- Time to `GET /health` from clean machine (p50/p95): unchanged from snapshot (27.33s / 30.61s)
- Time to scaffold DB resource and run tests (p50/p95): unchanged from snapshot (5.60s / 5.72s)
- Idempotency pass rate for mutating CLI commands: 100% (scaffold idempotency gate passing)
- Number of onboarding docs that show non-canonical flows: 0
- Number of user-reported "which command should I use" issues: not queried
- DX gate summary copied into changelog entry: no

## Migration Notes

- Breaking changes: see above and `CHANGELOG.md` `[0.9.0]`.
- Deprecated or legacy paths touched: `MembershipManager::transfer_ownership`,
  `EmailVerificationFlow::resend`.
- Upgrade steps: set `tideway = "0.9.0"`, fix compile errors per `docs/upgrading.md`, set
  `TIDEWAY_METRICS_BEARER_TOKEN` if metrics are scraped, run `credits-seaorm` migrations, then run
  `tideway --json doctor --upgrade --deny-warnings` and the app's tests.
- `docs/upgrading.md` updated for downstream changes: yes.
- Policy reference: `docs/deprecation_policy.md`

## Links

- Changelog entry: `CHANGELOG.md` `[0.9.0] - 2026-10-23`
- Previous release: `tideway-v0.8.0`
