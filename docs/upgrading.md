# Upgrading Tideway Applications

Tideway upgrades should be small, reviewable changes. Update the framework and only the
dependencies or APIs required by that framework release; keep unrelated application cleanup in
separate commits.

Generated application files belong to the application after creation. The upgrade command never
regenerates or overwrites them, and an upgrade should not rerun `new`, `backend`, `add --force`, or
other broad scaffolding commands over an existing project. Apply reported changes as focused edits
that follow the application's existing structure and business rules.

New CLI capabilities are not automatically upgrade requirements. For example, newer B2B/SaaS
scaffolds include secure organization invitations, but an existing app is not warned merely for
lacking those generated files. Apps with custom organization or invitation models should use the
adoption checklist in [Organizations](organizations.md#existing-and-custom-organization-models)
and add only schema-compatible migrations. This avoids replacing application roles, route
contracts, authorization rules, or table layouts.

## Recommended Workflow

1. Update the CLI so its checks target the current framework release:

   ```bash
   cargo install tideway-cli --locked
   ```

2. Start from a clean branch or commit, then run the read-only upgrade check from the application
   directory:

   ```bash
   tideway doctor --upgrade
   ```

   Use `--json` for CI or agent workflows. The check does not edit files or contact a registry. It
   compares the application with the framework version bundled into the installed CLI.

3. Change the Tideway version in `Cargo.toml`, then update only Tideway first:

   ```bash
   cargo update -p tideway --precise <version>
   cargo check --locked
   ```

4. Apply the specific compatibility changes reported by `doctor --upgrade` and this guide.

5. Run the normal project doctor after making the source changes. Upgrade mode intentionally checks
   compatibility only; normal mode checks environment, wiring, and migration setup:

   ```bash
   tideway doctor --deny-warnings
   ```

6. For database-backed applications, review and run pending migrations in the normal deployment
   workflow. Inspect the migration diff before applying it to shared environments.
   Tideway-generated additive migrations preserve the application's existing sequential or SeaORM
   timestamp naming convention; they do not introduce a separate framework migration history.

7. Run the application's complete test suite before committing:

   ```bash
   cargo test --locked
   ```

Avoid a broad `cargo update` during the framework upgrade. It makes failures harder to attribute
and mixes Tideway migration work with unrelated dependency changes.

After remediation, CI and code agents can require a clean upgrade report:

```bash
tideway --json doctor --upgrade --deny-warnings
```

`--deny-warnings` changes only the exit status; it does not apply fixes.

Upgrade doctor checks inspect `Cargo.toml`, application source, and migration source. They do not
connect to or verify a deployed database, so migration status and constraints must still be checked
through the application's normal migration and deployment workflow.

## 0.7.29 to 0.7.30 / CLI 0.1.45 to 0.1.46: fail-safe generated authentication

This release makes newly generated authentication safer for private and invitation-only products.
It also corrects framework rate-limiter recovery semantics. The framework update is additive and
does not rewrite application-owned routes, configuration, CI, tests, OpenAPI documents, or frontend
components.

Applications upgrading from 0.7.28 or earlier must also review each intervening section below. In
particular, applications using `billing-seaorm` must complete the 0.7.28-to-0.7.29 billing customer
schema check before deploying 0.7.30.

### Install and inspect

From a clean application branch:

```bash
cargo install tideway-cli --version 0.1.46 --locked
tideway --json doctor --upgrade
```

Then set the application dependency to Tideway 0.7.30, preserving every feature the application
already enables, and update only Tideway:

```toml
[dependencies]
tideway = { version = "0.7.30", features = ["auth"] }
```

```bash
cargo update -p tideway --precise 0.7.30
cargo check --locked
```

The dependency update delivers:

- reusable `AuthRateLimitConfig` and `AuthRateLimiter` types;
- backwards-compatible `LoginRateLimitConfig` and `LoginRateLimiter` aliases;
- corrected quota construction so a configured burst is replenished across its documented window.

It does **not** change the application's existing route topology or production policy.

For a read-only comparison with the current generated shape, create a disposable reference project
outside the application and inspect its auth files. Never run a broad scaffold with `--force` over
the real application:

```bash
tideway new tideway-auth-reference --preset api --no-prompt --path /tmp/tideway-auth-reference
```

### Adopt an explicit registration policy

Historical generated routes mounted `POST /auth/register` unconditionally. Add an
application-owned setting that defaults to `false`, pass it into the auth module, and mount the
route only when enabled:

```rust
let allow_public_registration = std::env::var("ALLOW_PUBLIC_REGISTRATION")
    .is_ok_and(|value| value.eq_ignore_ascii_case("true"));

let auth_module = AuthModule::new(/* existing dependencies */)
    .with_public_registration(allow_public_registration);
```

The module route builder should conditionally add the operation rather than returning a rejection
from a permanently mounted handler:

```rust
let router = Router::new()
    .route("/login", post(login))
    .route("/refresh", post(refresh))
    .route("/logout", post(logout));

let router = if state.allow_public_registration {
    router.route("/register", post(register))
} else {
    router
};
```

Add the fail-safe default to deployment configuration:

```dotenv
ALLOW_PUBLIC_REGISTRATION=false
```

If the application publishes OpenAPI, remove `/auth/register` from the final document whenever the
route is disabled. Add tests for both policies: the private configuration returns `404`, while the
explicitly enabled configuration contains the route and OpenAPI operation.

`TW-UPGRADE-AUTH-REGISTRATION-POLICY` remains until doctor can identify either the generated policy
shape or an audited custom equivalent.

### Protect registration and refresh

Create independent endpoint limiters; do not reuse the login bucket because the costs and expected
traffic differ:

```rust
use tideway::auth::{AuthRateLimitConfig, AuthRateLimiter};

let registration_rate_limiter =
    AuthRateLimiter::new(AuthRateLimitConfig::new(5, 60 * 60));
let refresh_rate_limiter =
    AuthRateLimiter::new(AuthRateLimitConfig::new(60, 60));
```

Before password hashing, token parsing, or database writes:

1. Resolve the client address with `ClientIpResolver` and the application's exact
   `TRUSTED_PROXY_IPS` allowlist.
2. Check the limiter using the resolved client IP.
3. Return `429 Too Many Requests` with an integer `Retry-After` header when blocked.
4. Keep logout outside ordinary auth throttling so clients can revoke sessions.

Registration and refresh must use separate keys or limiter instances. Password reset and
verification resend should additionally limit normalized email addresses so rotating source IPs
cannot create unlimited delivery work.

Generated limiters are process-local. Multi-replica deployments should enforce an equivalent
shared policy at a trusted gateway or use a distributed limiter.

Add route tests that exhaust each configured quota, assert `429`, and confirm `Retry-After` is
present. `TW-UPGRADE-AUTH-ENDPOINT-RATE-LIMITS` remains until doctor identifies both generated
limiters or an audited custom equivalent.

For custom or gateway-backed implementations, review the effective controls before placing these
markers beside the relevant policy code:

```rust
// tideway:auth-registration-policy
// tideway:auth-endpoint-rate-limits
```

The markers acknowledge an application-owned audit; they do not enable any framework behavior.

### Add PostgreSQL security coverage

Existing applications do not receive new CI or test files from the dependency update. Add a
PostgreSQL service and a disposable test URL to CI:

```yaml
services:
  postgres:
    image: postgres:16
    env:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: app_test
    ports:
      - 5432:5432
    options: >-
      --health-cmd "pg_isready -U postgres -d app_test"
      --health-interval 10s
      --health-timeout 5s
      --health-retries 5
env:
  TEST_DATABASE_URL: postgres://postgres:postgres@localhost:5432/app_test
```

Keep a committed application `Cargo.lock`. A fresh scaffold may generate it once, but CI should not
replace an existing lockfile.

Use an isolated PostgreSQL schema per test database fixture, run the application's real migrations,
and cover at least:

- cross-tenant read or mutation denial;
- member denial for an owner/admin-only operation;
- concurrent uniqueness, invitation, seat, or idempotency constraints;
- concurrent refresh-token reuse;
- clean migration application against a fresh database.

SQLite may remain the fast fallback for tests that do not depend on PostgreSQL transaction,
locking, type, or constraint behavior.

### Align the generated Vue registration form

The CLI 0.1.46 Vue `RegisterForm` remains hidden unless its `registrationEnabled` prop is `true` or
the frontend build has:

```dotenv
VITE_ALLOW_PUBLIC_REGISTRATION=true
```

Set that frontend value only when the backend also has `ALLOW_PUBLIC_REGISTRATION=true`. The Vite
value controls presentation and is visible to clients; it is never an authorization boundary.
Existing custom frontends require no change if they already hide or omit registration.

### Verify and deploy

After the focused application edits:

```bash
tideway --json doctor --upgrade --deny-warnings
tideway doctor --deny-warnings
cargo test --locked
```

For PostgreSQL applications, run the suite with `TEST_DATABASE_URL` before deployment and apply any
intervening additive migrations through the normal release process. Tideway 0.7.30 itself requires
no new database migration.

Rollback is straightforward: application code can return to 0.7.29 without a schema rollback.
Preserve the explicit registration policy, endpoint protection, and security tests because they do
not depend on a breaking 0.7.30 API.

## 0.7.28 to 0.7.29: billing customer schema contract

This patch aligns fresh billing migrations with the schema already required by
`SeaOrmBillingStore`. Existing applications using a custom `BillingStore`, or applications without
`billing-seaorm`, require no migration.

Applications using `SeaOrmBillingStore` should:

1. Install the matching CLI and run `tideway doctor --upgrade`. The
   `TW-UPGRADE-BILLING-CUSTOMER-SCHEMA` warning means migration source does not contain
   `billing_customers.billable_type` and `billing_customers.updated_at`. Because doctor is
   read-only and source-based, an edited historical migration can appear ready while an already
   deployed database is still incompatible; `validate_schema` is the authoritative runtime check.
2. Run `tideway add billing-schema`. The command preserves sequential or timestamp migration names,
   always creates a forward repair unless one is already registered, does not edit the historical
   billing migration, and does not change application code or dependencies.
3. Review the new migration before applying it. Existing rows receive `billable_type = "legacy"`
   because Tideway cannot safely infer an application's user-versus-organization model. The value
   is not used for authorization. Backfill a domain-specific value only when the application can
   derive it unambiguously.
4. Apply the migration before deploying the upgraded framework. Then call
   `billing_store.validate_schema().await?` during startup or from a database contract test
   so the deployed schema is checked, not only the migration files.
5. Exercise a real store-backed customer/Checkout path in application CI. Stripe itself may remain
   mocked; the database interaction must use `SeaOrmBillingStore`.

The repair is additive and its down migration intentionally retains the required columns. For an
emergency rollback, roll application code back while leaving the columns in place. Dropping them
would also break historical Tideway versions whose SeaORM model already expected them.

## 0.7.27 to 0.7.28: optional credits and allowances

The credits module is opt-in. Upgrading Tideway does not create tables, change billing behavior, or
require existing applications to adopt it. Applications that want allowances or prepaid product
units should first complete the normal framework upgrade above, then make adoption a separate,
reviewable change:

1. From a clean application worktree, run `tideway add credits`. The command adds the `credits` and
   `credits-seaorm` features, enables SeaORM's `with-json` migration support, and creates a ledger
   migration using the next available migration number.
2. Review the `Cargo.toml`, `migration/Cargo.toml`, generated migration, and migration registration.
   The command never renames, renumbers, or overwrites existing application migrations. Rerunning it
   detects an existing credits migration rather than creating another one.
3. Apply the migration through the application's normal deployment workflow before deploying code
   that constructs `SeaOrmCreditStore`.
4. Wire `CreditManager` only at application-owned usage boundaries. Derive `account_id` from the
   authenticated actor; do not trust a tenant identifier supplied directly by a client.
5. If prepaid Stripe top-ups are needed, enable `credits-stripe`, define immutable server-side pack
   IDs, and attach `CreditTopUpEventSink` to the existing billing webhook handler.
6. Run `tideway doctor --deny-warnings` and the application's migration, authorization, billing, and
   concurrency tests before committing.

Rollback is additive: application code can stop using the module while retaining the ledger tables.
Do not drop the tables during an emergency application rollback because they contain balances,
reservations, idempotency records, and audit history. See [Credits and allowances](credits.md) for
the full reserve/commit workflow and operational guidance.

## CLI 0.1.42 to 0.1.43: stable JWT identity

This CLI update changes newly generated auth code and does not rewrite existing application-owned
files. New projects use Tideway 0.7.27's paired `JwtAuth` API. Existing projects can either upgrade
to that additive API or apply the same single-source-of-truth pattern with their current
`JwtIssuer` and `JwtVerifier` types.

Some older SaaS scaffolds issued tokens with the display-facing `APP_NAME` as `iss`, while protected
routes independently expected the Cargo package name. Those applications could successfully
register and log in but receive `InvalidIssuer` from protected routes when the two names differed.
Verification failed closed, so this was an availability and correctness problem rather than an
authentication bypass.

Existing applications should first run `tideway doctor --upgrade`. If it reports
`TW-UPGRADE-JWT-IDENTITY-DRIFT`, make a focused application-owned change:

1. Add stable `JWT_ISSUER` and `JWT_AUDIENCE` settings. Do not derive them from a human-readable
   product name.
2. Prefer Tideway 0.7.27's `JwtAuthConfig` and `JwtAuth` to construct the issuer and access-token
   verifier from those values at startup. If remaining on an older Tideway release, configure the
   existing `JwtIssuer` and `JwtVerifier` together from the same values.
3. Pass the configured verifier to protected modules instead of giving each module the raw secret
   and allowing it to reconstruct policy independently.
4. Add an integration test that logs in and uses the returned access token on at least one protected
   application route. Use an `APP_NAME` deliberately different from `JWT_ISSUER` in that test.

Changing issuer or audience invalidates tokens created under the old identity. If production
issuance and verification already agree, preserve those existing values in the new settings and
deploy both sides together. Do not rotate the signing secret merely to adopt the explicit settings.

## 0.7.25 to 0.7.26

This is an additive framework update with no required database migration. `ResendMailer` is
available as a first-party HTTPS email provider; existing `Mailer` implementations and SMTP
configuration continue to work unchanged.

Fresh Tideway CLI 0.1.41 SaaS projects can include secure organization invitations. Generated files
remain application-owned, so existing applications should not rerun broad scaffolds over custom
code. Adopt only the relevant schema-compatible patterns from `docs/organizations.md`, including
token digests, atomic claims, organization scoping, seat checks, and delivery rate limits.

The invitation limiter remains process-local by default. Single-replica deployments require no
additional configuration; multi-replica deployments should provide a shared
`InvitationRateLimitProvider` so all replicas enforce one quota.

## 0.7.24 to 0.7.25

Custom stores that support seat changes must override `compare_and_save_subscription`. The
default trait implementation performs its read and write separately and is intended only for
development compatibility. Production implementations must use one conditional database operation,
such as `UPDATE ... WHERE billable_id = ? AND updated_at = ?`, and return `false` when no row matched.
The saved version must differ from the expected version, including when two updates occur during the
same wall-clock tick. Add a database-backed concurrency test that starts two updates with the same
expected version and asserts exactly one succeeds. Tideway CLI 0.1.39 reports custom stores without
this override through `tideway doctor --upgrade`.

`WebhookHandler::with_event_sink` is an additive hook for application billing lifecycle work. New
SaaS scaffolds include an application-owned sink; existing applications can continue using
`WebhookHandler::new` unchanged and receive the no-op default. Event sinks run after core state
updates and must be idempotent by Stripe event ID because a sink error releases the claim for retry.

## 0.7.23 to 0.7.24

Tideway 0.7.24 corrects duplicate-event handling in the built-in `SeaOrmBillingStore`. Applications
using that store receive the code fix by updating Tideway. The store requires a
`billing_processed_events` table whose `event_id` column is the primary key.

Fresh CLI scaffolds include `m010_create_billing_processed_events`. Existing applications must add
an equivalent migration unless they already have that table and constraint. The older
`webhook_processed_events` table belongs to the generic `DatabaseIdempotencyStore`; it does not
replace the billing store's table. Use the next available migration number in applications that
already have an `m010` migration, and register it without rewriting existing migrations.

For Tideway 0.7.27, add an application-owned migration that adds `status` (default `processed`),
nullable `claim_token`, and nullable `claimed_at` columns to both processed-event tables. Existing
rows remain completed. Fresh CLI projects include `m012_add_webhook_claim_lifecycle`; do not replace
or renumber application migrations that have already run.

Applications with a custom `BillingStore` should override `acquire_event_claim`,
`complete_event_claim`, and `release_owned_event_claim`. Acquisition must atomically create or
reclaim a stale lease. Completion and release must condition on both event ID and the opaque claim
token, so an expired worker cannot mutate a newer worker's claim. `AlreadyProcessed` is only for
completed work; an active claim must remain retryable. Compatibility defaults keep existing stores
compiling, and `tideway doctor --upgrade` warns until they adopt recoverable claims.

The essential SeaORM result handling is:

```rust,ignore
match processed_event::Entity::insert(event)
    .on_conflict(
        OnConflict::column(processed_event::Column::EventId)
            .do_nothing()
            .to_owned(),
    )
    .do_nothing()
    .exec(db)
    .await?
{
    TryInsertResult::Inserted(_) => Ok(true),
    TryInsertResult::Conflicted => Ok(false),
    TryInsertResult::Empty => Err(TidewayError::internal("empty webhook claim insert")),
}
```

Keep side effects idempotent by Stripe event ID. A lease closes the process-crash loss window, but
no database claim can guarantee exactly-once execution of an external side effect after lease
expiry.

## Machine-readable findings

Upgrade findings emitted with `--json` contain a stable `code`, `affected_path`, `docs_url`,
`level`, and human-readable `message`. Warning codes currently include:

| Code | Meaning |
| --- | --- |
| `TW-UPGRADE-DEPENDENCY-MISSING` | No Tideway dependency was found. |
| `TW-UPGRADE-VERSION-MISMATCH` | The application and installed CLI target different Tideway versions. |
| `TW-UPGRADE-VALIDATOR-MISMATCH` | A direct Validator dependency is incompatible. |
| `TW-UPGRADE-STRIPE-TLS-CONFLICT` | Direct async-stripe TLS features conflict with Tideway. |
| `TW-UPGRADE-BILLING-CLAIM-LIFECYCLE` | A custom billing store lacks owned acquire, complete, or release overrides. |
| `TW-UPGRADE-BILLING-RECOVERABLE-CLAIMS` | Billing processed-event tables lack lease lifecycle columns. |
| `TW-UPGRADE-BILLING-SUBSCRIPTION-CAS` | A custom billing store lacks an atomic subscription compare-and-save override. |
| `TW-UPGRADE-BILLING-CUSTOMER-SCHEMA` | Migration source lacks required built-in billing customer columns. |
| `TW-UPGRADE-BILLING-MIGRATION-MISSING` | The built-in billing store's event migration is absent. |
| `TW-UPGRADE-BILLING-MIGRATION-PRIMARY-KEY` | The event-ID uniqueness constraint could not be confirmed. |
| `TW-UPGRADE-JWT-ISSUER-SECRET` | The deprecated unchecked JWT issuer constructor is present. |
| `TW-UPGRADE-JWT-VERIFIER-SECRET` | The deprecated unchecked JWT verifier constructor is present. |
| `TW-UPGRADE-JWT-IDENTITY-DRIFT` | JWT issuance uses a display name while verification expects the Cargo package name. |
| `TW-UPGRADE-AUTH-REGISTRATION-POLICY` | A generated registration route is mounted without an explicit public-registration policy. |
| `TW-UPGRADE-AUTH-ENDPOINT-RATE-LIMITS` | Generated registration and refresh routes need endpoint-specific protection. |
| `TW-UPGRADE-APP-CONTEXT-DATABASE` | Application code accesses the old database field directly. |

For custom auth routing, remediate the two auth findings with equivalent application or gateway
controls. After reviewing the implementation, place `// tideway:auth-registration-policy` and
`// tideway:auth-endpoint-rate-limits` beside the relevant policy code so future read-only doctor
checks can distinguish an audited custom implementation from an unchanged historical scaffold.

## 0.7.13 to 0.7.23

Applications using the same surfaces as the API and SaaS presets may need these changes:

| Area | Required migration |
| --- | --- |
| Tideway | Set `tideway = "0.7.23"` and run `cargo update -p tideway --precise 0.7.23`. |
| Validation | If the app directly depends on `validator`, align it to `0.20`. A mismatch can surface as opaque Axum `Handler` trait errors. |
| Stripe | Tideway 0.7.23 billing selects async-stripe's `runtime-tokio-hyper` transport. A direct async-stripe dependency must select the same transport because async-stripe rejects multiple TLS implementations. |
| App context | Replace direct `context.database` field access with `context.database_opt()` or the appropriate public database accessor. |
| JWT issuing | Replace `JwtIssuerConfig::with_secret(...)` with `with_secure_secret(...)?`. Secrets must contain at least 32 bytes. |
| JWT verification | Replace `JwtVerifier::from_secret(...)` with `from_secret_checked(...)?`. |

The secure JWT constructor migration validates secret strength; it does not require changing token
audience or issuer policy. Treat policy changes as separate, explicitly reviewed auth work.

## Deployment Checks

- Confirm `JWT_SECRET` and any separate portal/auth secrets are at least 32 bytes before deploying.
- Expect `cargo check` to catch compile-time API migrations, but run integration tests for auth,
  billing, migrations, and generated routes.
- Commit the framework upgrade separately from security-audit cleanup and broad lockfile refreshes.
- Deploy schema additions before code that depends on them. Keep the previous application artifact
  available so code can be rolled back independently; do not drop additive event tables during an
  emergency rollback.

## Maintainer Contract

Before publishing a Tideway release:

- add release-specific notes here for any downstream edit;
- run `bash scripts/check_downstream_upgrade.sh`;
- keep `tideway doctor --upgrade` aligned with the versions and feature choices in the release;
- include the downstream upgrade result in the release checklist.
