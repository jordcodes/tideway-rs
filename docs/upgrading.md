# Upgrading Tideway Applications

Tideway upgrades should be small, reviewable changes. Update the framework and only the
dependencies or APIs required by that framework release; keep unrelated application cleanup in
separate commits.

Generated application files belong to the application after creation. The upgrade command never
regenerates or overwrites them, and an upgrade should not rerun `new`, `backend`, `add --force`, or
other broad scaffolding commands over an existing project. Apply reported changes as focused edits
that follow the application's existing structure and business rules.

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

Applications with a custom `BillingStore` must override `claim_event` with an atomic
insert-or-ignore operation. It must return `true` only for the caller that inserted the event and
`false` when the event was already claimed. Also implement `release_event_claim` so a failed handler
removes its claim and permits the provider to retry the event. `tideway doctor --upgrade` warns when
it finds a custom billing store without either required override.

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

`release_event_claim` should delete only that event's claim. Add a database-backed concurrency test
that launches two claims for the same event ID and asserts exactly one returns `true`, then verify a
released claim can be acquired again.

## Machine-readable findings

Upgrade findings emitted with `--json` contain a stable `code`, `affected_path`, `docs_url`,
`level`, and human-readable `message`. Warning codes currently include:

| Code | Meaning |
| --- | --- |
| `TW-UPGRADE-DEPENDENCY-MISSING` | No Tideway dependency was found. |
| `TW-UPGRADE-VERSION-MISMATCH` | The application and installed CLI target different Tideway versions. |
| `TW-UPGRADE-VALIDATOR-MISMATCH` | A direct Validator dependency is incompatible. |
| `TW-UPGRADE-STRIPE-TLS-CONFLICT` | Direct async-stripe TLS features conflict with Tideway. |
| `TW-UPGRADE-BILLING-CLAIM-LIFECYCLE` | A custom billing store lacks claim or release overrides. |
| `TW-UPGRADE-BILLING-SUBSCRIPTION-CAS` | A custom billing store lacks an atomic subscription compare-and-save override. |
| `TW-UPGRADE-BILLING-MIGRATION-MISSING` | The built-in billing store's event migration is absent. |
| `TW-UPGRADE-BILLING-MIGRATION-PRIMARY-KEY` | The event-ID uniqueness constraint could not be confirmed. |
| `TW-UPGRADE-JWT-ISSUER-SECRET` | The deprecated unchecked JWT issuer constructor is present. |
| `TW-UPGRADE-JWT-VERIFIER-SECRET` | The deprecated unchecked JWT verifier constructor is present. |
| `TW-UPGRADE-APP-CONTEXT-DATABASE` | Application code accesses the old database field directly. |

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
