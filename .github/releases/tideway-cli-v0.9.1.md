# Tideway CLI 0.9.1

## Release

- Version: 0.9.1 (`tideway-cli`). Generated applications use Tideway 0.9.0.
- Date: 2026-10-24
- Release owner: Jord

## Summary

Tideway CLI 0.9.1 fixes problems reported by a team upgrading an existing app from 0.7 with
`tideway add credits`. No framework release is needed.

Install with `cargo install tideway-cli --version 0.9.1 --locked`.

## Fixed

- `tideway add` keeps the trailing newline in `.env.example` and no longer rewrites it when no
  keys are added.
- `tideway add` registers migrations in `migration/src/lib.rs` at the right indentation, keeps the
  closing `]` in place, and handles a last entry without a trailing comma.
- The generated credit revocation and billing customer repair migrations run on SQLite even when
  `sea-orm-migration` is built without `sqlx-sqlite`.
- `tideway doctor` no longer warns about `STRIPE_PRICE_ID` in apps that do not read it.

Generated code belongs to your application. Apps that already ran `tideway add credits` keep the
migrations they generated; if they run migrations on SQLite, enable `sqlx-sqlite` on
`sea-orm-migration` or copy the `has_column` helper from the new templates.

## DX Metrics

### DX Gate Status

- [x] quickstart parity (`bash scripts/check_quickstart_parity.sh`)
- [x] docs drift (`bash scripts/check_docs_drift.sh`)
- [x] scaffold idempotency (`cargo test -p tideway-cli --test plan_mode_mutating_commands_test` and `cargo test -p tideway-cli --test resource_command_test`)
- [x] golden path integration tests (`cargo test -p tideway-cli --test dx_golden_path_test`)
- [x] downstream upgrade contract (`bash scripts/check_downstream_upgrade.sh`)

Also passing: `scripts/verify.sh`, and the credits migration tests against SQLite and PostgreSQL
17. The changed migration templates were also run on SQLite and PostgreSQL from a crate whose
`sea-orm-migration` enables only `sqlx-postgres`.

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

- Breaking changes: none.
- Deprecated or legacy paths touched: none.
- Upgrade steps: install the CLI. Existing apps need no changes.
- `docs/upgrading.md` updated for downstream changes: no.
- Policy reference: `docs/deprecation_policy.md`

## Links

- Changelog entry: `CHANGELOG.md` `[tideway-cli 0.9.1] - 2026-10-24`
- Framework release: `tideway-v0.9.0`
- Previous release: `tideway-cli-v0.9.0`
