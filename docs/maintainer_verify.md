# Maintainer Verify Guide

Use this when `scripts/verify.sh` fails.

Run:

```bash
bash scripts/verify.sh
```

## What `verify.sh` Runs

1. `bash scripts/check_docs_drift.sh`
2. `bash scripts/check_quickstart_parity.sh`
3. `bash scripts/check_command_taxonomy.sh`
4. `bash scripts/check_command_references.sh`
5. `bash scripts/check_onboarding_single_path.sh`
6. `bash scripts/check_release_template_dx_metrics.sh`
7. `bash scripts/check_dx_metrics_snapshot.sh`
8. `bash scripts/check_issue_template_dx_ambiguity.sh`
9. `bash scripts/check_cli_fs_writes.sh`
10. `bash scripts/check_public_api_surface.sh`
11. `cargo test -p tideway-cli --test messaging_contract_test`
12. `cargo test -p tideway-cli`
13. `cargo test --lib`
14. `cargo check --features billing`
15. `cargo check --all-features`
16. `cargo test --test prelude_smoke_test`
17. `cargo test --test feature_gate_contract_test`

## Common Failures and Fixes

### Docs Drift Failure

Symptoms:
- stale phrase warnings
- README version/snippet mismatch
- missing docs link

Fix:
- update `README.md`, `NEXT_STEPS.md`, or linked docs files to match current state
- ensure docs links point to existing files

---

### Quickstart Parity Failure

Symptoms:
- CLI fast-start snippet in `README.md` drifted
- missing required Agent Quickstart lines

Fix:
- restore/update `README.md` quickstart commands to the expected canonical flow
- keep the default quickstart aligned with `tideway new my_app -> tideway dev --fix-env`
- mention the SQLite local-dev default when the quickstart path changes
- ensure health-check verification line is present

---

### Command Taxonomy Failure

Symptoms:
- `docs/cli.md` is missing required Primary/Advanced grouping markers
- `tideway-cli/src/cli.rs` is missing expected "Advanced: ..." help text for advanced commands

Fix:
- keep `docs/cli.md` aligned with the required command taxonomy headings and labels
- keep clap help comments in `tideway-cli/src/cli.rs` aligned with taxonomy rules

---

### Command References Failure

Symptoms:
- docs contain stale or invalid command forms (for example, legacy backend-generation wording)
- docs reference unknown top-level `tideway` subcommands

Fix:
- replace stale command forms with current command names from `docs/cli.md`
- keep command examples in `README.md`, `NEXT_STEPS.md`, and `docs/**/*.md` aligned with the current CLI
- re-run:

```bash
bash scripts/check_command_references.sh
```

---

### Onboarding Single Path Failure

Symptoms:
- onboarding docs show competing starts in one section
- advanced commands appear in onboarding docs without explicit advanced labeling

Fix:
- keep onboarding docs focused on one recommended start per task
- in `README.md` and `docs/getting_started.md`, avoid alternative "Or ..." starts in first-run sections
- mark any `tideway init` / `tideway backend` / `tideway add` usage as advanced when referenced in onboarding docs
- if command-surface positioning changed, update `docs/deprecation_policy.md` and `.github/RELEASE_TEMPLATE.md`

---

### Command Surface / Deprecation Policy Drift

Symptoms:
- a PR adds or relabels a command path without saying whether it is primary, advanced, legacy, or deprecated
- overlapping command paths changed, but release notes or migration guidance were not updated

Fix:
- apply `docs/deprecation_policy.md`
- update `docs/cli.md`, `README.md`, and `docs/getting_started.md` if the user-facing recommendation changed
- update `.github/RELEASE_TEMPLATE.md` so the release owner records rationale and migration notes

---

### Release Template DX Metrics Failure

Symptoms:
- missing `.github/RELEASE_TEMPLATE.md`
- release template does not include the required DX gate checklist or metrics snapshot lines

Fix:
- restore/update `.github/RELEASE_TEMPLATE.md` with:
  - DX gate status checklist: quickstart parity, docs drift, scaffold idempotency, golden path integration tests
  - metrics snapshot fields from `ROADMAP_2026_DX_EXECUTION.md`
- re-run:

```bash
bash scripts/check_release_template_dx_metrics.sh
```

---

### DX Metrics Snapshot Failure

Symptoms:
- missing `docs/dx_metrics_snapshot.md`
- DX metrics snapshot is missing required gate or reporting fields

Fix:
- restore/update `docs/dx_metrics_snapshot.md`
- keep the gate summary and metrics fields aligned with `.github/RELEASE_TEMPLATE.md`
- if release scope materially changed onboarding or scaffold performance, refresh the snapshot before release
- re-run:

```bash
bash scripts/check_dx_metrics_snapshot.sh
```

---

### DX Issue Template Failure

Symptoms:
- missing `.github/ISSUE_TEMPLATE/dx_ambiguity_report.yml`
- DX ambiguity template missing required prompts for conflicting commands and expected guidance

Fix:
- restore/update `.github/ISSUE_TEMPLATE/dx_ambiguity_report.yml` with required DX ambiguity fields
- re-run:

```bash
bash scripts/check_issue_template_dx_ambiguity.sh
```

---

### CLI Filesystem Policy Failure

Symptoms:
- direct `std::fs::write/remove/create_dir_all` usage in `tideway-cli/src/commands`

Fix:
- use CLI helpers from `tideway-cli/src/lib.rs`:
  - `ensure_dir`
  - `write_file`
  - `remove_file`
  - `remove_dir`

---

### Public API Surface Drift

Symptoms:
- diff between current `src/lib.rs` exports and `ci/public-api-surface.txt`

Fix:
- if accidental, revert unintended export/mod changes
- if intentional, update baseline:

```bash
bash scripts/check_public_api_surface.sh --update
```

---

### CLI Test Failures (`cargo test -p tideway-cli`)

Symptoms:
- failing command tests, snapshot tests, wiring/idempotency tests

Fix:
- inspect failing test output first
- for intentional scaffold output changes:
  - update relevant files under `tideway-cli/tests/snapshots/`
- re-run targeted test, then full CLI suite

---

### Feature Build Failures (`cargo check --features billing` / `cargo check --all-features`)

Symptoms:
- optional modules compile in default builds, but fail when billing or full feature set is enabled
- missing fields, moved values, or unused-feature drift in feature-gated code

Fix:
- run the exact failing check locally and fix the referenced file/line
- make sure tests/builds for the affected feature compile with:
  - `cargo check --features billing`
  - `cargo check --all-features`
- if a public request type changed, update all test initializers and mock call sites

---

### Prelude or Feature-Gate Contract Failures

Symptoms:
- `prelude_smoke_test` fails after export changes
- `feature_gate_contract_test` missing compile guidance messages

Fix:
- keep `src/prelude.rs` aligned with intended stable imports
- keep feature-gate messages in `src/lib.rs` actionable and explicit
- update test expectations only when contract changes are intentional

## Maintainer Workflow

1. Run `bash scripts/verify.sh`
2. Fix first failing check
3. Re-run `bash scripts/verify.sh`
4. If command surface changed, apply `docs/deprecation_policy.md` and update release notes/templates
5. Commit once all checks pass
