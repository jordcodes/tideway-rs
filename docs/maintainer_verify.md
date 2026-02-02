# Maintainer Verify Guide

Use this when `scripts/verify.sh` fails.

Run:

```bash
bash scripts/verify.sh
```

## What `verify.sh` Runs

1. `python3 scripts/check_docs_drift.py`
2. `python3 scripts/check_quickstart_parity.py`
3. `bash scripts/check_cli_fs_writes.sh`
4. `python3 scripts/check_public_api_surface.py`
5. `cargo test -p tideway-cli`
6. `cargo test --test prelude_smoke_test`
7. `cargo test --test feature_gate_contract_test`

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
- ensure health-check verification line is present

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
python3 scripts/check_public_api_surface.py --update
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
4. Commit once all checks pass
