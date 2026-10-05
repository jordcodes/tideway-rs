#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[verify] docs drift"
bash scripts/check_docs_drift.sh

echo "[verify] quickstart parity"
bash scripts/check_quickstart_parity.sh

echo "[verify] command taxonomy"
bash scripts/check_command_taxonomy.sh

echo "[verify] command references"
bash scripts/check_command_references.sh

echo "[verify] onboarding single path"
bash scripts/check_onboarding_single_path.sh

echo "[verify] release template dx metrics"
bash scripts/check_release_template_dx_metrics.sh

echo "[verify] dx metrics snapshot"
bash scripts/check_dx_metrics_snapshot.sh

echo "[verify] dx issue template"
bash scripts/check_issue_template_dx_ambiguity.sh

echo "[verify] cli filesystem policy"
bash scripts/check_cli_fs_writes.sh

echo "[verify] public api surface"
bash scripts/check_public_api_surface.sh

echo "[verify] messaging contract"
cargo test -p tideway-cli --test messaging_contract_test

echo "[verify] tideway-cli tests"
cargo test -p tideway-cli

# Run the full suite with default features (covers feature-disabled code paths) and with every
# feature enabled (covers feature-gated modules and test files).
echo "[verify] tideway tests (default features)"
cargo test -p tideway

echo "[verify] tideway tests (all features)"
cargo test -p tideway --all-features

echo "[verify] tideway-macros tests"
cargo test -p tideway-macros

echo "[verify] tideway testing surfaces"
cargo test --example testing_example

echo "[verify] billing feature compile check"
cargo check --features billing

echo "[verify] all-features compile check"
cargo check --all-features

echo "[verify] downstream upgrade contract"
bash scripts/check_downstream_upgrade.sh

echo "[verify] OK"
