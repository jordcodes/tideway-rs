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

echo "[verify] cli filesystem policy"
bash scripts/check_cli_fs_writes.sh

echo "[verify] public api surface"
bash scripts/check_public_api_surface.sh

echo "[verify] messaging contract"
cargo test -p tideway-cli --test messaging_contract_test

echo "[verify] tideway-cli tests"
cargo test -p tideway-cli

echo "[verify] module contract tests"
cargo test --test prelude_smoke_test
cargo test --test feature_gate_contract_test

echo "[verify] OK"
