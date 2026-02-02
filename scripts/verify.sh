#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[verify] docs drift"
python3 scripts/check_docs_drift.py

echo "[verify] quickstart parity"
python3 scripts/check_quickstart_parity.py

echo "[verify] cli filesystem policy"
bash scripts/check_cli_fs_writes.sh

echo "[verify] public api surface"
python3 scripts/check_public_api_surface.py

echo "[verify] tideway-cli tests"
cargo test -p tideway-cli

echo "[verify] module contract tests"
cargo test --test prelude_smoke_test
cargo test --test feature_gate_contract_test

echo "[verify] OK"
