#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[downstream-upgrade] compile migrated application contract"
cargo check --locked -p tideway-downstream-upgrade-contract
echo "[downstream-upgrade] OK"
