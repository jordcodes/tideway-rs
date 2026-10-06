#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Scaffold compile tests must run in CI. An opt-in env var gate makes them silently pass instead.
PATTERN='TIDEWAY_CLI_SMOKE'

if rg -n "$PATTERN" tideway-cli -S; then
  echo "[scaffold-test-guard] Env-gated scaffold smoke tests found in tideway-cli." >&2
  echo "[scaffold-test-guard] Remove the gate and build against workspace source (patch_scaffold_to_workspace)." >&2
  exit 1
fi

echo "[scaffold-test-guard] OK"
