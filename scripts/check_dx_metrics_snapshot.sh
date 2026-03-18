#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[dx-metrics-snapshot] $1" >&2
  exit 1
}

snapshot="docs/dx_metrics_snapshot.md"

if [[ ! -f "$snapshot" ]]; then
  fail "Missing ${snapshot}. Add the current DX metrics snapshot."
fi

required_lines=(
  "# DX Metrics Snapshot"
  "Updated:"
  "## DX Gate Status"
  "- quickstart parity:"
  "- docs drift:"
  "- scaffold idempotency:"
  "- golden path integration tests:"
  "## Metrics Snapshot"
  "- Time to \`GET /health\` from clean machine (p50/p95):"
  "- Time to scaffold DB resource and run tests (p50/p95):"
  "- Idempotency pass rate for mutating CLI commands:"
  "- Number of onboarding docs that show non-canonical flows:"
  "- Number of user-reported \"which command should I use\" issues:"
  "## Release Notes Guidance"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$snapshot"; then
    fail "${snapshot} is missing required line: ${line}"
  fi
done

echo "[dx-metrics-snapshot] OK"
