#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[release-template] $1" >&2
  exit 1
}

template=".github/RELEASE_TEMPLATE.md"

if [[ ! -f "$template" ]]; then
  fail "Missing ${template}. Add a release template with DX metrics."
fi

required_lines=(
  "## DX Metrics"
  "### DX Gate Status"
  "- [ ] quickstart parity"
  "- [ ] docs drift"
  "- [ ] scaffold idempotency"
  "- [ ] golden path integration tests"
  "### Metrics Snapshot"
  "- Metrics snapshot file: \`docs/dx_metrics_snapshot.md\`"
  "- Latest \`tideway-dx-benchmark\` workflow run/artifact:"
  "- Time to \`GET /health\` from clean machine (p50/p95):"
  "- Time to scaffold DB resource and run tests (p50/p95):"
  "- Idempotency pass rate for mutating CLI commands:"
  "- Number of onboarding docs that show non-canonical flows:"
  "- Number of user-reported \"which command should I use\" issues:"
  "- DX gate summary copied into changelog entry:"
  "- Command surface rationale / roadmap issue:"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$template"; then
    fail "${template} is missing required DX metrics line: ${line}"
  fi
done

echo "[release-template] OK"
