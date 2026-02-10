#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[command-taxonomy] $1" >&2
  exit 1
}

if ! grep -Fq "## Command Groups" docs/cli.md; then
  fail "docs/cli.md must include '## Command Groups'."
fi

required_primary=(
  '- `new`'
  '- `dev`'
  '- `resource`'
  '- `doctor`'
  '- `migrate`'
)
for line in "${required_primary[@]}"; do
  if ! grep -Fq -- "$line" docs/cli.md; then
    fail "docs/cli.md is missing primary command: $line"
  fi
done

required_advanced_docs=(
  '### `tideway init` (advanced)'
  '### `tideway add` (advanced)'
  '### `tideway backend` (advanced)'
  '### `tideway generate` (advanced)'
  '### `tideway setup` (advanced)'
)
for line in "${required_advanced_docs[@]}"; do
  if ! grep -Fq -- "$line" docs/cli.md; then
    fail "docs/cli.md is missing advanced label: $line"
  fi
done

required_advanced_help=(
  "/// Advanced: generate frontend components (not for backend API scaffolding)"
  "/// Advanced: generate backend scaffolding for existing/nonstandard projects (not for greenfield)"
  "/// Advanced: add features/scaffolding to an existing project (not the default new-app path)"
  "/// Advanced: initialize main.rs by scanning modules in existing projects (not for greenfield)"
  "/// Advanced: set up frontend dependencies (not required for API-only workflows)"
)
for line in "${required_advanced_help[@]}"; do
  if ! grep -Fq -- "$line" tideway-cli/src/cli.rs; then
    fail "tideway-cli/src/cli.rs is missing advanced help text: $line"
  fi
done

echo "[command-taxonomy] OK"
