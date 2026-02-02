#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[docs-drift] $1" >&2
  exit 1
}

version="$(awk '
  /^\[package\]$/ { in_package=1; next }
  /^\[/ { if (in_package) exit }
  in_package && $1=="version" {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' Cargo.toml)"

if [[ -z "${version:-}" ]]; then
  fail "Unable to parse [package].version from Cargo.toml"
fi

expected_dep="tideway = \"${version}\""
if ! grep -Fq "$expected_dep" README.md; then
  fail "README.md dependency snippet must include \`${expected_dep}\` (synced with Cargo.toml package.version)."
fi

forbidden_readme=(
  "Docs TBD"
  "SQLx (Coming Soon)"
  "SQLx (coming soon)"
)
for phrase in "${forbidden_readme[@]}"; do
  if grep -Fq "$phrase" README.md; then
    fail "README.md still contains stale phrase: '${phrase}'"
  fi
done

if grep -Fq "CLI tool for scaffolding projects" NEXT_STEPS.md; then
  fail "NEXT_STEPS.md still contains stale phrase: 'CLI tool for scaffolding projects'"
fi

while IFS= read -r link; do
  [[ -z "$link" ]] && continue
  if [[ ! -f "$link" ]]; then
    fail "README.md contains missing docs link: ${link}"
  fi
done < <(grep -oE 'docs/[A-Za-z0-9_./-]+\.md' README.md | sort -u)

echo "[docs-drift] OK"
