#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[dx-issue-template] $1" >&2
  exit 1
}

template=".github/ISSUE_TEMPLATE/dx_ambiguity_report.yml"

if [[ ! -f "$template" ]]; then
  fail "Missing ${template}. Add the DX ambiguity issue template."
fi

required_lines=(
  "name: DX Ambiguity Report"
  "description: Report confusing command or docs paths so Tideway can keep one clear default flow."
  "title: \"[DX Ambiguity]: \""
  "- dx"
  "- triage"
  "label: What were you trying to do?"
  "label: Where did ambiguity happen?"
  "label: Which commands or paths looked equally valid?"
  "label: Which path did you choose and what happened?"
  "label: What guidance did you expect?"
  "label: Minimal reproduction steps"
  "label: tideway-cli version"
  "label: Rust version"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$template"; then
    fail "${template} is missing required field: ${line}"
  fi
done

echo "[dx-issue-template] OK"
