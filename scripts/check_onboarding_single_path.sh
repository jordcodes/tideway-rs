#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[onboarding-path] $1" >&2
  exit 1
}

# Onboarding docs should avoid presenting advanced commands as default flow.
onboarding_docs=(
  "README.md"
  "docs/getting_started.md"
)

advanced_cmds=(
  "tideway init"
  "tideway backend"
  "tideway add "
)

for doc in "${onboarding_docs[@]}"; do
  for cmd in "${advanced_cmds[@]}"; do
    while IFS=: read -r line_no line; do
      [[ -z "${line_no:-}" ]] && continue
      lower="$(echo "$line" | tr '[:upper:]' '[:lower:]')"
      if [[ "$lower" != *"advanced"* ]]; then
        fail "${doc}:${line_no} uses '${cmd}' without marking it as advanced."
      fi
    done < <(grep -nF "$cmd" "$doc" || true)
  done
done

if ! grep -Fq 'Canonical onboarding path:' README.md; then
  fail "README.md must include 'Canonical onboarding path:'."
fi

echo "[onboarding-path] OK"
