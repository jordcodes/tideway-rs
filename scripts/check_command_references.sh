#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[command-refs] $1" >&2
  exit 1
}

docs=(
  "README.md"
  "NEXT_STEPS.md"
  "ROADMAP_2026_DX_EXECUTION.md"
  "docs"
)

allowed_top_level_regex='^(new|doctor|generate|backend|add|init|resource|setup|dev|migrate|templates)$'
invalid_top_level=()

while IFS= read -r line; do
  [[ -z "${line:-}" ]] && continue

  file="${line%%:*}"
  remainder="${line#*:}"
  line_no="${remainder%%:*}"
  matched="${remainder#*:}"
  cmd="${matched#tideway }"

  if [[ ! "$cmd" =~ $allowed_top_level_regex ]]; then
    invalid_top_level+=("${file}:${line_no} -> ${matched}")
  fi
done < <(rg -n -o -g '*.md' '\btideway [a-z][a-z-]*' "${docs[@]}" || true)

if [[ ${#invalid_top_level[@]} -gt 0 ]]; then
  {
    echo "[command-refs] Found invalid top-level tideway command references:"
    for ref in "${invalid_top_level[@]}"; do
      echo "  - ${ref}"
    done
  } >&2
  exit 1
fi

deprecated_forms=(
  "tideway generate backend"
)

for pattern in "${deprecated_forms[@]}"; do
  if rg -n -F -g '*.md' -- "$pattern" "${docs[@]}" >/tmp/tideway-command-refs.$$; then
    {
      echo "[command-refs] Deprecated command form detected: '${pattern}'"
      cat /tmp/tideway-command-refs.$$
    } >&2
    rm -f /tmp/tideway-command-refs.$$
    exit 1
  fi
done
rm -f /tmp/tideway-command-refs.$$ 2>/dev/null || true

echo "[command-refs] OK"
