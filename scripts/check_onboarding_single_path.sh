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

count_bash_blocks_in_section() {
  local file="$1"
  local start_marker="$2"
  local end_regex="$3"

  awk -v start_marker="$start_marker" -v end_re="$end_regex" '
    BEGIN {
      in_section = 0
      saw_section = 0
      count = 0
    }
    $0 == start_marker {
      in_section = 1
      saw_section = 1
      next
    }
    in_section && $0 ~ end_re {
      in_section = 0
    }
    in_section && $0 ~ /^```bash$/ {
      count++
    }
    END {
      if (!saw_section) {
        print "MISSING"
      } else {
        print count
      }
    }
  ' "$file"
}

section_contains_pattern() {
  local file="$1"
  local start_marker="$2"
  local end_regex="$3"
  local pattern="$4"

  awk -v start_marker="$start_marker" -v end_re="$end_regex" -v pattern="$pattern" '
    BEGIN {
      in_section = 0
      found = 0
    }
    $0 == start_marker {
      in_section = 1
      next
    }
    in_section && $0 ~ end_re {
      in_section = 0
    }
    in_section && $0 ~ pattern {
      found = 1
    }
    END {
      if (found) {
        exit 0
      }
      exit 1
    }
  ' "$file"
}

readme_faststart_blocks="$(count_bash_blocks_in_section \
  "README.md" \
  '### CLI (Fastest Start)' \
  '^### '
)"
if [[ "$readme_faststart_blocks" == "MISSING" ]]; then
  fail "README.md is missing the '### CLI (Fastest Start)' section."
fi
if [[ "$readme_faststart_blocks" -ne 1 ]]; then
  fail "README.md CLI (Fastest Start) must contain exactly one bash code block, found ${readme_faststart_blocks}."
fi

if section_contains_pattern "README.md" '### CLI (Fastest Start)' '^### ' '^Or '; then
  fail "README.md CLI (Fastest Start) must not include alternative 'Or ...' starts."
fi

getting_started_create_blocks="$(count_bash_blocks_in_section \
  "docs/getting_started.md" \
  '## 1) Create a new app' \
  '^## '
)"
if [[ "$getting_started_create_blocks" == "MISSING" ]]; then
  fail "docs/getting_started.md is missing the '## 1) Create a new app' section."
fi
if [[ "$getting_started_create_blocks" -ne 1 ]]; then
  fail "docs/getting_started.md section '1) Create a new app' must contain exactly one bash code block, found ${getting_started_create_blocks}."
fi

if section_contains_pattern "docs/getting_started.md" '## 1) Create a new app' '^## ' '^Or '; then
  fail "docs/getting_started.md section '1) Create a new app' must not include alternative 'Or ...' starts."
fi

if ! section_contains_pattern "docs/getting_started.md" '## 1) Create a new app' '^## ' 'tideway new my_app'; then
  fail "docs/getting_started.md section '1) Create a new app' must include 'tideway new my_app'."
fi

if ! section_contains_pattern "docs/getting_started.md" '## 1) Create a new app' '^## ' 'tideway dev --fix-env'; then
  fail "docs/getting_started.md section '1) Create a new app' must include 'tideway dev --fix-env'."
fi

echo "[onboarding-path] OK"
