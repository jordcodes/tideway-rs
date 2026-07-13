#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "[quickstart-parity] $1" >&2
  exit 1
}

actual_fast_start="$(awk '
  BEGIN { in_section=0; in_block=0 }
  /^### CLI \(Fastest Start\)/ { in_section=1; next }
  in_section && /^```bash$/ { in_block=1; next }
  in_block && /^```$/ { exit }
  in_block { print }
' README.md)"

if [[ -z "${actual_fast_start:-}" ]]; then
  fail "Missing bash code block after heading: '### CLI (Fastest Start)'"
fi

read -r -d '' expected_fast_start <<'EOF' || true
cargo install tideway-cli
tideway new my_app
cd my_app
tideway dev --fix-env
EOF

if [[ "$actual_fast_start" != "$expected_fast_start" ]]; then
  fail "CLI fast-start snippet drifted."
fi

required_lines=(
  "tideway resource <name>"
  "tideway dev --fix-env"
)
for line in "${required_lines[@]}"; do
  if ! grep -Fq "$line" README.md; then
    fail "README Agent Quickstart is missing required line: '${line}'"
  fi
done

if grep -Fq "tideway resource <name> --wire" README.md; then
  fail "README primary guidance must keep resource shape flags behind the advanced path."
fi

if ! grep -Fq 'Then visit `http://localhost:8000/health`.' README.md; then
  fail "README quickstart must include the health endpoint verification line."
fi

if ! grep -Fq 'The default API-first scaffold uses SQLite for local development.' README.md; then
  fail "README quickstart must mention the default local SQLite path."
fi

echo "[quickstart-parity] OK"
