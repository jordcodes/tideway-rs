#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_RS="$ROOT/src/lib.rs"
BASELINE="$ROOT/ci/public-api-surface.txt"

generate_snapshot() {
  awk '
    function trim(s) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
      return s
    }
    {
      line=$0
      gsub(/[[:space:]]+/, " ", line)
      line=trim(line)
      if (line == "") next

      if (line == "#[macro_export]") {
        macro_export=1
        next
      }

      if (line ~ /^pub mod .+;$/) {
        print line
        macro_export=0
        next
      }

      if (line ~ /^pub use .+;$/) {
        print line
        macro_export=0
        next
      }

      if (macro_export) {
        if (line ~ /^macro_rules![[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
          macro_name = line
          sub(/^macro_rules![[:space:]]+/, "", macro_name)
          sub(/[^A-Za-z0-9_].*$/, "", macro_name)
          print "pub macro " macro_name
        }
        macro_export=0
      }
    }
  ' "$LIB_RS"
}

if [[ "${1:-}" == "--update" ]]; then
  mkdir -p "$(dirname "$BASELINE")"
  generate_snapshot > "$BASELINE"
  echo "[public-api] baseline updated"
  exit 0
fi

if [[ ! -f "$BASELINE" ]]; then
  echo "[public-api] Missing baseline at ci/public-api-surface.txt. Run scripts/check_public_api_surface.sh --update." >&2
  exit 1
fi

tmp_current="$(mktemp)"
tmp_expected="$(mktemp)"
trap 'rm -f "$tmp_current" "$tmp_expected"' EXIT

generate_snapshot > "$tmp_current"
grep -vE '^[[:space:]]*$|^[[:space:]]*#' "$BASELINE" > "$tmp_expected"

if ! diff -u "$tmp_expected" "$tmp_current" >/tmp/public-api.diff.$$; then
  echo "[public-api] Public API surface drift detected." >&2
  cat /tmp/public-api.diff.$$ >&2
  rm -f /tmp/public-api.diff.$$
  echo "[public-api] If this change is intentional, update the baseline with: scripts/check_public_api_surface.sh --update" >&2
  exit 1
fi
rm -f /tmp/public-api.diff.$$

echo "[public-api] OK"
