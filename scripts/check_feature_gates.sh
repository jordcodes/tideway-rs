#!/usr/bin/env bash
set -euo pipefail

# Each feature set builds a separate variant of tideway and its dependencies, so keep these
# checks in their own target dir to avoid evicting the main build's cached artifacts.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET_DIR="target/feature-gates"
failures=0

check_features() {
  cargo check -p tideway --no-default-features --features "$1" --target-dir "$TARGET_DIR" 2>&1
}

echo "[feature-gates] feature-gate-errors"
if output="$(check_features feature-gate-errors)"; then
  echo "expected check with feature-gate-errors to fail:"
  echo "$output"
  failures=1
else
  for expected in \
    'Enable the `auth` feature to use tideway::auth' \
    'Enable the `billing` feature to use tideway::billing' \
    'Enable the `organizations` feature to use tideway::organizations' \
    'Enable the `admin` feature to use tideway::admin' \
    'Enable the `cache` feature to use tideway::cache' \
    'Enable the `database` feature to use tideway::database' \
    'Enable the `metrics` feature to use tideway::metrics' \
    'Enable the `openapi` feature to use tideway::openapi' \
    'Enable the `sessions` feature to use tideway::session' \
    'Enable the `jobs` feature to use tideway::jobs' \
    'Enable the `email` feature to use tideway::email' \
    'Enable the `storage` feature to use tideway::storage' \
    'Enable the `validation` feature to use tideway::validation' \
    'Enable the `websocket` feature to use tideway::websocket'; do
    if ! grep -qF -- "$expected" <<<"$output"; then
      echo "missing expected compile guidance: $expected"
      failures=1
    fi
  done
  if [[ $failures -ne 0 ]]; then
    echo "$output"
  fi
fi

echo "[feature-gates] feature-gate-warnings"
if ! output="$(check_features feature-gate-warnings)"; then
  echo "expected check with feature-gate-warnings to succeed:"
  echo "$output"
  failures=1
fi

for feature in admin auth billing database-sqlx jobs openapi organizations websocket; do
  echo "[feature-gates] isolated feature: $feature"
  if ! output="$(check_features "$feature")"; then
    echo "expected isolated feature build to succeed for $feature:"
    echo "$output"
    failures=1
  elif grep -qF -- 'unused import: `error::TidewayError`' <<<"$output"; then
    echo "isolated feature build leaked the core warning for $feature:"
    echo "$output"
    failures=1
  fi
done

if [[ $failures -ne 0 ]]; then
  echo "[feature-gates] FAILED"
  exit 1
fi

echo "[feature-gates] OK"
