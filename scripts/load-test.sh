#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOAD_DIR="$ROOT_DIR/load-tests"
APP_MANIFEST="$LOAD_DIR/app/Cargo.toml"
RESULTS_DIR="${RESULTS_DIR:-$LOAD_DIR/results/$(date -u +%Y%m%dT%H%M%SZ)}"
BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
DURATION="${DURATION:-30s}"
CONCURRENCY="${CONCURRENCY:-50}"
WS_CLIENTS="${WS_CLIENTS:-1000}"
APP_LOG="$RESULTS_DIR/app.log"
APP_PID=""

mkdir -p "$RESULTS_DIR"

cleanup() {
  if [[ -n "$APP_PID" ]]; then
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
  fi
  docker compose -f "$LOAD_DIR/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! command -v oha >/dev/null 2>&1; then
  echo "oha 1.14 is required; install it with: cargo install oha --version 1.14.0 --locked" >&2
  exit 1
fi

docker compose -f "$LOAD_DIR/docker-compose.yml" up -d --wait postgres

DATABASE_URL="postgres://tideway:tideway@127.0.0.1:55432/tideway_load" \
JWT_SECRET="0123456789abcdef0123456789abcdef" \
  cargo run --release --manifest-path "$APP_MANIFEST" --bin tideway-load-app >"$APP_LOG" 2>&1 &
APP_PID=$!

for _ in $(seq 1 120); do
  if curl --fail --silent "$BASE_URL/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "load app exited before becoming healthy" >&2
    tail -100 "$APP_LOG" >&2
    exit 1
  fi
  sleep 1
done
curl --fail --silent "$BASE_URL/health" >/dev/null

TOKEN="$(curl --fail --silent "$BASE_URL/load/token" | sed -E 's/.*"access_token":"([^"]+)".*/\1/')"

run_http() {
  local name="$1"
  shift
  NO_COLOR=true oha -z "$DURATION" -c "$CONCURRENCY" --output-format json "$@" \
    >"$RESULTS_DIR/$name.json"
}

run_http health "$BASE_URL/health"
run_http authenticated -H "Authorization: Bearer $TOKEN" "$BASE_URL/load/authenticated"
run_http rate_limited "$BASE_URL/load/rate-limited"
run_http database "$BASE_URL/api/items?limit=20&offset=200&q=item"

WS_URL="ws://127.0.0.1:18080/load/ws" \
HTTP_URL="$BASE_URL/load/broadcast" \
  cargo run --release --manifest-path "$APP_MANIFEST" --bin ws_load -- "$WS_CLIENTS" \
  >"$RESULTS_DIR/websocket.json"

echo "Load-test results written to $RESULTS_DIR"
