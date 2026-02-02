#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PATTERN='std::fs::(write|remove_file|remove_dir|create_dir_all)\(|\bfs::(write|remove_file|remove_dir|create_dir_all)\('

if rg -n "$PATTERN" tideway-cli/src/commands -S; then
  echo "[cli-fs-guard] Direct filesystem write/remove calls found in tideway-cli/src/commands." >&2
  echo "[cli-fs-guard] Use CLI helpers (write_file/ensure_dir/remove_file/remove_dir)." >&2
  exit 1
fi

echo "[cli-fs-guard] OK"
