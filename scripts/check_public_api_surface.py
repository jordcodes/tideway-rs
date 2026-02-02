#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB_RS = ROOT / "src/lib.rs"
BASELINE = ROOT / "ci/public-api-surface.txt"


def normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def extract_public_api(lib_rs_text: str) -> list[str]:
    snapshot: list[str] = []
    macro_export = False

    for raw_line in lib_rs_text.splitlines():
        line = normalize(raw_line)
        if not line:
            continue

        if line == "#[macro_export]":
            macro_export = True
            continue

        if line.startswith("pub mod ") and line.endswith(";"):
            snapshot.append(line)
            macro_export = False
            continue

        if line.startswith("pub use ") and line.endswith(";"):
            snapshot.append(line)
            macro_export = False
            continue

        if macro_export:
            macro_match = re.match(r"macro_rules!\s+([a-zA-Z_][a-zA-Z0-9_]*)", line)
            if macro_match:
                snapshot.append(f"pub macro {macro_match.group(1)}")
            macro_export = False

    return snapshot


def load_snapshot() -> list[str]:
    lib_rs_text = LIB_RS.read_text(encoding="utf-8")
    return extract_public_api(lib_rs_text)


def write_baseline(lines: list[str]) -> None:
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(lines) + "\n"
    BASELINE.write_text(payload, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect accidental public API surface drift.")
    parser.add_argument(
        "--update",
        action="store_true",
        help="Overwrite ci/public-api-surface.txt with the current snapshot.",
    )
    args = parser.parse_args()

    current = load_snapshot()

    if args.update:
        write_baseline(current)
        print("[public-api] baseline updated")
        return

    if not BASELINE.exists():
        print(
            "[public-api] Missing baseline at ci/public-api-surface.txt. "
            "Run scripts/check_public_api_surface.py --update.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    expected = [
        line
        for line in BASELINE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if current != expected:
        diff = "\n".join(
            difflib.unified_diff(
                expected,
                current,
                fromfile="ci/public-api-surface.txt",
                tofile="src/lib.rs snapshot",
                lineterm="",
            )
        )
        print("[public-api] Public API surface drift detected.", file=sys.stderr)
        print(diff, file=sys.stderr)
        print(
            "[public-api] If this change is intentional, update the baseline with: "
            "scripts/check_public_api_surface.py --update",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print("[public-api] OK")


if __name__ == "__main__":
    main()
