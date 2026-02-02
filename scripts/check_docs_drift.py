#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"[docs-drift] {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    cargo_toml = ROOT / "Cargo.toml"
    readme = ROOT / "README.md"
    next_steps = ROOT / "NEXT_STEPS.md"

    cargo_text = cargo_toml.read_text(encoding="utf-8")
    version_match = re.search(
        r"(?ms)^\[package\]\s.*?^version\s*=\s*\"([^\"]+)\"",
        cargo_text,
    )
    if not version_match:
        fail("Unable to parse [package].version from Cargo.toml")
    version = version_match.group(1)
    expected_dep = f'tideway = "{version}"'

    readme_text = readme.read_text(encoding="utf-8")
    next_steps_text = next_steps.read_text(encoding="utf-8")

    if expected_dep not in readme_text:
        fail(
            f"README.md dependency snippet must include `{expected_dep}` "
            f"(synced with Cargo.toml package.version)."
        )

    forbidden = [
        ("README.md", "Docs TBD", readme_text),
        ("README.md", "SQLx (Coming Soon)", readme_text),
        ("README.md", "SQLx (coming soon)", readme_text),
        ("NEXT_STEPS.md", "CLI tool for scaffolding projects", next_steps_text),
    ]
    for file_name, phrase, haystack in forbidden:
        if phrase in haystack:
            fail(f"{file_name} still contains stale phrase: {phrase!r}")

    docs_links = sorted(set(re.findall(r"docs/[a-zA-Z0-9_./-]+\\.md", readme_text)))
    missing = [link for link in docs_links if not (ROOT / link).exists()]
    if missing:
        fail("README.md contains missing docs links: " + ", ".join(missing))

    print("[docs-drift] OK")


if __name__ == "__main__":
    main()
