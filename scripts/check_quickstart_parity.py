#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def fail(message: str) -> None:
    print(f"[quickstart-parity] {message}", file=sys.stderr)
    raise SystemExit(1)


def extract_first_bash_block_after(heading: str, text: str) -> str:
    heading_index = text.find(heading)
    if heading_index == -1:
        fail(f"Missing heading: {heading!r}")
    tail = text[heading_index:]
    match = re.search(r"```bash\n(.*?)\n```", tail, flags=re.DOTALL)
    if not match:
        fail(f"Missing bash code block after heading: {heading!r}")
    return match.group(1).strip()


def main() -> None:
    readme = README.read_text(encoding="utf-8")

    expected_cli_fast_start = "\n".join(
        [
            "cargo install tideway-cli",
            "tideway new my_app",
            "cd my_app",
            "tideway doctor --fix",
            "tideway dev --fix-env",
        ]
    )

    actual_fast_start = extract_first_bash_block_after("### CLI (Fastest Start)", readme)
    if actual_fast_start != expected_cli_fast_start:
        fail(
            "CLI fast-start snippet drifted.\n"
            "Expected:\n"
            f"{expected_cli_fast_start}\n\n"
            "Found:\n"
            f"{actual_fast_start}"
        )

    required_agent_lines = [
        "tideway resource <name> --wire --db --repo --service --paginate --search",
        "tideway dev --fix-env",
    ]
    for line in required_agent_lines:
        if line not in readme:
            fail(f"README Agent Quickstart is missing required line: {line!r}")

    if "Then visit `http://localhost:8000/health`." not in readme:
        fail("README quickstart must include the health endpoint verification line.")

    print("[quickstart-parity] OK")


if __name__ == "__main__":
    main()
