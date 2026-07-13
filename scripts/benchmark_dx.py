#!/usr/bin/env python3
"""Measure Tideway's canonical developer journeys without enforcing thresholds."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional


SCHEMA_VERSION = 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark Tideway's new-to-health and resource-to-tests golden paths. "
            "Results are observational and do not fail on latency."
        )
    )
    parser.add_argument("--samples", type=int, default=5, help="Number of fresh projects (1-20).")
    parser.add_argument(
        "--cli",
        type=Path,
        default=Path("target/release/tideway"),
        help="Path to the prebuilt tideway CLI binary.",
    )
    parser.add_argument(
        "--framework-source",
        type=Path,
        default=Path("."),
        help="Workspace root used to patch generated apps to the framework under test.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/dx-benchmarks/results.json"),
        help="JSON result path.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=600,
        help="Maximum time for each health boot or test command.",
    )
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def nearest_rank(values: list[int], percentile: float) -> int:
    if not values:
        raise ValueError("cannot calculate a percentile without samples")
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def metric(values: list[int]) -> dict[str, Any]:
    return {
        "unit": "ms",
        "samples": values,
        "p50": nearest_rank(values, 0.50),
        "p95": nearest_rank(values, 0.95),
    }


def run_self_test() -> None:
    values = [50, 10, 30, 20, 40]
    assert nearest_rank(values, 0.50) == 30
    assert nearest_rank(values, 0.95) == 50
    assert metric(values)["samples"] == values
    print("[dx-benchmark] self-test OK", flush=True)


def command_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("CARGO_TARGET_DIR", None)
    env["CARGO_INCREMENTAL"] = "0"
    env["CARGO_TERM_COLOR"] = "never"
    return env


def run_checked(
    command: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=command_env(),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out after {timeout_seconds}s: {' '.join(command)}") from error
    if result.returncode != 0:
        combined = (result.stdout + "\n" + result.stderr).strip()
        tail = "\n".join(combined.splitlines()[-80:])
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{tail}")
    return result


def toml_string(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def patch_to_workspace(project: Path, framework_source: Path) -> None:
    cargo_toml = project / "Cargo.toml"
    tideway_macros = framework_source / "tideway-macros"
    patch = (
        "\n[patch.crates-io]\n"
        f'tideway = {{ path = "{toml_string(framework_source)}" }}\n'
        f'tideway-macros = {{ path = "{toml_string(tideway_macros)}" }}\n'
    )
    cargo_toml.write_text(cargo_toml.read_text(encoding="utf-8") + patch, encoding="utf-8")


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def health_is_ready(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGINT)
        else:
            process.terminate()
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=5)


def wait_for_health(
    process: subprocess.Popen[str],
    *,
    port: int,
    timeout_seconds: int,
    log_path: Path,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if health_is_ready(port):
            return
        return_code = process.poll()
        if return_code is not None:
            log_tail = "\n".join(log_path.read_text(encoding="utf-8").splitlines()[-80:])
            raise RuntimeError(f"tideway dev exited with {return_code} before health was ready\n{log_tail}")
        time.sleep(0.1)
    log_tail = "\n".join(log_path.read_text(encoding="utf-8").splitlines()[-80:])
    raise RuntimeError(f"health endpoint was not ready after {timeout_seconds}s\n{log_tail}")


def measure_sample(
    *,
    sample: int,
    cli: Path,
    framework_source: Path,
    timeout_seconds: int,
) -> tuple[int, int]:
    with tempfile.TemporaryDirectory(prefix=f"tideway-dx-{sample:02d}-") as temp:
        root = Path(temp)
        project = root / f"dx_sample_{sample:02d}"
        log_path = root / "tideway-dev.log"

        print(f"[dx-benchmark] sample {sample}: measuring new -> health", flush=True)
        health_started = time.monotonic_ns()
        run_checked(
            [
                str(cli),
                "new",
                project.name,
                "--preset",
                "api",
                "--no-prompt",
                "--path",
                str(project),
            ],
            timeout_seconds=timeout_seconds,
        )
        patch_to_workspace(project, framework_source)
        port = reserve_port()
        dev_env = command_env()
        dev_env["TIDEWAY_PORT"] = str(port)
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(cli), "dev", "--fix-env", "--path", str(project)],
                cwd=project,
                env=dev_env,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=(os.name == "posix"),
            )
            try:
                wait_for_health(
                    process,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    log_path=log_path,
                )
                health_ms = round((time.monotonic_ns() - health_started) / 1_000_000)
            finally:
                stop_process(process)

        print(
            f"[dx-benchmark] sample {sample}: health ready in {health_ms / 1000:.2f}s; "
            "measuring resource -> tests",
            flush=True,
        )
        resource_started = time.monotonic_ns()
        run_checked(
            [
                str(cli),
                "resource",
                "widget",
                "--path",
                str(project),
            ],
            timeout_seconds=timeout_seconds,
        )
        run_checked(["cargo", "test"], cwd=project, timeout_seconds=timeout_seconds)
        resource_ms = round((time.monotonic_ns() - resource_started) / 1_000_000)
        print(
            f"[dx-benchmark] sample {sample}: resource tests passed in {resource_ms / 1000:.2f}s",
            flush=True,
        )
        return health_ms, resource_ms


def rust_version() -> str:
    result = subprocess.run(
        ["rustc", "--version"], check=False, capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def git_sha(framework_source: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=framework_source,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def render_summary(results: dict[str, Any]) -> str:
    health = results["metrics"]["new_to_health_ms"]
    resource = results["metrics"]["resource_to_tests_ms"]
    return "\n".join(
        [
            "## Tideway DX golden-path benchmark",
            "",
            "| Journey | p50 | p95 | Samples |",
            "| --- | ---: | ---: | ---: |",
            f'| `new` → `/health` | {health["p50"] / 1000:.2f}s | {health["p95"] / 1000:.2f}s | {len(health["samples"])} |',
            f'| `resource` → tests | {resource["p50"] / 1000:.2f}s | {resource["p95"] / 1000:.2f}s | {len(resource["samples"])} |',
            "",
            "Observational only: no latency threshold is enforced.",
        ]
    )


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if not 1 <= args.samples <= 20:
        raise SystemExit("--samples must be between 1 and 20")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")

    cli = args.cli.resolve()
    framework_source = args.framework_source.resolve()
    output = args.output.resolve()
    if not cli.is_file():
        raise SystemExit(f"tideway CLI not found: {cli}; build it before benchmarking")
    if not (framework_source / "Cargo.toml").is_file():
        raise SystemExit(f"framework source is not a Tideway workspace: {framework_source}")
    if shutil.which("cargo") is None:
        raise SystemExit("cargo is required")

    health_samples: list[int] = []
    resource_samples: list[int] = []
    for sample in range(1, args.samples + 1):
        health_ms, resource_ms = measure_sample(
            sample=sample,
            cli=cli,
            framework_source=framework_source,
            timeout_seconds=args.timeout_seconds,
        )
        health_samples.append(health_ms)
        resource_samples.append(resource_ms)

    results: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "git_sha": git_sha(framework_source),
        "environment": {
            "os": platform.system(),
            "architecture": platform.machine(),
            "rust": rust_version(),
            "samples": args.samples,
            "cache_model": (
                "fresh project and target directory per sample; shared Cargo registry/git cache; "
                "resource journey follows health boot in the same project"
            ),
        },
        "metrics": {
            "new_to_health_ms": metric(health_samples),
            "resource_to_tests_ms": metric(resource_samples),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    summary = render_summary(results)
    print("\n" + summary, flush=True)
    print(f"[dx-benchmark] wrote {output}", flush=True)
    if github_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(github_summary).open("a", encoding="utf-8") as summary_file:
            summary_file.write(summary + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("[dx-benchmark] interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as error:
        print(f"[dx-benchmark] error: {error}", file=sys.stderr)
        raise SystemExit(1)
