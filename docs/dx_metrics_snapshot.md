# DX Metrics Snapshot

Updated: 2026-07-13
Scope: `main` at `76149a6` before the automated benchmark workflow was added

## DX Gate Status

- quickstart parity: passing (`bash scripts/check_quickstart_parity.sh`)
- docs drift: passing (`bash scripts/check_docs_drift.sh`)
- scaffold idempotency: passing (`cargo test -p tideway-cli --test plan_mode_mutating_commands_test` and `cargo test -p tideway-cli --test resource_command_test`)
- golden path integration tests: passing (`cargo test -p tideway-cli --test dx_golden_path_test`)

## Metrics Snapshot

- Time to `GET /health` from clean machine (p50/p95): 28.84s / 29.70s (5-sample local baseline; fresh project and target directory, shared Cargo registry/git cache).
- Time to scaffold DB resource and run tests (p50/p95): 5.82s / 5.99s (5-sample local baseline; resource journey follows the health boot in the same project).
- Idempotency pass rate for mutating CLI commands: 100% while the scaffold idempotency gate is passing.
- Number of onboarding docs that show non-canonical flows: 0 while `bash scripts/check_onboarding_single_path.sh` is passing.
- Number of user-reported "which command should I use" issues: manual issue-tracker query required at release time.

## Benchmark Methodology

Run the same harness used by the scheduled `Benchmarks` workflow:

```bash
cargo build --release --locked -p tideway-cli
python3 scripts/benchmark_dx.py \
  --samples 5 \
  --cli target/release/tideway \
  --framework-source . \
  --output target/dx-benchmarks/results.json
```

Each sample uses a fresh generated API and fresh Cargo target directory. The Cargo registry and git cache are shared, matching a developer who has Rust dependencies cached but is starting a new project. Building the Tideway CLI itself is excluded.

- `new` → `/health` includes scaffolding, compilation, local environment repair, migrations, server startup, and the first successful health response.
- `resource` → tests begins in that same booted project and includes the canonical DB-backed resource command plus `cargo test`.
- p50/p95 use the nearest-rank method. Five samples make p95 the slowest observed sample, so the result is a trend baseline rather than a service-level guarantee.
- Scheduled and manually dispatched workflows upload the raw JSON as the `tideway-dx-benchmark` artifact and write the summary to the GitHub Actions job summary.
- No latency threshold is enforced until enough scheduled Linux runs exist to establish a stable baseline.

## Release Notes Guidance

- Copy a short DX gate summary into the release notes / changelog entry for each release.
- Link the latest `tideway-dx-benchmark` artifact when onboarding or scaffold performance changed materially.
- If command surface changed, include the roadmap issue or rationale and the migration notes from the release template.
