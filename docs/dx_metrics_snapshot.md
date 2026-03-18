# DX Metrics Snapshot

Updated: 2026-03-18
Scope: current `main` before the next release cut

## DX Gate Status

- quickstart parity: passing (`bash scripts/check_quickstart_parity.sh`)
- docs drift: passing (`bash scripts/check_docs_drift.sh`)
- scaffold idempotency: passing (`cargo test -p tideway-cli --test plan_mode_mutating_commands_test` and `cargo test -p tideway-cli --test resource_command_test`)
- golden path integration tests: passing (`cargo test -p tideway-cli --test dx_golden_path_test`)

## Metrics Snapshot

- Time to `GET /health` from clean machine (p50/p95): benchmark capture pending; record before release if the onboarding/runtime path changed materially.
- Time to scaffold DB resource and run tests (p50/p95): benchmark capture pending; record before release if scaffold/resource generation changed materially.
- Idempotency pass rate for mutating CLI commands: 100% while the scaffold idempotency gate is passing.
- Number of onboarding docs that show non-canonical flows: 0 while `bash scripts/check_onboarding_single_path.sh` is passing.
- Number of user-reported "which command should I use" issues: manual issue-tracker query required at release time.

## Release Notes Guidance

- Copy a short DX gate summary into the release notes / changelog entry for each release.
- If command surface changed, include the roadmap issue or rationale and the migration notes from the release template.
