# Tideway Release Notes Template

## Release

- Version:
- Date:
- Release owner:

## Summary

Briefly describe the release scope and user impact.

## Highlights

- Notable change 1
- Notable change 2
- Notable change 3

## DX Metrics

### DX Gate Status

- [ ] quickstart parity (`bash scripts/check_quickstart_parity.sh`)
- [ ] docs drift (`bash scripts/check_docs_drift.sh`)
- [ ] scaffold idempotency (`cargo test -p tideway-cli --test plan_mode_mutating_commands_test` and `cargo test -p tideway-cli --test resource_command_test`)
- [ ] golden path integration tests (`cargo test -p tideway-cli --test dx_golden_path_test`)
- [ ] downstream upgrade contract (`bash scripts/check_downstream_upgrade.sh`)

### Metrics Snapshot

- Metrics snapshot file: `docs/dx_metrics_snapshot.md`
- Latest `tideway-dx-benchmark` workflow run/artifact:
- Time to `GET /health` from clean machine (p50/p95):
- Time to scaffold DB resource and run tests (p50/p95):
- Idempotency pass rate for mutating CLI commands:
- Number of onboarding docs that show non-canonical flows:
- Number of user-reported "which command should I use" issues:
- DX gate summary copied into changelog entry:

## Migration Notes

- Breaking changes:
- Deprecated or legacy paths touched:
- Command surface rationale / roadmap issue:
- Upgrade steps:
- `docs/upgrading.md` updated for downstream changes:
- Policy reference: `docs/deprecation_policy.md`

## Links

- Changelog entry:
- Roadmap issue:
- Related issues:
- Related PRs:
