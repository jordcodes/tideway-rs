# Tideway 2026 DX-First Roadmap

## Product Goal
Build the fastest path to shipping Rust APIs with a batteries-included framework that stays modular as apps grow.

## Guiding Principle
Optimize for developer flow first: time-to-first-working-endpoint, reliable scaffolding, safe re-runs, and clear module boundaries.

## Success Metrics
- New API from scaffold to first successful `GET /health`: <= 60 seconds.
- New DB resource (`--wire --db --repo --service --paginate --search`) scaffold + run: <= 5 minutes.
- CLI command re-run safety (idempotency) for all wiring commands: 100%.
- P0/P1 scaffold regressions in CI on main: 0.

## Phase DX-1: 60-Second Golden Path
### Outcome
New users can scaffold, run, and verify a working API with near-zero friction.

### Acceptance Criteria
- `tideway new <app>` plus `tideway dev --fix-env` succeeds on clean machine baseline.
- `tideway doctor` identifies and auto-fixes top setup issues with actionable output.
- Getting-started docs match current CLI output and templates exactly.

### Scope
- Harden `new`, `dev`, `doctor` first-run path.
- Add explicit smoke tests for generated app boot path.
- Improve failure messages for missing env/tooling.

## Phase DX-2: Scaffold Reliability + Idempotency
### Outcome
Generated code is consistently usable and safe to re-run.

### Acceptance Criteria
- `add` and `resource` wiring paths are idempotent across marker and legacy formats.
- `--plan` mode parity for all mutating commands.
- Generated resource includes tests + pagination/search + docs wiring by default when requested.

### Scope
- Extend idempotency matrix tests for all add/resource subcommands.
- Enforce CLI file-write helper usage in commands.
- Add snapshot coverage for scaffold outputs.

## Phase DX-3: Modular API Contracts
### Outcome
Batteries stay optional, with clear runtime module contracts.

### Acceptance Criteria
- Public module contract is documented and tested (`register_module`, optional modules, prelude).
- Feature-gated modules fail with clear compile-time guidance.
- App context patterns are stable and documented for extension points.

### Scope
- Formalize module contract docs + compile-fail checks.
- Keep public API surface guard current and intentional.
- Add examples that compose optional modules cleanly.

## Phase DX-4: Fast Feedback Loop
### Outcome
Developers get fast, precise signal when they break scaffolds or contracts.

### Acceptance Criteria
- CI includes docs drift, API surface, scaffold guardrails, and targeted CLI tests.
- Local verify path is one command with clear pass/fail output.
- Common regressions caught before merge.

### Scope
- Keep guardrails minimal but high-value.
- Introduce focused contract tests for generated app boot, resource wiring, and module registration.
- Publish maintainer troubleshooting playbook.

## Phase DX-5: Batteries-Included Showcase
### Outcome
A polished reference path demonstrates end-to-end Tideway value.

### Acceptance Criteria
- Starter presets are opinionated and production-oriented (`api`, `saas`, `worker`).
- Reference app demonstrates auth + database + docs + jobs + email integration.
- Docs support copy/paste onboarding and incremental adoption.

### Scope
- Ship curated presets and reference app.
- Add deployment docs for Docker + one cloud target.
- Add release checklist tied to DX metrics.

---

## DX-1 Initial Execution Plan (First 2 Weeks)

### Slice 1: Golden path contract tests
- Add integration tests that run scaffold -> dev/doctor happy path in temp dirs.
- Add assertions for expected generated files and startup output markers.
- Add failure-mode tests for missing env and fix flow.

### Slice 2: Doctor first-run hardening
- Expand `doctor --fix` coverage for missing `.env.example` and common config gaps.
- Standardize warning/error wording and machine-readable `--json` output.
- Add regression tests for each auto-fix path.

### Slice 3: Getting-started doc parity
- Update README quickstart and command examples to exact CLI behavior.
- Add docs parity check script for quickstart snippets.
- Add CI gate for quickstart drift.

### Exit Criteria for DX-1
- New contributor can run quickstart from clean clone with no manual debugging.
- All DX-1 tests/guardrails pass in CI.
- No open P1 issues tagged `dx-golden-path`.
