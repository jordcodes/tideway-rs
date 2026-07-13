# Tideway DX Execution Roadmap (2026)

## Why This Exists
Tideway already has strong capability coverage, but DX cost is growing because there are too many valid entry points for the same outcome. This roadmap narrows the default path and treats everything else as advanced or legacy.

## Product North Star
Fastest path from zero to a production-shaped Rust API, without sacrificing modularity.

## Current Friction (Critical)
1. Multiple scaffold pathways overlap (`new`, `backend`, `init`, `add`, `resource`), creating decision fatigue and inconsistent outcomes.
2. Docs present multiple competing starts (`cargo run`, `tideway dev`, manual wiring, macro wiring) before users learn the canonical path.
3. The module composition surface is powerful but over-exposed early (`register_module`, `register_modules`, `register_optional_modules`, plus macros).
4. Some command outputs still push manual dependency wiring, which conflicts with the batteries-included promise.
5. Success metrics exist, but day-to-day ownership and release gates are not yet tied to those metrics.

## Strategy
- Define one default path for 80% of users.
- Keep advanced paths, but mark them as advanced/legacy and remove them from first-run docs.
- Shift from feature-complete messaging to "time-to-working-API" messaging.
- Tie every release to measurable DX gates.

## Canonical Path (Single Story)
1. `tideway new <app>` (wizard/preset)
2. `tideway dev --fix-env`
3. `tideway resource <name>` (the default API profile wires the full stack)
4. `tideway migrate` (or auto via dev)

Everything else should be either:
- Advanced: existing project migration, nonstandard architecture
- Legacy: retained for compatibility, not promoted

## 90-Day Plan

### Phase A (Weeks 1-3): Command Surface Rationalization
Goal: remove ambiguity in command intent.

Deliverables:
- Publish command taxonomy in docs and CLI help:
  - Primary: `new`, `dev`, `resource`, `doctor`, `migrate`
  - Advanced: `add`, `backend`, `init`, `generate`, `setup`, `templates`
- Add clear help text that points back to the canonical path.
- Mark overlapping commands as advanced in help/docs (without breaking them).

Acceptance criteria:
- New user can choose a path from help text in under 30 seconds.
- CLI docs no longer present competing first steps.

### Phase B (Weeks 4-6): First-Run and Scaffold Consistency
Goal: same inputs produce same mental model and structure.

Deliverables:
- Ensure `new` presets and `backend` outputs align on naming and generated structure.
- Remove/manual-wire guidance from happy-path outputs where scaffolding can do it automatically.
- Add compatibility warnings when users combine commands in conflicting ways.

Acceptance criteria:
- Running `new --preset saas` does not require a separate conceptual model from backend scaffolding.
- No happy-path output asks users to manually edit dependency lists for common flows.

### Phase C (Weeks 7-9): API Composition Simplification
Goal: reduce "many ways" in core API docs.

Deliverables:
- Publicly designate one preferred composition pattern for getting-started examples.
- Move alternative composition patterns into an "Advanced Composition" section.
- Keep full contract surface stable but de-emphasize alternatives in onboarding docs.

Acceptance criteria:
- Getting-started uses one route-module style and one registration style.
- Advanced alternatives are discoverable but not interleaved with onboarding.

### Phase D (Weeks 10-12): DX Gatekeeping and Release Policy
Goal: protect the simplified experience from regression.

Deliverables:
- Add release checklist with hard DX gates:
  - quickstart parity
  - docs drift
  - scaffold idempotency
  - golden path integration tests
- Add one benchmark-style metric job for scaffold latency and resource generation latency.
- Require roadmap issue linkage for any new CLI command/flag that expands surface area.

Acceptance criteria:
- Every release reports DX gate status in changelog.
- No new command surface lands without rationale and migration notes.

## What To Deprioritize (For Now)
- New top-level commands unless they remove complexity.
- New optional APIs in onboarding docs.
- Broad feature expansion without scaffold and docs parity.

## Metrics Dashboard (Weekly)
- Time to `GET /health` from clean machine (p50/p95)
- Time to scaffold DB resource and run tests (p50/p95)
- Idempotency pass rate for mutating CLI commands
- Number of onboarding docs that show non-canonical flows
- Number of user-reported "which command should I use" issues

## Ownership Model
- CLI Owner: command surface, wizard decisions, command help quality
- Framework Owner: module/API contract stability and deprecation policy
- Docs Owner: canonical path integrity and drift prevention
- Release Owner: DX gates in CI and changelog reporting

## Immediate Backlog (Next 10 PRs)
1. Add "Primary vs Advanced" grouping to CLI docs and `--help` descriptions.
2. Update getting-started to a single path (`new` -> `dev --fix-env` -> `resource ...`).
3. Move alternative module registration patterns out of onboarding.
4. Add warning text in `backend` and `init` docs indicating advanced/legacy positioning.
5. Align `new` and `backend` naming language for B2B/B2C/SaaS.
6. Add integration test for mixed-command flow conflicts.
7. Add a docs rule: onboarding docs may show only one recommended path per task.
8. Add release template section for DX metrics.
9. Add an issue template for DX ambiguity reports.
10. Publish deprecation policy for low-usage overlapping command paths.

## Definition of Better
- New users stop asking "which path should I pick?"
- Maintainers stop fixing the same drift class in three places.
- Tideway feels opinionated by default, extensible by choice.
