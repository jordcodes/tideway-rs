# Tideway DX Implementation Plan - March 11, 2026

## Objective

Make Tideway's canonical path trustworthy:

1. `tideway new <app>`
2. `tideway dev --fix-env`
3. first successful request
4. `tideway resource <name>`

The concrete product target is:

- fresh scaffold compiles cleanly
- fresh scaffold tests pass
- fresh scaffold boots locally without manual debugging
- advanced framework choices stay available, but no longer block day-0 success

## Product Decisions

### Decision 1: keep `new` as the primary entry point

Do not add another top-level command.

### Decision 2: keep the richer API preset, but make local DB setup frictionless

Recommended direction:

- Use SQLite as the local-development default for the API preset.
- Keep Postgres as the production-shaped path exposed through:
  - `--with-docker`
  - explicit DB backend selection
  - SaaS/backend presets

Reason:

- it preserves Tideway's "real API" positioning
- it removes Docker and local Postgres from the first-run critical path
- it lets `tideway dev --fix-env` actually deliver on its promise

### Decision 3: release quality is defined by generated-app behavior

No release should go out unless a fresh generated app:

- `cargo check`s
- `cargo test`s
- survives the first `tideway dev --fix-env` boot path

## Scope

### In scope

- starter template fixes
- resource template fixes
- `new`, `dev`, and `doctor` behavior
- fresh-scaffold CI gates
- onboarding docs and help text
- beginner-facing API surface reduction in docs

### Out of scope

- new top-level commands
- new framework modules
- major expansion of frontend generators
- SQLx backend implementation

## Workstreams

## Workstream A - Golden Path Integrity

Priority: P0

Goal:

- generated apps must compile, test, and boot cleanly

Target files:

- `tideway-cli/templates/backend/starter/Cargo.toml.hbs`
- `tideway-cli/templates/backend/starter/src/main.rs.hbs`
- `tideway-cli/templates/backend/starter/env_example.hbs`
- `tideway-cli/src/commands/resource.rs`
- `tideway-cli/tests/new_command_test.rs`
- `tideway-cli/tests/dx_golden_path_test.rs`
- new generated-app smoke test / CI script

Tasks:

1. Remove scaffold/runtime drift with the published Tideway crate.
2. Eliminate unexpected `cfg(feature = "openapi")` warnings in generated apps.
3. Fix generated test code so it compiles against the published Tideway testing API.
4. Add a release-blocking generated-app smoke path:
   - scaffold fresh app
   - `cargo check`
   - `cargo test`
   - `tideway dev --plan`

Acceptance criteria:

- fresh scaffold builds with zero warnings on the default path
- fresh scaffold `cargo test` passes
- no test relies on `TIDEWAY_CLI_SMOKE` for at least one default scaffold compile check

## Workstream B - First-Run Boot Reliability

Priority: P0

Goal:

- `tideway dev --fix-env` gets a new developer to a running app

Target files:

- `tideway-cli/src/commands/dev.rs`
- `tideway-cli/src/commands/doctor.rs`
- `tideway-cli/src/commands/new.rs`
- starter templates
- docs quickstart files

Tasks:

1. Introduce a frictionless local DB default for the API preset.
2. Teach `dev` to validate actual boot prerequisites, not just env files.
3. If DB setup still blocks boot, return one decisive actionable fix instead of a panic.
4. Keep `doctor` as a preflight/report command, not the main path.

Recommended implementation order:

1. switch API preset local DB config to SQLite
2. make `dev` detect DB backend and set the correct local behavior
3. keep Postgres examples behind `--with-docker` and explicit backend selection

Acceptance criteria:

- `tideway new my_app`
- `cd my_app`
- `tideway dev --fix-env`

Results in:

- a booted server
- reachable `/health`
- no Docker requirement on the default path

## Workstream C - Starter Simplification

Priority: P1

Goal:

- reduce day-0 concept load without losing Tideway's opinionated value

Target files:

- `tideway-cli/src/cli.rs`
- `tideway-cli/src/commands/new.rs`
- starter templates
- `README.md`
- `docs/getting_started.md`
- `docs/cli.md`

Tasks:

1. Reframe presets around user intent:
   - default local API starter
   - explicit API preset
   - SaaS preset
   - worker preset
2. Ensure the default starter does not front-load unnecessary concerns.
3. Keep `resource <name>` as the first explicit persistence step users take; reserve shape flags for intentional customization.

Acceptance criteria:

- default scaffold fits on a small mental model:
  - app
  - routes
  - config
  - optional docs
- auth/database/billing complexity is introduced intentionally, not by surprise

## Workstream D - Dev Command Ownership

Priority: P1

Goal:

- `dev` becomes the real local-development command, not just a wrapper around `cargo run`

Target files:

- `tideway-cli/src/commands/dev.rs`
- `tideway-cli/src/commands/doctor.rs`
- `docs/error_recovery.md`
- `docs/cli.md`

Tasks:

1. Add backend-aware readiness checks before launching:
   - env exists
   - DB file/URL is sane
   - database is reachable or creatable
2. Improve failure messages to say exactly what remains.
3. Add `--json` diagnostics so agents and tooling can react to failures.

Acceptance criteria:

- if `dev` cannot boot, the output names the single next fix
- there is no panic-driven first-run failure on the default path

## Workstream E - Beginner API Surface Reduction

Priority: P2

Goal:

- one blessed framework composition path in onboarding

Target files:

- `README.md`
- `docs/getting_started.md`
- `docs/advanced_composition.md`
- `docs/module_contracts.md`
- `src/core.rs`
- `src/lib.rs`

Tasks:

1. Standardize onboarding on:
   - `module!`
   - `register_module`
   - `serve()`
2. Move all alternatives to advanced docs.
3. Evaluate API naming cleanups for the next release train:
   - safe default gets the simple name
   - advanced/raw path gets the explicit name

Acceptance criteria:

- onboarding docs show one composition style per task
- no beginner docs require choosing between near-duplicate APIs

## PR Sequence

## PR 1 - Generated App Must Compile

Outcome:

- close the scaffold drift immediately

Changes:

- fix generated OpenAPI gating
- fix generated resource test code
- ungate one scaffold compile test in CI

Files:

- `tideway-cli/templates/backend/starter/src/main.rs.hbs`
- `tideway-cli/src/commands/resource.rs`
- `tideway-cli/tests/new_command_test.rs`

Exit criteria:

- fresh scaffold `cargo check`
- fresh scaffold `cargo test`

## PR 2 - Add Release-Blocking Scaffold Smoke Gate

Outcome:

- generated-app behavior becomes a release contract

Changes:

- add CI script/test for scaffold -> build -> test -> dev-plan
- wire into maintainer/release verification

Files:

- new script under `scripts/`
- `scripts/verify.sh`
- `docs/maintainer_verify.md`
- release workflow or CI config

Exit criteria:

- main branch cannot regress generated-app integrity silently

## PR 3 - Switch Default Local API Preset To Frictionless DB

Outcome:

- default scaffold no longer depends on external Postgres

Changes:

- change starter env/database template defaults
- update generated `Cargo.toml` DB features as needed
- update migration/dev flow for local backend

Files:

- `tideway-cli/templates/backend/starter/Cargo.toml.hbs`
- `tideway-cli/templates/backend/starter/env_example.hbs`
- `tideway-cli/templates/backend/starter/src/main.rs.hbs`
- `tideway-cli/src/commands/new.rs`

Exit criteria:

- `tideway new my_app && cd my_app && tideway dev --fix-env` boots locally

## PR 4 - Upgrade `dev` To Own Boot Readiness

Outcome:

- first-run failures become guided fixes instead of runtime surprises

Changes:

- DB readiness checks
- better error output
- `--json` structured diagnostics

Files:

- `tideway-cli/src/commands/dev.rs`
- `tideway-cli/src/commands/doctor.rs`
- tests for missing DB / unbootable app path

Exit criteria:

- `dev` either boots or gives one clear next step

## PR 5 - Simplify Starter Story In Docs And CLI Help

Outcome:

- the product story matches the working product

Changes:

- update README quickstart
- update getting started
- update CLI docs/help text to reflect the new local-first behavior

Files:

- `README.md`
- `docs/getting_started.md`
- `docs/cli.md`
- `tideway-cli/src/cli.rs`
- existing docs parity scripts as needed

Exit criteria:

- quickstart docs are both minimal and true

## PR 6 - Move Alternative Framework Paths Fully Behind Advanced Docs

Outcome:

- framework power remains, but beginner confusion drops

Changes:

- tighten onboarding examples
- move alternative registration/serving patterns into advanced docs
- document the blessed default composition path clearly

Files:

- `README.md`
- `docs/getting_started.md`
- `docs/advanced_composition.md`
- `docs/module_contracts.md`

Exit criteria:

- new users no longer need to choose between multiple equivalent framework APIs on day 0

## Test Matrix To Add

These are the concrete tests missing today:

1. Fresh scaffold compile test against published artifact behavior
2. Fresh scaffold `cargo test`
3. Fresh scaffold first boot success test
4. Fresh scaffold no-warning test on default path
5. Default `dev` failure contract test:
   - if boot fails, error message is explicit and actionable
6. API preset local DB backend test
7. README quickstart smoke test that follows the exact documented commands

## Metrics

Track these weekly:

- time to `GET /health` from clean machine
- fresh scaffold build success rate
- fresh scaffold test success rate
- fresh scaffold first-boot success rate
- number of manual steps before first successful request
- number of required local services on the default path

Target thresholds:

- `GET /health` from clean scaffold: <= 90 seconds on baseline machine
- fresh scaffold build/test/boot success on main: 100%
- required external services on default path: 0

## Risks

### Risk 1: SQLite local default creates Postgres drift

Mitigation:

- keep Postgres in explicit presets and CI coverage
- add backend-aware tests for both local default and production-shaped preset

### Risk 2: fixing generated-app drift exposes more unpublished release mismatches

Mitigation:

- make scaffold smoke gates mandatory before release

### Risk 3: docs lag the product again during transition

Mitigation:

- update docs in the same PRs as behavior changes
- extend parity scripts only after behavior is correct

## Non-Negotiable Exit State

The plan is done when a new developer can do this on a clean machine:

```bash
cargo install tideway-cli
tideway new my_app
cd my_app
tideway dev --fix-env
```

And the result is:

- the app boots
- `/health` responds
- the scaffold has no surprising compile/test failures
- the docs and CLI output say exactly what the product actually does
