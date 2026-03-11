# Tideway DX Research - March 11, 2026

## Executive Summary

Tideway has the right ambition and a surprisingly strong amount of DX scaffolding already in place. The docs, CLI taxonomy, roadmap, and shell checks all point toward the same product goal: one opinionated path from `new` to a working API.

The main problem is that the golden path is not trustworthy enough yet.

The biggest issue is not "missing features". It is that a fresh scaffold still asks the developer to understand too much too early, and in at least one important case it fails before first success:

- a fresh default scaffold compiles with warnings
- `cargo test` in the generated app fails
- `tideway dev --fix-env` on the generated app still panics on first boot if the target Postgres database does not already exist

That means Tideway currently has a messaging system for a great developer experience, but not yet a fully reliable product path for it.

If I were prioritizing this pragmatically, I would not add new framework features or new CLI commands right now. I would spend the next chunk of work making the default path boringly reliable end-to-end.

## What Tideway Is Trying To Be

The project direction is coherent:

- The README positions Tideway as a "batteries-included Rust web framework" for building SaaS applications quickly while keeping modularity and flexibility.
- The DX execution roadmap defines the north star as the fastest path from zero to a production-shaped Rust API, without sacrificing modularity.
- The roadmap also explicitly identifies the core risk correctly: too many valid entry points and too much exposed flexibility too early.

This is a good goal.

In practice, Tideway is trying to sit in a space closer to:

- Rails for opinionated application flow
- Laravel for starter kits and scaffolding
- FastAPI for immediate local feedback and built-in OpenAPI
- Loco.rs for Rust-native app generation with batteries included

That is a reasonable product position. The opportunity is real. Rust still does not have a clear default answer for "I want to ship an API quickly without assembling everything myself."

## What Is Already Good

There is a lot here worth preserving:

- The canonical path is stated clearly in the README, docs, roadmap, and CLI help.
- The CLI already distinguishes `Primary` vs `Advanced` commands.
- There are useful DX guardrails:
  - `scripts/check_onboarding_single_path.sh`
  - `scripts/check_quickstart_parity.sh`
  - `scripts/check_docs_drift.sh`
  - `tideway-cli/tests/dx_golden_path_test.rs`
- The framework capability surface is strong: auth, jobs, OpenAPI, validation, billing, organizations, testing helpers, etc.
- The project has already started shifting from "look how much is in here" toward "what is the fastest successful path".

I ran the local DX guardrails and they all passed:

- `bash scripts/check_onboarding_single_path.sh`
- `bash scripts/check_quickstart_parity.sh`
- `bash scripts/check_docs_drift.sh`
- `cargo test -p tideway-cli --test dx_golden_path_test`

That matters because it shows the repo already has discipline around messaging consistency.

## The Real DX Problems

### 1. The default scaffold is not actually first-run safe

This is the highest-priority problem.

The default `tideway new my_app` path currently lands the user in an API preset with:

- auth
- database
- openapi
- validation
- config
- docker-compose
- CI
- a generated DB-backed `todo` resource

That is a lot of shape before the user has even seen one successful request.

More importantly, the generated starter assumes a Postgres database exists locally:

- `tideway-cli/templates/backend/starter/env_example.hbs` sets `DATABASE_URL=postgres://postgres:postgres@localhost:5432/{{project_name}}`
- `tideway-cli/templates/backend/starter/src/main.rs.hbs` connects to the database eagerly and calls `.expect("Failed to connect to database")`
- `tideway-cli/src/commands/dev.rs` only copies `.env`, sets `DATABASE_AUTO_MIGRATE=true`, and runs `cargo run`

I generated a fresh app and verified the actual first boot behavior:

- `tideway dev --fix-env` created `.env`
- the app built
- the app then panicked because database `my_app` did not exist

That means the current default path is still "production-shaped" before it is "first success shaped".

Pragmatic recommendation:

- Make `tideway new` boot without external services by default.
- If Tideway wants to keep the API preset as default, then local dev needs a no-drama database story:
  - SQLite by default for day 0, or
  - auto-create the Postgres database, or
  - actually orchestrate Docker + DB provisioning from `tideway dev`

Right now the framework is asking the user to solve infrastructure before it has earned trust.

### 2. Generated apps are out of sync with published artifacts

This is the second critical problem.

A generated app should be the most heavily validated output in the whole project. Right now it is not.

I found two concrete release-integrity issues:

- The generated app emits `#[cfg(feature = "openapi")]` guards into the app crate even though the generated `Cargo.toml` does not define local crate features.
- The generated resource tests use `.with_json(...)`, but the generated app depends on the published `tideway = "0.7.16"` crate, and `cargo test` in the scaffold fails.

Evidence in the repo:

- `tideway-cli/templates/backend/starter/src/main.rs.hbs` inserts `#[cfg(feature = "openapi")]`
- `tideway-cli/src/commands/resource.rs` generates `#[cfg(feature = "openapi")]` blocks and test code using `.with_json(...)`
- `tideway-cli/tests/new_command_test.rs` contains a compile smoke test, but it is gated behind `TIDEWAY_CLI_SMOKE`

Observed result from a real generated app:

- `cargo test` failed
- compile warnings appeared for unexpected `cfg(feature = "openapi")`
- generated resource tests did not compile

This is a release-process problem more than a template problem.

Pragmatic recommendation:

- Add a mandatory CI job that:
  - generates a fresh app from the published CLI behavior
  - uses the published Tideway crate version the scaffold references
  - runs `cargo check`
  - runs `cargo test`
  - runs `tideway dev --plan`
- Remove the `TIDEWAY_CLI_SMOKE` gate for at least one scaffold compile test in CI.
- Treat "fresh scaffold compiles and tests cleanly" as a release-blocking invariant.

If the scaffold is the product, the scaffold must be tested like the product.

### 3. `tideway dev` is positioned as a dev orchestrator, but behaves more like a thin wrapper

The docs and command naming imply a high-level command:

- load env
- help the app boot
- handle migrations
- smooth over local setup

But the current behavior is much thinner:

- ensure `.env`
- inject `DATABASE_AUTO_MIGRATE=true`
- run `cargo run`

That is useful, but it does not actually close the most painful part of the loop:

- is the database reachable?
- does the database exist?
- should Docker be started?
- should migrations be initialized or run?
- is the app bootable right now?

`doctor` also stays mostly in static-analysis territory. It checks env keys and wiring hints, but not real readiness.

Pragmatic recommendation:

- Make `tideway dev` responsible for "I can boot this app locally".
- Keep `doctor` as the reporting/preflight command.
- Upgrade `dev` to optionally:
  - verify DB reachability
  - create the database if missing
  - run migrations
  - offer a one-shot Docker startup path when the scaffold includes `docker-compose.yml`

The bar should be: if Tideway tells the user "`tideway dev --fix-env` is the primary local run command", then that command should either boot the app or tell them exactly what one action remains.

### 4. The default starter is too concept-heavy for day 0

The framework says the main story is:

1. `tideway new`
2. `tideway dev --fix-env`
3. `tideway resource ...`
4. `tideway migrate`

That is good as a story.

But the starter itself currently jumps straight into:

- auth
- JWT wiring
- DB pool wiring
- OpenAPI wiring
- generated resource CRUD
- config modules
- CI and Docker

That is probably too much for the first 10 minutes.

The best DX frameworks separate:

- day 0: boot and understand the shape
- day 1: add persistence and auth
- day 2: add production concerns

Laravel does this well with starter kits. FastAPI does it with an extremely small first file and instant docs. Loco.rs does it by asking what kind of app and DB you want, including SQLite. Rails succeeds by making the conventions feel singular and obvious.

Pragmatic recommendation:

- Split Tideway's starter experience more explicitly:
  - `new` default: zero-infra local API starter
  - `new --preset api` or `new --preset saas`: richer batteries-included starter
- Alternatively keep the current default preset, but make it use the easiest possible local backend and defer heavier infrastructure.

The user's first feeling should be "I am productive", not "I now own an architecture".

### 5. The framework API still exposes too many near-duplicate concepts early

This is the main framework-level problem, separate from CLI scaffolding.

The roadmap already calls this out, and the code confirms it:

- `App::register_module`
- `App::register_modules`
- `App::register_optional_module`
- `register_modules!`
- `register_optional_modules!`
- `module!`
- `App::layer`
- `App::with_global_layer`
- `App::into_router`
- `App::into_router_with_middleware`
- `App`
- `AppBuilder`

Most of these are defensible individually.

The DX issue is cumulative. A beginner does not experience these as "powerful options". They experience them as "I do not know which one is the real one".

Pragmatic recommendation:

- Pick one blessed composition style for onboarding and keep repeating it everywhere.
- Move all other composition patterns behind an explicit "Advanced Composition" boundary.
- Consider API naming that reduces footguns:
  - the safe default should have the simpler name
  - the advanced/raw path should have the more explicit name

Concretely, `into_router_with_middleware()` reads like the exceptional case even though the docs say it is the recommended manual-serving path. That is backwards from a DX perspective.

### 6. Some README surface still weakens trust

Two things stand out:

- The feature matrix still advertises `database-sqlx` as a placeholder.
- The quickstart messaging is strong, but it currently over-promises relative to verified first-run behavior.

Pragmatic recommendation:

- Hide placeholders from top-level marketing docs until they are real.
- Reserve top-level README claims for paths that are continuously validated end-to-end.

Trust is a DX feature.

## Comparison With Good DX Patterns

I checked current official docs from a few frameworks with strong developer experience:

- FastAPI: the first tutorial is a tiny app plus `fastapi dev`, and OpenAPI is immediately available.
- Laravel: the framework distinguishes between a fresh app and optional starter kits like Breeze, which explicitly scaffold auth when you ask for it.
- Loco.rs: the wizard asks what kind of app and DB provider you want, including SQLite, and keeps the initial choice explicit.
- Rails: the current guide still leans on a very clear singular path and an opinionated philosophy instead of exposing every variation early.

The pattern across them is consistent:

- one obvious way to start
- first success before customization
- generators that are trusted
- advanced choices introduced after the user has momentum

Tideway is already trying to do exactly this. It just has to close the gap between intent and reality.

## What I Would Do Next

### Priority 0: Restore trust in the golden path

These should be the next releases' highest-priority deliverables:

1. Make a fresh generated app boot cleanly.
2. Make `cargo test` in a fresh generated app pass.
3. Remove scaffold compile warnings from the default path.
4. Add a hard CI gate for generated-app compile/test/boot behavior.

Until these are true, everything else is downstream.

### Priority 1: Make the default starter effortless

I would choose one of these models and commit to it:

Option A:

- `tideway new` gives a zero-infra starter
- `tideway new --preset api` gives the current heavier starter

Option B:

- keep `tideway new` as API-first
- but make local dev default to SQLite or another no-drama path

Option C:

- keep Postgres as default
- but make `tideway dev` provision everything necessary to boot locally

My pragmatic preference is Option B.

Why:

- it preserves Tideway's "production-shaped API" positioning
- it still gives users DB-backed local development
- it removes Docker and local Postgres from the first-run critical path

### Priority 2: Shrink the beginner-facing framework surface

For onboarding docs and scaffolds:

- use one module style
- use one registration style
- use one serving style
- use one testing style

Everything else should live in advanced docs.

I would be especially aggressive about not showing `AppBuilder`, `register_modules!`, `register_optional_modules!`, or manual-serving variations in early docs unless absolutely needed.

### Priority 3: Tighten product packaging

I would reframe Tideway's packages as:

- Starter: fast local API
- API preset: DB + auth + OpenAPI
- SaaS preset: organizations + billing + admin
- Worker preset: jobs-oriented

That is easier to understand than exposing the full command/feature matrix too early.

## Suggested Metrics

The current roadmap metrics are good. I would add two more that directly map to developer trust:

- Fresh scaffold boot success rate on a clean machine
- Fresh scaffold `cargo test` pass rate using published artifacts

And I would elevate these metrics:

- Time to `GET /health`
- Number of required manual steps before first successful request
- Number of required local services for default `tideway new`

The simplest developer experience metric is:

"How many things had to already be true before the framework felt useful?"

Right now Tideway is still too high on that measure.

## Bottom Line

Tideway does not need a new identity.

It already knows what it wants to be:

- opinionated by default
- modular by choice
- batteries included
- fast path to a real API

What it needs now is product honesty and stronger release discipline around the happy path.

If the next phase of work is:

- fix the generated app
- make `dev` actually get people running
- reduce day-0 complexity
- hide advanced framework choices until later

then Tideway can become a genuinely strong Rust answer to "I need to build and ship an API quickly".

If instead it keeps expanding capability without making the default path trustworthy, it will feel impressive to maintainers and expensive to new users.

## Sources

Local repo references:

- `README.md`
- `ROADMAP_2026_DX_EXECUTION.md`
- `docs/getting_started.md`
- `src/core.rs`
- `src/lib.rs`
- `src/testing/scenario.rs`
- `tideway-cli/src/cli.rs`
- `tideway-cli/src/commands/dev.rs`
- `tideway-cli/src/commands/doctor.rs`
- `tideway-cli/src/commands/new.rs`
- `tideway-cli/src/commands/resource.rs`
- `tideway-cli/templates/backend/starter/Cargo.toml.hbs`
- `tideway-cli/templates/backend/starter/env_example.hbs`
- `tideway-cli/templates/backend/starter/src/main.rs.hbs`
- `tideway-cli/tests/dx_golden_path_test.rs`
- `tideway-cli/tests/new_command_test.rs`

External references:

- FastAPI first steps: https://fastapi.tiangolo.com/tutorial/first-steps/
- Laravel starter kits: https://laravel.com/docs/11.x/starter-kits
- Laravel controllers/resource controllers: https://laravel.com/docs/11.x/controllers
- Loco.rs getting started guide: https://loco.rs/docs/getting-started/guide/
- Loco.rs starters: https://loco.rs/docs/getting-started/starters/
- Rails getting started: https://guides.rubyonrails.org/getting_started.html
