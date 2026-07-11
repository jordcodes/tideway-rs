---
name: tideway-apps
description: Build, scaffold, update, and extend downstream Rust APIs that use the published Tideway framework and tideway-cli. Use when a user wants to create a Tideway app, add auth, database-backed resources, organizations, billing, search, pagination, migrations, or update an existing Tideway API to a newer framework or CLI version.
---

# Tideway Apps

## Purpose
Help agents build and maintain downstream APIs that use Tideway, not the Tideway framework repo itself. Prefer the published `tideway-cli` and generated app conventions over hand-writing boilerplate.

## First Checks
- Confirm whether the current workspace is:
  - a downstream Tideway app, or
  - the Tideway framework repo.
- If it is a downstream app, inspect:
  - `Cargo.toml`
  - `.env.example` / `.env`
  - `src/main.rs`
  - migrations directory, if present
- If exact current versions matter, verify them from crates.io or from the Tideway repo manifests. Do not assume version numbers are current.

## New API Golden Path
- Install or update the CLI when needed:
  - `cargo install tideway-cli`
- Create the app with the wizard or preset:
  - `tideway new my_api`
- Prefer generated modules and resources:
  - `tideway resource <name> --wire --db --repo --service --paginate --search`
- Run the app:
  - `tideway dev --fix-env`
- Run migrations when DB-backed features are enabled:
  - `tideway migrate`
- For plan-only or review work, use `--plan` before mutating.
- For agent-readable output, prefer `--json` when supported.

## Common App Recipes
- Basic CRUD API:
  - Generate a DB-backed resource with `--wire --db --repo --service`.
  - Add `--paginate --search` for list endpoints unless the user explicitly wants minimal routes.
- Auth-backed API:
  - Use the CLI auth scaffold where available instead of custom token plumbing.
  - Protected access-token paths should call `verify_access_token(token).await`.
  - Raw `verify(token).await` is only appropriate for generic/custom claims flows that perform their own purpose validation.
- SaaS or B2B API:
  - Prefer organization-aware generated scaffolds and resource profiles.
  - Use `organization_member` / `organization_members` naming for generated B2B backends.
- Billing:
  - Prefer generated billing routes and migrations.
  - Production webhook stores should atomically claim events before side effects and release claims on retryable processing errors.

## Updating Existing Tideway Apps
- Update the framework dependency in the app `Cargo.toml`, then run:
  - `cargo update -p tideway`
  - app test suite
- Update the CLI used for future scaffolding:
  - `cargo install tideway-cli --version <latest>`
- For auth-backed apps, search for old access verification calls:
  - `rg "verify\\(token\\)|JwtVerifier<AccessTokenClaims"`
- Replace protected-route access checks with:
  - `verify_access_token(token).await`
- For billing apps, check custom `BillingStore` implementations for `claim_event` and `release_event_claim`.

## Editing Existing Apps
- Preserve generated file paths and module names unless the user explicitly wants a migration.
- Follow Tideway’s route -> repository -> service shape for DB-backed resources.
- Use migrations for schema changes; do not silently require manual DB edits.
- Keep app-specific business logic in services or handlers, not generated framework internals.
- When changing generated-style code, mirror the local app’s existing conventions rather than inventing a new structure.

## Validation
- For app changes, run the narrowest useful tests first, then the app’s normal test suite.
- For generated-resource or scaffold changes, verify the generated app still compiles:
  - `cargo check`
  - `cargo test`
- For auth changes, include a regression that refresh tokens cannot authenticate protected access routes.
- For billing webhook changes, include a regression for duplicate event handling or claim release on failure.

## When To Use The Maintainer Skill Instead
Use the `tideway` maintainer skill when editing the Tideway framework repo, CLI internals, templates, release process, or repository tests. Use this skill when building or updating an application that consumes Tideway.
