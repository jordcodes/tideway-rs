---
name: tideway
description: Agent guidance for the Tideway framework and CLI scaffolding.
---

# Tideway Skill

## Purpose
Help agents work effectively in the Tideway repo and use the CLI scaffolds correctly.

## Current Direction (DX-First)
- Product goal: batteries-included, modular Rust APIs with fastest path to shipping.
- Source of truth roadmap: `ROADMAP_2026_DX_EXECUTION.md`.
- Prioritize work in this order:
  1. Golden-path speed (`new` -> `dev` -> first endpoint)
  2. Scaffold reliability and idempotency
  3. Clear module/API contracts with feature-gate clarity
  4. Fast feedback loops via tests and CI guardrails

## Golden Path
- Create a new app with the wizard:
  - `tideway new my_app`
- Add a DB-backed resource:
  - `tideway resource <name>`
- Run:
  - `tideway dev --fix-env`
  - `tideway migrate`

## Updating Existing Tideway Apps
- Check the current published versions in the repo manifests before advising exact versions:
  - Framework crate: `Cargo.toml`
  - CLI crate and scaffold framework pin: `tideway-cli/Cargo.toml`
- Update app dependencies to the latest released framework version. Example only:
  - `tideway = "0.7.21"`
  - Then run `cargo update -p tideway` and the app test suite.
- Update the CLI when scaffolding or refreshing generated code. Example only:
  - `cargo install tideway-cli --version 0.1.34`
- For apps using auth, search for protected-route JWT access checks:
  - `rg "verify\\(token\\)|JwtVerifier<AccessTokenClaims"`
- Access-token authentication paths should call:
  - `verify_access_token(token).await`
- Keep raw `verify(token).await` only for generic/custom claims flows where the caller performs its own purpose validation.
- For apps using billing webhooks, update to a version with `BillingStore::claim_event` / `release_event_claim` and prefer atomic insert-or-ignore implementations in production stores.

## Release Workflow
- Before a release, confirm the intended versions and update all relevant version sources:
  - Root `Cargo.toml` package version for `tideway`
  - `tideway-cli/Cargo.toml` package version
  - `tideway-cli/Cargo.toml` `package.metadata.tideway_version`
  - Exact-version docs and CLI scaffold snapshots when they intentionally drift
  - `Cargo.lock` package entries, usually via `cargo check` or tests
- Run release verification before publishing:
  - `cargo test -p tideway --features auth,billing,test-billing,billing-seaorm --lib`
  - `cargo test -p tideway-cli`
  - `cargo test`
- For Cargo publishing, dry-run both crates first:
  - `cargo publish --dry-run -p tideway`
  - `cargo publish --dry-run -p tideway-cli`
- Publish `tideway` before `tideway-cli` when the CLI metadata or generated apps point at the new framework version.
- Tag both release surfaces when both are released:
  - `tideway-vX.Y.Z`
  - `tideway-cli-vA.B.C`
- Push the release commit and tags to GitHub after successful publish.
- Keep unrelated local files such as `.DS_Store` or local agent folders out of release commits.

## Security Patch Checklist
- For auth, billing, generated-route, token, webhook, storage, or authorization changes, add focused regression tests that demonstrate the old failure mode is closed.
- Check both framework code and generated templates; security fixes often need both:
  - Core framework: `src/`
  - CLI templates: `tideway-cli/templates/`
  - Starter templates: `tideway-cli/templates/backend/starter/`
- Run feature-enabled tests for affected optional modules; default `cargo test` may not compile auth or billing modules.
- Prefer additive APIs and safer generated defaults over breaking existing generic APIs unless a breaking change is necessary to close the issue.
- For access-token auth, protected-route verification must reject refresh tokens. Use `verify_access_token(token).await` for access paths.
- For webhook idempotency, claim events before side effects and release claims on retryable handler errors.

## Generated App Validation
- After changing CLI templates, run `cargo test -p tideway-cli`.
- Expect scaffold snapshots to change when generated files, dependency versions, or scaffold metadata change; update snapshots only after inspecting the diff.
- CLI tests include generated app compile checks against the workspace source. Let the slow preset compile tests finish before declaring template changes valid.
- Preserve generated paths and module names unless the user explicitly accepts a migration. Generated-path compatibility matters for existing apps and docs.
- Keep B2B generated backend naming on `organization_member` / `organization_members`; legacy apps may still use `membership` / `memberships`.

## Repo Map
- Core framework: `src/`
- CLI: `tideway-cli/src/`
- CLI templates: `tideway-cli/templates/`
- Docs: `docs/`

## Required Conventions
- Use `TIDEWAY_VERSION` for CLI scaffolds.
- For CLI writes, use helpers in `tideway-cli/src/lib.rs`:
  - `ensure_dir`, `write_file`, `remove_file`, `remove_dir`
- Respect `--json` and `--plan` output modes.
- Preserve generated-path compatibility; prefer additive updates.
- B2B backend scaffolds use `organization_member` / `organization_members` naming (legacy generated apps may still use `membership` / `memberships`).

## Guardrails
- Docs drift: `bash scripts/check_docs_drift.sh`
- CLI FS-write policy: `bash scripts/check_cli_fs_writes.sh`
- Public API surface: `bash scripts/check_public_api_surface.sh`

## Testing
- CLI: `cargo test -p tideway-cli`
- Full: `cargo test`
