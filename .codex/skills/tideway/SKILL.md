---
name: tideway
description: Agent guidance for the Tideway framework and CLI scaffolding.
---

# Tideway Skill

## Purpose
Help agents work effectively in the Tideway repo and use the CLI scaffolds correctly.

## Current Direction (DX-First)
- Product goal: batteries-included, modular Rust APIs with fastest path to shipping.
- Source of truth roadmap: `ROADMAP_2026_DX.md`.
- Prioritize work in this order:
  1. Golden-path speed (`new` -> `dev` -> first endpoint)
  2. Scaffold reliability and idempotency
  3. Clear module/API contracts with feature-gate clarity
  4. Fast feedback loops via tests and CI guardrails

## Golden Path
- Create a new app with the wizard:
  - `tideway new my_app`
- Add a DB-backed resource:
  - `tideway resource <name> --wire --db --repo --service --paginate --search`
- Run:
  - `tideway dev --fix-env`
  - `tideway migrate`

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
