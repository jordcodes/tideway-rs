# Tideway Skills (for coding agents)

This file provides a concise, agent-friendly guide to working on the Tideway codebase and CLI.

## Project Overview
- `tideway` is a Rust web framework (Axum-based) with batteries-included SaaS primitives.
- `tideway-cli` scaffolds apps, resources, and backend modules.
- `tideway-macros` contains optional proc-macros.

## Repo Map
- Core framework: `src/`
- CLI: `tideway-cli/src/`
- CLI templates: `tideway-cli/templates/`
- Docs: `docs/`
- Examples: `examples/`
- Tests: `tests/` and `tideway-cli/tests/`

## Golden Path (API Project)
If starting a new API app:
- `tideway new my_app` (wizard)
- Choose preset (API or B2B backend).
- Generate first resource.
- `tideway dev --fix-env`
- `tideway migrate` (when using DB)

If adding a resource:
- `tideway resource carehome --wire --db --repo --service --paginate --search`

## CLI Behavior (Important)
- `--json` outputs machine-readable JSON lines.
- `--plan` outputs planned file operations without writing.
- Use the helpers in `tideway-cli/src/lib.rs` for file I/O and plan mode:
  - `ensure_dir`, `write_file`, `remove_file`, `remove_dir`
  - `is_plan_mode`, `is_json_output`

## Conventions
- Resources follow: routes -> repo -> service layering when DB-backed.
- OpenAPI wiring is optional but prefer it when `openapi` feature is enabled.
- Keep generated file paths stable; prefer additive changes over breaking rewrites.
- Prefer SeaORM for DB scaffolding.

## Common Entry Points
- `tideway-cli/src/commands/new.rs` (new project + wizard)
- `tideway-cli/src/commands/resource.rs` (CRUD generator)
- `tideway-cli/src/commands/backend.rs` (B2B/B2C modules)
- `tideway-cli/src/commands/add.rs` (feature toggles + wiring)

## Testing
- CLI: `cargo test -p tideway-cli`
- Core: `cargo test`

## Pitfalls to Avoid
- Hard-coding Tideway crate versions; use `TIDEWAY_VERSION`.
- Writing files directly; always use `write_file` + `ensure_dir`.
- Printing raw text during `--json` mode; prefer `print_*` helpers.

## Useful Patterns
- For list endpoints: support `paginate` + `search (q)` when DB-backed.
- Prefer `id_type` defaults (`int`) unless user opts into `uuid`.

## When In Doubt
- Run `tideway doctor` to surface missing features.
- Use `tideway init` to re-wire `main.rs` after adding modules.
