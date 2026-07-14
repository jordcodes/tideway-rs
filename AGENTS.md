# Tideway Agent Guidance

This repo uses a fast-scaffolding CLI (`tideway-cli`) and a core Rust framework (`tideway`).  
Follow these conventions to work efficiently and safely.

## Golden Path (API)
- Prefer the CLI wizard: `tideway new my_app` and follow prompts.
- Add resources with:
  - `tideway resource <name>`
- Run the app:
  - `tideway dev --fix-env`
  - `tideway migrate` for DB migrations

## File Map
- Core framework: `src/`
- CLI: `tideway-cli/src/`
- CLI templates: `tideway-cli/templates/`
- Docs: `docs/`
- Tests: `tests/`, `tideway-cli/tests/`

## CLI Conventions
- `--json` emits machine-readable output (useful for agents).
- `--plan` shows planned file operations without writing.
- Use `TIDEWAY_VERSION` for Tideway versioning in CLI scaffolds.
- Never write files directly in CLI code. Use helpers in `tideway-cli/src/lib.rs`:
  - `ensure_dir`, `write_file`, `remove_file`, `remove_dir`

## Patterns
- DB-backed resources: `routes` → `repositories` → `services`.
- Use `paginate` + `search (q)` for list endpoints when DB-backed.
- Avoid breaking changes to generated paths; prefer additive updates.

## Upgrading Existing Apps
- Treat generated files as application-owned code. Never rerun broad scaffolds with `--force` over
  an existing app or replace custom handlers, services, authorization, or migrations wholesale.
- Inspect the read-only upgrade report first: `tideway --json doctor --upgrade`.
- Apply only the reported compatibility edits and additive migrations.
- After remediation, run `tideway --json doctor --upgrade --deny-warnings`, normal
  `tideway doctor --deny-warnings`, pending migrations, and the application test suite.
- For built-in SeaORM billing, require `billing_processed_events.event_id` to be a primary key.
- See `docs/upgrading.md` for stable finding codes, version-specific steps, testing, and rollback.

## Testing
- CLI tests: `cargo test -p tideway-cli`
- Full test suite: `cargo test`
