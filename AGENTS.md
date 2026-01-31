# Tideway Agent Guidance

This repo uses a fast-scaffolding CLI (`tideway-cli`) and a core Rust framework (`tideway`).  
Follow these conventions to work efficiently and safely.

## Golden Path (API)
- Prefer the CLI wizard: `tideway new my_app` and follow prompts.
- Add resources with:
  - `tideway resource <name> --wire --db --repo --service --paginate --search`
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

## Testing
- CLI tests: `cargo test -p tideway-cli`
- Full test suite: `cargo test`
