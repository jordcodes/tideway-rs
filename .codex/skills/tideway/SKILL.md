---
name: tideway
description: Agent guidance for the Tideway framework and CLI scaffolding.
---

# Tideway Skill

## Purpose
Help agents work effectively in the Tideway repo and use the CLI scaffolds correctly.

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

## Testing
- CLI: `cargo test -p tideway-cli`
- Full: `cargo test`
