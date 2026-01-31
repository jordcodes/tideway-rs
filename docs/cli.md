# CLI Reference

This doc lists the Tideway CLI commands with common examples.

## Installation

```bash
cargo install tideway-cli
```

## Commands

Global options:
- `--json` - Emit machine-readable JSON lines (useful for tooling/agents)

### `tideway new`

Create a new starter project.

```bash
tideway new my_app
```

If you run it without extra flags, it will prompt for options.

Use a preset to apply common defaults:

```bash
tideway new my_app --preset api
```

List presets:

```bash
tideway new --preset list
```

With features and local Postgres:

```bash
tideway new my_app --features auth,database --with-docker
```

With config scaffolding and CI:

```bash
tideway new my_app --with-config --with-ci
```

Skip prompts in CI:

```bash
tideway new my_app --no-prompt
```

Hide the generated file summary:

```bash
tideway new my_app --summary false
```

Always generate `.env.example`:

```bash
tideway new my_app --with-env
```

Available presets:
- `minimal` - basic starter
- `api` - auth + database + openapi + validation, plus config, docker, CI, env, and a DB-backed sample resource

### `tideway init`

Scan your existing project and generate `main.rs` wiring.

```bash
tideway init
```

Minimal entrypoint:

```bash
tideway init --minimal
```

### `tideway add`

Add Tideway features and optional scaffolding.

```bash
tideway add auth
tideway add auth --wire
tideway add database
tideway add database --wire
tideway add openapi
tideway add openapi --wire
```

When adding OpenAPI, the CLI creates `src/openapi_docs.rs` if it does not exist.

### `tideway resource`

Generate a CRUD route module for a resource.

```bash
tideway resource user --wire
tideway resource invoice_item --wire --with-tests false
tideway resource user --wire --db
tideway resource user --wire --db --repo
tideway resource user --wire --db --repo --repo-tests
tideway resource user --wire --db --repo --service
tideway resource user --wire --db --id-type uuid
tideway resource user --wire --db --id-type uuid --add-uuid
tideway resource user --wire --db --paginate
tideway resource user --wire --db --paginate --search
```

If the OpenAPI feature is enabled, `--wire` will also update `src/openapi_docs.rs` with the new routes.
Use `--db` to scaffold a SeaORM entity + migration and switch routes to real DB CRUD. With `--wire`, it also wires the database into `main.rs`.
Use `--repo` to generate a repository layer for DB-backed resources.
Use `--repo-tests` to generate an ignored CRUD smoke test (requires DATABASE_URL).
Use `--service` to generate a thin service layer on top of the repository.
Use `--id-type` to switch ID generation (int or uuid) for DB scaffolding. Use `--add-uuid` to automatically add the `uuid` dependency.
Use `--paginate` to add limit/offset query params to list endpoints.
Use `--search` to add a `q` search filter to list endpoints (requires `--paginate`).

### `tideway doctor`

Check for missing features and env vars.

```bash
tideway doctor
```

Fix missing `.env.example`:

```bash
tideway doctor --fix
```

### `tideway backend`

Generate a full backend preset.

```bash
tideway backend b2c --name my_app
tideway backend b2b --name my_app
```

### `tideway generate`

Generate frontend components.

```bash
tideway generate auth
tideway generate billing --with-views
tideway generate all --framework vue
```

### `tideway setup`

Install Tailwind + shadcn-vue for your frontend.

```bash
tideway setup
```

### `tideway dev`

Run a Tideway app in dev mode (loads `.env`, optional migrations).

```bash
tideway dev
tideway dev --fix-env
tideway dev --no-migrate
tideway dev -- --release
```

### `tideway migrate`

Run database migrations (SeaORM by default).

```bash
tideway migrate
tideway migrate status
tideway migrate down
tideway migrate init
tideway migrate up -- --num 2
```

## Notes

- `tideway new` is the fastest path to a runnable API.
- `tideway doctor` is a quick sanity check before deploying.
