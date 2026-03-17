# CLI Reference

This doc lists the Tideway CLI commands with common examples.

## Installation

```bash
cargo install tideway-cli
```

## Command Groups

Primary (recommended for most users):
- `new`
- `dev`
- `resource`
- `doctor`
- `migrate`

Advanced (existing projects, nonstandard workflows, or legacy compatibility):
- `add`
- `backend`
- `init`
- `generate`
- `setup`
- `templates`

## Commands

Global options:
- `--json` - Emit machine-readable JSON lines (useful for tooling/agents)
- `--plan` - Show planned changes without writing files

### `tideway new`

Create a new starter project.

```bash
tideway new my_app
```

If you run it without extra flags, it will prompt for options and default to the API-first path.
The first interactive screen promotes `api`, `saas`, and `worker`; `minimal`, backend presets, and custom feature picking stay under an advanced branch.
In non-interactive/CI use, `--no-prompt` follows the same API-first defaults unless you explicitly choose a different preset or shape flags.
For the default API path, local development uses SQLite unless you explicitly add `--with-docker` for Postgres.
The API preset already seeds a sample `todo` resource wired through entity, repository, and service layers, with `limit`, `offset`, and `q` support on the list endpoint.
The SaaS preset generates the B2B auth/billing/organizations/admin backend scaffold with Postgres Docker, CI, env defaults, and a public `GET /billing/plans` smoke endpoint.

Use a preset to apply common defaults:

```bash
tideway new my_app --preset api
tideway new my_app --preset saas
tideway new my_app --preset worker
```

List presets:

```bash
tideway new --preset list
```

With features and explicit local Postgres:

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

Explicit minimal starter:

```bash
tideway new my_app --preset minimal --no-prompt
```

Always generate `.env.example`:

```bash
tideway new my_app --with-env
```

Available presets:
- `minimal` - basic starter
- `api` - auth + database + openapi + validation, plus config, CI, env, and a sample `todo` resource with entity/repository/service layers, pagination, and search (SQLite local dev by default; add `--with-docker` for Postgres)
- `saas` - b2b backend scaffold with auth, billing, organizations, admin, docker, CI, env, and billing-ready defaults
- `worker` - jobs-first scaffold (database + jobs + redis + metrics) with config, docker, CI, env

### `tideway init` (advanced)

Scan your existing project and generate `main.rs` wiring.

```bash
tideway init
```

Minimal entrypoint:

```bash
tideway init --minimal
```

### `tideway add` (advanced)

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
tideway resource user
tideway resource user --profile stub
tideway resource user --wire
tideway resource invoice_item --wire
tideway resource user --wire --db
tideway resource user --wire --db --repo
tideway resource user --wire --db --repo --repo-tests
tideway resource user --wire --db --repo --service
tideway resource user --wire --db --id-type uuid
tideway resource user --wire --db --id-type uuid --add-uuid
tideway resource user --wire --db --paginate
tideway resource user --wire --db --paginate --search
```

`--profile api` is the default and applies full-stack defaults (`--wire --db --repo --service --paginate --search`) when no shape flags are set.
Use `--profile stub` for lightweight route-only scaffolding.
If you pass shape flags explicitly (`--wire`, `--db`, `--repo`, `--service`, `--paginate`, `--search`), Tideway uses those exact flags and does not apply profile defaults.

If the OpenAPI feature is enabled, `--wire` will also update `src/openapi_docs.rs` with the new routes.
Use `--db` to scaffold a SeaORM entity + migration and switch routes to real DB CRUD. With `--wire`, it also wires the database into `main.rs`.
Use `--repo` to generate a repository layer for DB-backed resources.
Use `--repo-tests` to generate an ignored CRUD smoke test (defaults to postgres profile).
Set `TIDEWAY_TEST_DB_BACKEND=postgres_container` to run against a Docker container when
the `test-containers` feature is enabled, or `TIDEWAY_TEST_DB_BACKEND=postgres` with
`TEST_DATABASE_URL`/`TIDEWAY_TEST_DATABASE_URL` for local PostgreSQL.
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

`tideway doctor` is optional for the recommended new-app path; use it as a sanity check or when recovering from setup drift.

### `tideway backend` (advanced)

Generate a full backend preset.

```bash
tideway backend b2c --name my_app
tideway backend b2b --name my_app
```

Compatibility note:
- Current B2B scaffolds generate `organization_members` (entity/module: `organization_member`).
- Older generated apps may use `memberships`/`membership` for the same concept.

### `tideway generate` (advanced)

Generate frontend components.

```bash
tideway generate auth
tideway generate billing --with-views
tideway generate all --framework vue
```

### `tideway setup` (advanced)

Install Tailwind + shadcn-vue for your frontend.

```bash
tideway setup
```

### `tideway dev`

Run a Tideway app in dev mode (loads `.env`, optional migrations).

```bash
tideway dev
tideway dev
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

- Canonical path: `new` -> `dev` -> `resource ...` -> `migrate`.
- `tideway new` is intended to steer new users into the API-first path by default; use `--preset minimal` only when you want the lighter scaffold explicitly.
- `tideway doctor` is a quick sanity check and repair tool, not a required first-run step.
