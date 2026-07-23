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

See `docs/deprecation_policy.md` for how Tideway classifies primary, advanced, legacy, and deprecated command paths.

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
The API preset seeds a sample `todo` resource wired through entity, repository, and service layers, with `limit`, `offset`, and `q` support on the list endpoint. Generated list queries default to 20 rows and cap `limit` at 100.
The API preset also generates database-backed registration, login, refresh rotation, logout, password-reset storage, and `GET /auth/me`; its delivery hooks remain application-owned. Public registration is disabled by default and must be explicitly enabled with `ALLOW_PUBLIC_REGISTRATION=true` for an intentional self-service or bootstrap flow. The SaaS preset goes further with working password-reset and email-verification flows plus provider-neutral Resend, SMTP, development console, and custom `Mailer` options. Keep `REQUIRE_EMAIL_VERIFICATION=false` until a production provider and verified sender are configured.
The SaaS preset generates the B2B auth/billing/organizations/admin backend scaffold with Postgres Docker, CI, env defaults, secure email-delivered organization invitations, and a public `GET /billing/public/plans` smoke endpoint. Invitation files are generated only on this greenfield path; upgrades never overwrite an application's organization model.
Invitations are included by default and can be omitted with `--without-invitations`.

Use a preset to apply common defaults:

```bash
tideway new my_app --preset api
tideway new my_app --preset saas
tideway new my_app --preset saas --without-invitations
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

Feature names are validated before any files are written. Common aliases are normalized (`db` to `database`, `session` to `sessions`, and `mfa` to `auth-mfa`); unknown names fail with a supported-feature list and a nearby suggestion when available.

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
- `saas` - b2b backend scaffold with auth, billing, organizations, secure invitations, admin, docker, CI, env, and billing-ready defaults
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
tideway add organizations --wire --db
tideway add credits
tideway add billing-schema
tideway add openapi
tideway add openapi --wire
```

When adding OpenAPI, the CLI creates `src/openapi_docs.rs` if it does not exist.
`tideway add organizations --wire --db` is a focused backend add path: it generates organization routes, entities, and migrations without billing/admin scaffolding.
It currently expects an existing org-aware DB-backed auth/user contract (`RequestActor` organization helpers, `user.organization_id`, and registered user migrations). If you only need an organization-shaped CRUD resource, use `tideway resource organization --profile tenant`.

`tideway add credits` is additive: it enables the persistent credits features and registers a new
ledger migration without generating or replacing application handlers or migration history. It
preserves the application's existing migration convention, including sequential names such as
`m014_...` and SeaORM timestamp names such as `m20260717_143012_...`. See `docs/credits.md` for the
reserve/commit workflow and optional Stripe top-ups.

`tideway add billing-schema` is an upgrade repair for applications using
`SeaOrmBillingStore`. It registers an idempotent additive migration for the current
`billing_customers` contract unless that forward repair already exists. It does not edit an applied
migration, application code, dependencies, or environment files. Review the generated legacy-value
backfill before running `tideway migrate`.

### `tideway resource`

Generate a CRUD route module for a resource.

Recommended full API resource:

```bash
tideway resource user
```

Intent-specific full-stack profiles:

```bash
tideway resource organization --profile tenant
tideway resource subscription --profile owned
tideway resource admin_user --profile admin
tideway resource audit_event --profile event
```

Advanced shape overrides and lightweight scaffolds:

```bash
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
For the primary workflow, prefer `tideway resource <name>` and let the profile choose those implementation details.
`--profile tenant` generates a tenant or organization-shaped schema (`name`, `slug`, `status`, timestamps).
`--profile owned` generates a tenant-owned resource shape (`organization_id`, `owner_id`, `name`, `status`, timestamps).
`--profile admin` generates an operator/admin shape (`email`, `role`, `enabled`, timestamps).
`--profile event` generates an audit/event shape (`event_type`, `actor_id`, `subject_id`, `payload_json`, timestamps).
`--profile stub` keeps the lightweight route-only scaffold.
If you pass shape flags explicitly (`--wire`, `--db`, `--repo`, `--service`, `--paginate`, `--search`), Tideway uses those exact flags and does not apply profile defaults.

If the OpenAPI feature is enabled, `--wire` will also update `src/openapi_docs.rs` with the new routes.
Use `--db` to scaffold a SeaORM entity + migration and switch routes to real DB CRUD. With `--wire`,
it also wires the database into `main.rs`. Generated migrations preserve the convention already in
the application: sequential (`m015_...`) or SeaORM timestamp (`m20260717_143012_...`). For a mixed
history, Tideway follows the convention of the last migration registered in
`Migrator::migrations()`; if that cannot be determined, it stops instead of guessing.
Use `--repo` to generate a repository layer for DB-backed resources.
Use `--repo-tests` to generate an ignored CRUD smoke test (defaults to postgres profile).
Set `TIDEWAY_TEST_DB_BACKEND=postgres_container` to run against a Docker container when
the `test-containers` feature is enabled, or `TIDEWAY_TEST_DB_BACKEND=postgres` with
`TEST_DATABASE_URL`/`TIDEWAY_TEST_DATABASE_URL` for local PostgreSQL.
Use `--service` to generate a validating service layer on top of the repository, with input normalization and not-found handling for the service-backed path.
On SaaS scaffolds with the shared request actor contract, generated `owned` and `admin` resources also move tenant/admin enforcement into the service layer instead of keeping it only in the route handlers.
Generated `owned` services keep cross-tenant lookups opaque, but return an explicit forbidden error when a record is in the caller's organization and owned by a different user.
Those actor-aware service writes also generate a no-op audit hook seam with a structured event payload (`action`, `actor_id`, `organization_id`, `resource`, `resource_id`) so create/update/delete flows have one obvious place to attach activity logging, event publishing, or outbound side effects.
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

Check an existing application before upgrading Tideway:

```bash
tideway doctor --upgrade
```

This check is read-only and reports framework-version drift, direct dependency mismatches, and
known source migrations. It uses the Tideway version bundled into the installed CLI and supports
global `--json` output. Add `--deny-warnings` when CI or an agent should receive a non-zero exit
status until every warning is resolved. Finding JSON includes stable codes, affected paths, and the
upgrade-guide URL. See `docs/upgrading.md` for the complete workflow.

`tideway doctor` is optional for the recommended new-app path; use it as a sanity check or when recovering from setup drift.

### `tideway backend` (advanced)

Generate a full backend preset.
For greenfield SaaS apps, prefer `tideway new my_app --preset saas`; use `backend` when you are grafting the scaffold into an existing or nonstandard project.

```bash
tideway backend b2c --name my_app
tideway backend b2b --name my_app
tideway backend b2b --name my_app --without-invitations
```

B2B backends include secure organization invitations by default. Use `--without-invitations` when
membership onboarding is owned by another service or an existing application-specific workflow.
The flag omits the invitation routes, entity, migration, email hook, and associated dependency; it
does not remove the rest of the organizations module.

Compatibility note:
- Current B2B scaffolds generate `organization_members` (entity/module: `organization_member`).
- Older generated apps may use `memberships`/`membership` for the same concept.

### `tideway generate` (advanced)

Generate Vue frontend helpers for existing Vue apps.
This is a secondary workflow and is not part of the primary API path.

```bash
tideway generate auth
tideway generate organizations --with-views
tideway generate billing --with-views
tideway generate all --framework vue
```

`tideway generate organizations` is frontend-only. It does not generate backend organization routes, membership storage, or migrations.

### `tideway setup` (advanced)

Set up Vue frontend dependencies (Tailwind + shadcn-vue) for the advanced frontend helper path.
This is secondary to the API-first workflow.

```bash
tideway setup
```

### `tideway dev`

Run a Tideway app in dev mode with automatic rebuilds and restarts (loads `.env`, optional migrations).

```bash
tideway dev --fix-env
tideway dev --no-migrate
tideway dev -- --release
tideway dev --no-watch
```

`--fix-env` is the recommended first-run command. It creates `.env` from `.env.example` and replaces recognized JWT placeholders and an empty `MFA_ENCRYPTION_KEY` with independent cryptographically random local values. Existing configured secrets are not rotated. The generated `.env` is gitignored; production secrets should come from your deployment secret manager.

Before starting Cargo, `tideway dev` validates database configuration and prints the local API, health, Swagger UI, and OpenAPI URLs that are enabled by the effective configuration. Existing shell environment variables take precedence over values in `.env`; `.env` supplies only missing values. The command enables pending migrations for the local run unless `--no-migrate` is supplied, which explicitly sets `DATABASE_AUTO_MIGRATE=false` for that run.

By default, the command verifies that the configured development port is available before compiling, then watches Rust sources, migrations, Cargo manifests, and `.env`. It debounces editor save events, cancels superseded builds, and restarts the application only after a successful build. If compilation fails, the last working server keeps running while Tideway waits for the next change. Press Ctrl-C to stop the watcher and its child processes. Use `--no-watch` for the previous one-shot `cargo run` behaviour.

Arguments after the first `--` are passed to Cargo. To pass arguments to the application in watch mode, add a second separator: `tideway dev -- --release -- --seed`.

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

- Canonical path: `new` -> `dev` -> `resource <name>` -> `migrate`.
- `tideway new` is intended to steer new users into the API-first path by default; use `--preset minimal` only when you want the lighter scaffold explicitly.
- `tideway doctor` is a quick sanity check and repair tool, not a required first-run step.
- Frontend `generate` / `setup` flows are currently Vue-focused advanced helpers, not a co-equal onboarding path with the backend/API workflow.
