# Getting Started

This guide takes you from `tideway new` to a working API using the canonical Tideway path.

## 1) Create a new app

```bash
tideway new my_app
cd my_app
tideway dev --fix-env
```
`tideway new my_app` is the encouraged API-first path.
In interactive mode, the first screen promotes `api`, `saas`, and `worker`; the lightweight `minimal` path lives under the wizard's advanced branch.
Use `--no-prompt` for the same defaults in CI/non-interactive runs, or `--preset minimal` if you explicitly want the lightweight starter.
For preset variants (`api`, `saas`, `worker`), see `docs/cli.md`.
The default API scaffold uses SQLite locally, so this path boots without extra database setup.
It also includes a sample `todo` resource wired through entity, repository, and service layers, with pagination and `q` search already enabled on the list endpoint.
`tideway dev --fix-env` creates `.env` from `.env.example`, replaces known development placeholders with cryptographically random local secrets, and runs pending migrations. It is safe to rerun: configured secrets are preserved.
If you want local Postgres instead, run `tideway new my_app --with-docker`, then `docker compose up -d` before `tideway dev --fix-env`.

## 2) Run the server

Visit:
- `http://localhost:8000/health`
- `http://localhost:8000/api`
- `http://localhost:8000/swagger-ui`
- `http://localhost:8000/api-docs/openapi.json`

## 3) Add a DB-backed resource (recommended)

```bash
tideway resource user
tideway migrate
```

The default API profile scaffolds routes, database entity/migration, repository, service, pagination, search, and wiring. Use the shape flags in the CLI reference only when you intentionally want a partial or customized scaffold.
If `tideway dev --fix-env` is not already running, start it now.
Run `tideway doctor` when you want a quick sanity check; it is not required for the happy path.

## 4) OpenAPI docs

If you followed the API-first scaffold, OpenAPI is already wired when enabled. Visit:

- `http://localhost:8000/swagger-ui`
- `http://localhost:8000/api-docs/openapi.json`

The generated document includes resource routes, authentication routes, JWT bearer security, and MFA routes when `auth-mfa` is enabled. Passwords, refresh tokens, MFA challenges, and verification codes are marked write-only in their request schemas.

For an MFA-enabled API from the start:

```bash
tideway new my_app --preset api --features auth-mfa
cd my_app
tideway dev --fix-env
```

The command generates independent local `JWT_SECRET` and `MFA_ENCRYPTION_KEY` values in the gitignored `.env`; `.env.example` remains secret-free. In production, inject stable secrets through your deployment secret manager. Changing `MFA_ENCRYPTION_KEY` makes previously encrypted MFA secrets unreadable.

If you need manual OpenAPI composition instead of the scaffolded path, see `docs/openapi.md`.
If you need trait-based module contracts or alternative registration styles, see:
- `docs/module_contracts.md`
- `docs/advanced_composition.md`

## 5) Configure the app

Tideway applies sensible defaults when you use `serve()`, but you can customize config:

```rust
use tideway::ConfigBuilder;

let config = ConfigBuilder::new()
    .with_log_level("debug")
    .with_dev_mode(true)
    .build()?;

let app = App::with_config(config)
    .register_module(routes::ApiModule);
```

`with_dev_mode(true)` enables the dev middleware branch.
Use `DevConfigBuilder` when you want specific dev tooling such as request dumping or stack traces in dev error responses.
For manual serving, global layers, or non-canonical composition, see `docs/advanced_composition.md` and `README.md`.

## 6) Return structured errors

```rust
use tideway::{Result, TidewayError};

async fn get_user() -> Result<String> {
    Err(TidewayError::not_found("User not found"))
}
```

## 7) Test endpoints

```rust
use tideway::testing::get as test_get;

#[tokio::test]
async fn test_health() {
    let app = tideway::App::new().into_router();

    test_get(app, "/health")
        .execute()
        .await
        .assert_ok();
}
```

## 8) Advanced follow-ups

- Manual database wiring: `docs/database_traits.md`
- Manual auth wiring: `docs/auth.md`
- Manual OpenAPI composition: `docs/openapi.md`
- Trait-based or mixed module composition: `docs/module_contracts.md` and `docs/advanced_composition.md`
- Advanced existing-project workflows: `docs/cli.md` (`tideway init`, `tideway backend`, `tideway add`)

## 9) Next steps

### Useful command

```bash
tideway doctor
```

- See `docs/auth.md`, `docs/database_traits.md`, `docs/validation.md`
- For advanced existing-project wiring, see `docs/cli.md`
