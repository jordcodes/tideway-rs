# tideway-cli

CLI tool for scaffolding [Tideway](https://crates.io/crates/tideway) applications.

## Installation

```bash
cargo install tideway-cli
```

## Commands

Global options:
- `--json` - Emit machine-readable JSON lines (useful for tooling/agents)
- `--plan` - Show planned changes without writing files

### `tideway new`

Create a minimal Tideway app with a starter route and sensible defaults.

```bash
tideway new my_app
```

If you run it without extra flags, it will prompt for common options.

Options:
- `--preset` - Preset to apply (minimal, api)
- `--features` - Tideway features to enable (comma-separated)
- `--with-config` - Generate config.rs and error.rs starter files
- `--with-docker` - Generate docker-compose.yml for local Postgres
- `--with-ci` - Generate GitHub Actions CI workflow
- `--no-prompt` - Skip interactive prompts
- `--summary` - Print generated file summary
- `--with-env` - Always generate .env.example
- `--path` - Output directory (default: project name)
- `--force` - Overwrite existing files

Example:
```bash
tideway new my_app --features auth,database
```

Preset example:
```bash
tideway new my_app --preset api
```

List presets:
```bash
tideway new --preset list
```

Preset `api` also includes a DB-backed sample resource and migration scaffold.

Docker example:
```bash
tideway new my_app --features database --with-docker
```

CI example:
```bash
tideway new my_app --with-ci
```

The starter includes a basic `tests/health.rs` you can run with:
```bash
cargo test
```

### `tideway doctor`

Diagnose missing Tideway feature flags based on detected modules.

```bash
tideway doctor
```

Options:
- `--path` - Project directory to analyze (default: current directory)
- `--fix` - Generate .env.example when missing

### `tideway backend`

Generate backend scaffolding with auth, billing, organizations, and admin modules.

```bash
# B2C app (auth + billing + admin)
tideway backend b2c --name my_app

# B2B app (auth + billing + organizations + admin)
tideway backend b2b --name my_app
```

Options:
- `--name` - Project name (default: `my_app`)
- `--output` - Output directory (default: `./src`)
- `--database` - Database type: `postgres` or `sqlite` (default: `postgres`)
- `--force` - Overwrite existing files

### `tideway init`

Scan for modules and generate `main.rs` with proper wiring.

```bash
tideway init
```

This detects auth/, billing/, organizations/, and admin/ modules in your src directory and generates:
- `main.rs` - Application entry point with module registration
- `config.rs` - Configuration struct with environment loading
- `.env.example` - Example environment variables

Options:
- `--src` - Source directory to scan (default: `./src`)
- `--name` - Project name (default: from Cargo.toml)
- `--force` - Overwrite existing files
- `--no-database` - Skip database setup
- `--no-migrations` - Skip auto-migration on startup
- `--minimal` - Generate a minimal main.rs + sample routes module

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

### `tideway setup`

Set up frontend dependencies (Tailwind, shadcn components).

```bash
tideway setup
```

This automatically:
- Installs and configures Tailwind CSS
- Initializes shadcn-vue
- Installs all required shadcn components (button, input, card, dialog, table, etc.)

Options:
- `--style` - Styling: `shadcn`, `tailwind`, or `unstyled` (default: `shadcn`)
- `--no-tailwind` - Skip Tailwind setup
- `--no-components` - Skip shadcn component installation

### `tideway dev`

Run your app with `.env` loaded and optional auto-migrations.

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

### `tideway generate`

Generate frontend components for Vue (more frameworks coming soon).

```bash
# Generate auth components
tideway generate auth

# Generate all modules
tideway generate all --with-views
```

Options:
- `--framework` - Frontend framework: `vue` (default: `vue`)
- `--style` - Styling: `shadcn`, `tailwind`, or `unstyled` (default: `shadcn`)
- `--output` - Output directory (default: `./src/components/tideway`)
- `--with-views` - Also generate view files
- `--force` - Overwrite existing files

## Quick Start

### Backend

```bash
# Create a new B2B SaaS backend
mkdir my-saas-api && cd my-saas-api
cargo init
tideway backend b2b --name my_saas
tideway init

# Set up environment
cp .env.example .env
# Edit .env with your database URL and JWT secret

# Run (migrations run automatically on startup)
cargo run
```

Your API will be running at `http://localhost:3000` with routes:
- `POST /auth/register`, `POST /auth/login`, `GET /auth/me`
- `GET /organizations`, `POST /organizations`
- `GET /admin/users`, `GET /admin/organizations`

### Frontend

```bash
# Create Vue project with TypeScript, Router, and Pinia
npm create vue@latest my-saas-web -- --typescript --router --pinia
cd my-saas-web
npm install

# Set up Tailwind + shadcn-vue + all components
tideway setup

# Generate components, views, and configure router
tideway generate all --with-views

# Run
npm run dev
```

Your frontend will be at `http://localhost:5173` with pages:
- `/login`, `/register`, `/forgot-password`, `/reset-password`
- `/billing`
- `/settings/organization`, `/settings/members`
- `/admin`, `/admin/users`, `/admin/organizations`

### CORS Setup

If your frontend and backend are on different ports, add CORS to your backend `main.rs`:

```rust
use axum::http::{header, Method};
use tower_http::cors::CorsLayer;

// In main():
let cors = CorsLayer::new()
    .allow_origin(["http://localhost:5173".parse().unwrap()])
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

let router = app.into_router().layer(cors);
```

Add `tower-http` to your `Cargo.toml`:
```bash
cargo add tower-http --features cors
```

## Generated Structure

```
src/
├── main.rs           # Entry point with auto-migrations
├── lib.rs            # Module exports
├── config.rs         # Environment configuration
├── error.rs          # Error types
├── entities/         # SeaORM entities
├── auth/             # Authentication module
├── billing/          # Stripe billing module
├── organizations/    # Multi-tenancy (B2B only)
└── admin/            # Admin dashboard

migration/src/        # Database migrations
```

## Links

- [Tideway Framework](https://crates.io/crates/tideway)
- [Documentation](https://docs.rs/tideway)
- [GitHub](https://github.com/jordcodes/tideway-rs)
