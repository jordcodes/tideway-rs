# tideway-cli

CLI tool for scaffolding [Tideway](https://crates.io/crates/tideway) applications.

## Installation

```bash
cargo install tideway-cli
```

## Commands

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
