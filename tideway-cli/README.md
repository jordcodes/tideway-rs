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

```bash
# Create a new B2B SaaS backend
mkdir my-saas && cd my-saas
cargo init
tideway backend b2b --name my_saas
tideway init

# Set up environment
cp .env.example .env
# Edit .env with your database URL and secrets

# Run (migrations run automatically)
cargo run
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
