# CLI Reference

This doc lists the Tideway CLI commands with common examples.

## Installation

```bash
cargo install tideway-cli
```

## Commands

### `tideway new`

Create a new starter project.

```bash
tideway new my_app
```

With features and local Postgres:

```bash
tideway new my_app --features auth,database --with-docker
```

With config scaffolding and CI:

```bash
tideway new my_app --with-config --with-ci
```

### `tideway init`

Scan your existing project and generate `main.rs` wiring.

```bash
tideway init
```

Minimal entrypoint:

```bash
tideway init --minimal
```

### `tideway doctor`

Check for missing features and env vars.

```bash
tideway doctor
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

## Notes

- `tideway new` is the fastest path to a runnable API.
- `tideway doctor` is a quick sanity check before deploying.
