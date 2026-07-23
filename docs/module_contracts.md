# Module Contracts

Tideway is batteries-included, but module composition is explicit and stable.

## Contract Surface

The primary contract surface for app composition is:

- `App::register_module(module)`
- `App::register_optional_module(module)`
- `App::register_modules(iter)` for homogeneous module lists
- `tideway::register_modules!` for mixed module types
- `tideway::register_optional_modules!` for optional-only composition
- `tideway::prelude::*` for curated common imports

These APIs are intended to remain stable and are covered by tests.

## Prelude Contract

`tideway::prelude::*` is intentionally curated and small:

- Core app/config types (`App`, `AppBuilder`, `ConfigBuilder`, `AppContext`, `Result`, etc.)
- Module composition macros (`module!`, `register_modules!`, `register_optional_modules!`)
- Feature-specific exports only when their feature is enabled

Use the prelude for application code when you want stable, low-friction imports.

## Feature-Gated Modules

Feature-gated modules are explicit (`auth`, `database`, `openapi`, etc.).

Two enforcement modes exist:

- `feature-gate-errors`: compile-time errors with actionable guidance
- `feature-gate-warnings`: deprecated module stubs that compile, with warnings

Example:

```toml
[dependencies]
tideway = { version = "0.7.30", default-features = false, features = ["feature-gate-errors"] }
```

In this mode, using disabled modules yields clear messages such as:
"Enable the `auth` feature to use tideway::auth".

## Stability Guidance

When evolving module APIs:

1. Prefer additive changes over path/shape breaks.
2. Keep generated scaffolds aligned with this contract surface.
3. Update prelude exports intentionally and guard with tests.
4. Keep feature-gate error messages actionable and specific.
