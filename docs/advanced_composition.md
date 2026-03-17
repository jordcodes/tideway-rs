# Advanced Composition

This page documents advanced alternatives to the canonical Tideway onboarding style.

Canonical onboarding style:
- Define modules with `module!`.
- Register modules with `App::register_module(...)`.
- Use `tideway new` + `tideway dev` + `tideway resource ... --wire ...`.

## Grouped Route Syntax

You can group multiple methods for one path in `module!`:

```rust
tideway::module!(
    UsersModule,
    prefix = "/api",
    routes = [
        ("/users", get => list_users, post => create_user),
    ]
);
```

## Mixed Module Registration

For mixed module types, use `register_modules!`:

```rust
let app = tideway::register_modules!(
    App::new(),
    routes::ApiModule,
    users::UsersModule,
);
```

## Optional Module Registration

For optional modules in mixed lists:

```rust
let app = tideway::register_modules!(
    App::new(),
    routes::ApiModule;
    optional: optional_module
);
```

For optional-only module registration:

```rust
let app = tideway::register_optional_modules!(
    App::new(),
    optional_module
);
```

## Homogeneous Module Iterators

When modules share one concrete type:

```rust
let app = App::new().register_modules(modules);
```

## Notes

- These patterns are stable and supported.
- They are marked advanced because they are not required for first-run productivity.
- For API contracts, see `docs/module_contracts.md`.
