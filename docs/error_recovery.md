# Error Recovery

Tideway CLI errors now follow a standard format:

- `Problem: ...`
- `Primary fix: ...`
- `Advanced fix: ...`

Use primary fixes first. Use advanced fixes when adapting an existing project.

## Common Recovery Flows

### 1) `tideway new` fails because app name is missing

```bash
tideway new my_app
```

### 2) `tideway new` fails because destination exists

Primary:
```bash
tideway new my_app_v2
```

Advanced:
```bash
tideway new my_app --force
```

### 3) `tideway add ...` fails because `Cargo.toml` is missing

Primary:
```bash
cd /path/to/rust/project
tideway add auth
```

Advanced:
```bash
tideway new my_app
cd my_app
tideway add auth
```

### 4) `tideway resource ...` fails because `src/` is missing

Primary:
```bash
cd my_app
tideway resource user
```

Advanced:
```bash
tideway new my_app
cd my_app
tideway resource user
```

### 5) `tideway resource ... --repo` fails without `--db`

Primary:
```bash
tideway resource user --db --repo
```

Advanced:
```bash
tideway resource user --wire
```

### 6) DB resource generation fails because database feature/deps are missing

Primary:
```bash
tideway new my_app --preset api
```

Advanced:
```bash
tideway add database
tideway resource user --wire --db
```

### 7) UUID id resource generation fails without `uuid` dependency

Primary:
```bash
tideway resource user --wire --db --id-type uuid --add-uuid
```

Advanced:
```bash
# add uuid dependency manually, then rerun
tideway resource user --wire --db --id-type uuid
```

### 8) `tideway migrate` cannot detect backend

Primary:
```bash
tideway migrate status --backend sea-orm
```

Advanced:
```bash
tideway add database
tideway migrate status
```

### 9) `tideway migrate` fails because `DATABASE_URL` is missing/invalid

Primary:
```bash
tideway dev
tideway migrate status
```

Advanced:
```bash
# set DATABASE_URL in .env manually
tideway migrate status
```

### 10) `tideway init` / `tideway backend` confusion

Primary (new app):
```bash
tideway new my_app
cd my_app
tideway dev
```

Advanced (existing project):
```bash
tideway backend b2c --name my_app
tideway init
```

## See Also

- `docs/getting_started.md`
- `docs/cli.md`
- `docs/advanced_composition.md`
