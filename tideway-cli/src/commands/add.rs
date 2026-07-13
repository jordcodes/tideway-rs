//! Add command - enable Tideway features and scaffold modules.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{AddArgs, AddFeature};
use crate::commands::app_builder::{
    find_app_builder_end_insert_at, find_app_builder_marker_range, find_app_builder_start,
    find_app_builder_var_name, find_statement_terminator,
    find_unmarked_app_builder_statement_range, insert_snippet_into_builder_block,
};
use crate::commands::file_ops::{ensure_module_decl, to_pascal_case, write_file_with_force};
use crate::commands::messaging::GREENFIELD_NEW_APP_FIRST;
use crate::templates::{BackendTemplateContext, BackendTemplateEngine};
use crate::{
    CommandRuntime, TIDEWAY_VERSION, ensure_dir, error_contract, print_info, print_success,
    print_warning, write_file,
};

pub fn run(args: AddArgs) -> Result<()> {
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(args: AddArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();
    validate_add_args(&args)?;

    let project_dir = PathBuf::from(&args.path);
    let cargo_path = project_dir.join("Cargo.toml");

    if !cargo_path.exists() {
        return Err(anyhow::anyhow!(error_contract(
            &format!("Cargo.toml not found in {}", project_dir.display()),
            "Run this command inside a Rust project root.",
            GREENFIELD_NEW_APP_FIRST,
        )));
    }

    let cargo_contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;

    let project_name = project_name_from_cargo(&cargo_contents, &project_dir);
    let project_name_pascal = to_pascal_case(&project_name);

    if args.feature == AddFeature::Organizations {
        validate_organizations_preconditions(&project_dir, args.db)?;
    }

    update_cargo_toml(&cargo_path, &cargo_contents, args.feature)?;
    update_env_example(&project_dir, args.feature, &project_name)?;

    if args.feature == AddFeature::Auth {
        scaffold_auth(
            &project_dir,
            &project_name,
            &project_name_pascal,
            args.force,
        )?;
        print_info("Auth scaffold created in src/auth/");
        if args.wire {
            wire_auth_in_main(&project_dir, &project_name)?;
        } else {
            print_info("Next steps: wire AuthModule + SimpleAuthProvider in main.rs");
        }
    }

    if args.feature == AddFeature::Database && args.wire {
        wire_database_in_main(&project_dir)?;
    }

    if args.feature == AddFeature::Openapi {
        ensure_openapi_docs_file(&project_dir)?;
        if args.wire {
            wire_openapi_in_main(&project_dir)?;
        } else {
            print_info("Next steps: wire OpenAPI in main.rs");
        }
    }

    if args.feature == AddFeature::Organizations {
        scaffold_organizations(
            &project_dir,
            &project_name,
            &project_name_pascal,
            args.force,
            args.db,
        )?;
        print_info("Organizations scaffold created in src/organizations/");
        if args.wire {
            wire_organizations_in_main(&project_dir)?;
        } else {
            print_info("Next steps: wire OrganizationModule in main.rs");
        }
    }

    print_success(&format!("Added {}", args.feature));
    Ok(())
}

fn validate_add_args(args: &AddArgs) -> Result<()> {
    if args.db && args.feature != AddFeature::Organizations {
        return Err(anyhow::anyhow!(error_contract(
            "--db is only supported with `tideway add organizations`",
            "Run `tideway add organizations --wire --db` for database-backed organization scaffolding.",
            "For DB-backed CRUD resources, use `tideway resource <name> --wire --db --repo --service`.",
        )));
    }

    Ok(())
}

fn update_cargo_toml(path: &Path, contents: &str, feature: AddFeature) -> Result<()> {
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;

    let deps = doc["dependencies"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let deps_table = deps.as_table_mut().ok_or_else(|| {
        anyhow::anyhow!("Invalid Cargo.toml: [dependencies] must be a TOML table")
    })?;

    let tideway_item = deps_table.entry("tideway");

    let feature_names = tideway_features_for_add(feature);

    match tideway_item {
        toml_edit::Entry::Vacant(entry) => {
            let mut table = toml_edit::InlineTable::new();
            table.get_or_insert("version", TIDEWAY_VERSION);
            let feature_refs = feature_names.iter().map(String::as_str).collect::<Vec<_>>();
            table.get_or_insert("features", array_value(&feature_refs));
            entry.insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
        }
        toml_edit::Entry::Occupied(mut entry) => {
            if entry.get().is_str() {
                let version = entry.get().as_str().unwrap_or(TIDEWAY_VERSION).to_string();
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", version);
                let feature_refs = feature_names.iter().map(String::as_str).collect::<Vec<_>>();
                table.get_or_insert("features", array_value(&feature_refs));
                entry.insert(toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
            } else {
                let item = entry.get_mut();
                let features = item["features"]
                    .or_insert(toml_edit::Item::Value(toml_edit::Value::Array(
                        toml_edit::Array::new(),
                    )))
                    .as_array_mut()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Invalid Cargo.toml: dependencies.tideway.features must be an array"
                        )
                    })?;

                for feature_name in &feature_names {
                    if !features.iter().any(|v| v.as_str() == Some(feature_name)) {
                        features.push(feature_name.as_str());
                    }
                }
            }
        }
    }

    if feature == AddFeature::Database || feature == AddFeature::Organizations {
        deps_table
            .entry("sea-orm")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable({
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", "1.1");
                table.get_or_insert(
                    "features",
                    array_value(&["sqlx-postgres", "runtime-tokio-rustls"]),
                );
                table
            })));
    }

    if feature == AddFeature::Auth || feature == AddFeature::Organizations {
        deps_table
            .entry("async-trait")
            .or_insert(toml_edit::value("0.1"));
        deps_table
            .entry("serde")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable({
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", "1.0");
                table.get_or_insert("features", array_value(&["derive"]));
                table
            })));
        deps_table
            .entry("serde_json")
            .or_insert(toml_edit::value("1.0"));
        deps_table
            .entry("uuid")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::InlineTable({
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", "1");
                table.get_or_insert("features", array_value(&["v4", "serde"]));
                table
            })));
        deps_table.entry("chrono").or_insert(toml_edit::Item::Value(
            toml_edit::Value::InlineTable({
                let mut table = toml_edit::InlineTable::new();
                table.get_or_insert("version", "0.4");
                table.get_or_insert("features", array_value(&["serde"]));
                table
            }),
        ));
    }

    write_file(path, &doc.to_string())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn tideway_features_for_add(feature: AddFeature) -> Vec<String> {
    match feature {
        AddFeature::Organizations => vec![
            "auth".to_string(),
            "database".to_string(),
            "organizations".to_string(),
            "organizations-seaorm".to_string(),
        ],
        _ => vec![feature.to_string()],
    }
}

fn update_env_example(project_dir: &Path, feature: AddFeature, project_name: &str) -> Result<()> {
    let env_path = project_dir.join(".env.example");
    let mut lines = if env_path.exists() {
        fs::read_to_string(&env_path)
            .with_context(|| format!("Failed to read {}", env_path.display()))?
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
    } else {
        vec![
            "# Server".to_string(),
            "TIDEWAY_HOST=0.0.0.0".to_string(),
            "TIDEWAY_PORT=8000".to_string(),
            String::new(),
        ]
    };

    let mut existing = BTreeSet::new();
    for line in &lines {
        if let Some((key, _)) = line.split_once('=') {
            existing.insert(key.trim().to_string());
        }
    }

    match feature {
        AddFeature::Database => {
            if !existing.contains("DATABASE_URL") {
                lines.push("# Database".to_string());
                lines.push(format!(
                    "DATABASE_URL=postgres://postgres:postgres@localhost:5432/{}",
                    project_name
                ));
                lines.push(String::new());
            }
        }
        AddFeature::Auth => {
            if !existing.contains("JWT_SECRET") {
                lines.push("# Auth".to_string());
                lines.push("JWT_SECRET=replace-with-at-least-32-random-bytes".to_string());
                lines.push(String::new());
            }
        }
        AddFeature::Organizations => {
            if !existing.contains("JWT_SECRET") {
                lines.push("# Auth".to_string());
                lines.push("JWT_SECRET=replace-with-at-least-32-random-bytes".to_string());
                lines.push(String::new());
            }
            if !existing.contains("DATABASE_URL") {
                lines.push("# Database".to_string());
                lines.push(format!(
                    "DATABASE_URL=postgres://postgres:postgres@localhost:5432/{}",
                    project_name
                ));
                lines.push(String::new());
            }
        }
        _ => {}
    }

    write_file(&env_path, &lines.join("\n"))
        .with_context(|| format!("Failed to write {}", env_path.display()))?;
    Ok(())
}

fn scaffold_auth(
    project_dir: &Path,
    project_name: &str,
    project_name_pascal: &str,
    force: bool,
) -> Result<()> {
    let context = BackendTemplateContext {
        project_name: project_name.to_string(),
        project_name_pascal: project_name_pascal.to_string(),
        has_organizations: false,
        database: "postgres".to_string(),
        database_url: format!(
            "postgres://postgres:postgres@localhost:5432/{}",
            project_name
        ),
        is_sqlite_database: false,
        tideway_version: TIDEWAY_VERSION.to_string(),
        tideway_features: vec!["auth".to_string()],
        has_tideway_features: true,
        has_auth_feature: true,
        has_auth_mfa_feature: false,
        has_database_feature: false,
        has_billing_feature: false,
        has_openapi_feature: false,
        needs_arc: true,
        has_config: false,
    };

    let engine = BackendTemplateEngine::new(context)?;
    let auth_dir = project_dir.join("src").join("auth");

    write_file_with_force(
        &auth_dir.join("mod.rs"),
        &engine.render("starter/src/auth/mod.rs")?,
        force,
    )?;
    write_file_with_force(
        &auth_dir.join("provider.rs"),
        &engine.render("starter/src/auth/provider.rs")?,
        force,
    )?;
    write_file_with_force(
        &auth_dir.join("routes.rs"),
        &engine.render("starter/src/auth/routes.rs")?,
        force,
    )?;

    Ok(())
}

fn validate_organizations_preconditions(project_dir: &Path, db: bool) -> Result<()> {
    if !db {
        return Err(anyhow::anyhow!(error_contract(
            "Organizations backend scaffolding requires --db",
            "Run `tideway add organizations --wire --db`.",
            "For route-only CRUD, use `tideway resource organization --profile tenant`.",
        )));
    }

    let src_dir = project_dir.join("src");
    let actor_path = src_dir.join("auth/actor.rs");
    let user_path = src_dir.join("entities/user.rs");
    let migration_lib_path = project_dir.join("migration/src/lib.rs");
    let required = [&actor_path, &user_path, &migration_lib_path];

    let missing = required
        .iter()
        .filter(|path| !path.exists())
        .map(|path| {
            path.strip_prefix(project_dir)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect::<Vec<_>>();

    if !missing.is_empty() {
        return Err(anyhow::anyhow!(error_contract(
            &format!(
                "Organizations scaffold requires the DB-backed auth contract; missing {}",
                missing.join(", ")
            ),
            "Run this in a project generated by `tideway new --preset saas` or add the DB-backed auth/user scaffold first.",
            "For a lightweight organization-shaped resource, use `tideway resource organization --profile tenant`.",
        )));
    }

    if !project_dir
        .join("migration/src/m001_create_users.rs")
        .exists()
    {
        return Err(anyhow::anyhow!(error_contract(
            "Organizations DB scaffold requires migration/src/m001_create_users.rs",
            "Run this in a project with the DB-backed auth migrations already present.",
            "Use `tideway resource organization --profile tenant --wire --db --repo --service` for standalone CRUD scaffolding.",
        )));
    }

    let actor_contents = fs::read_to_string(&actor_path)
        .with_context(|| format!("Failed to read {}", actor_path.display()))?;
    let user_contents = fs::read_to_string(&user_path)
        .with_context(|| format!("Failed to read {}", user_path.display()))?;
    let migration_lib_contents = fs::read_to_string(&migration_lib_path)
        .with_context(|| format!("Failed to read {}", migration_lib_path.display()))?;

    let mut missing_contract = Vec::new();
    if !actor_contents.contains("for_organization_with_verifier")
        || !actor_contents.contains("require_org_role")
        || !actor_contents.contains("membership")
    {
        missing_contract.push("org-aware RequestActor helpers");
    }
    if !user_contents.contains("organization_id") {
        missing_contract.push("user.organization_id field");
    }
    if !migration_lib_contents.contains("mod m001_create_users;")
        || !migration_lib_contents.contains("Box::new(m001_create_users::Migration)")
    {
        missing_contract.push("registered m001_create_users migration");
    }
    if !has_registered_user_organization_id_migration(project_dir, &migration_lib_contents)? {
        missing_contract.push("registered users.organization_id migration");
    }

    if !missing_contract.is_empty() {
        return Err(anyhow::anyhow!(error_contract(
            &format!(
                "Organizations scaffold requires an org-aware DB-backed auth contract; missing {}",
                missing_contract.join(", ")
            ),
            "Run this in a B2B/SaaS backend scaffold, or upgrade auth/user/migrations to the organizations-aware contract first.",
            "For a lightweight organization-shaped resource, use `tideway resource organization --profile tenant`.",
        )));
    }

    Ok(())
}

fn has_registered_user_organization_id_migration(
    project_dir: &Path,
    migration_lib_contents: &str,
) -> Result<bool> {
    for migration in registered_migration_modules(migration_lib_contents) {
        let path = project_dir
            .join("migration/src")
            .join(format!("{migration}.rs"));
        if !path.exists() {
            continue;
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        if migration_adds_user_organization_id(&contents) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn registered_migration_modules(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("mod ") || !trimmed.ends_with(';') {
                return None;
            }

            let module = trimmed
                .trim_start_matches("mod ")
                .trim_end_matches(';')
                .trim();
            if contents.contains(&format!("Box::new({module}::Migration)")) {
                Some(module.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn migration_adds_user_organization_id(contents: &str) -> bool {
    let contents = strip_rust_comments(contents);
    let compact = contents.split_whitespace().collect::<String>();
    let targets_users_table = compact.contains(".table(Users::Table)");
    let adds_column = compact.contains(".add_column(");
    let organization_id_column = compact.contains("ColumnDef::new(Users::OrganizationId)")
        || compact.contains("ColumnDef::new(Alias::new(\"organization_id\"))")
        || compact.contains("ColumnDef::new(Iden::new(\"organization_id\"))");

    targets_users_table && adds_column && organization_id_column
}

fn strip_rust_comments(contents: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        LineComment,
        BlockComment,
        String,
    }

    let mut out = String::with_capacity(contents.len());
    let mut chars = contents.chars().peekable();
    let mut state = State::Normal;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        match state {
            State::Normal => match ch {
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    state = State::LineComment;
                    out.push(' ');
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    state = State::BlockComment;
                    out.push(' ');
                }
                '"' => {
                    state = State::String;
                    escaped = false;
                    out.push(ch);
                }
                _ => out.push(ch),
            },
            State::LineComment => {
                if ch == '\n' {
                    state = State::Normal;
                    out.push('\n');
                }
            }
            State::BlockComment => {
                if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    state = State::Normal;
                    out.push(' ');
                } else if ch == '\n' {
                    out.push('\n');
                }
            }
            State::String => {
                out.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    state = State::Normal;
                }
            }
        }
    }

    out
}

fn scaffold_organizations(
    project_dir: &Path,
    project_name: &str,
    project_name_pascal: &str,
    force: bool,
    db: bool,
) -> Result<()> {
    let context = BackendTemplateContext {
        project_name: project_name.to_string(),
        project_name_pascal: project_name_pascal.to_string(),
        has_organizations: true,
        database: "postgres".to_string(),
        database_url: format!(
            "postgres://postgres:postgres@localhost:5432/{}",
            project_name
        ),
        is_sqlite_database: false,
        tideway_version: TIDEWAY_VERSION.to_string(),
        tideway_features: vec![
            "auth".to_string(),
            "database".to_string(),
            "organizations".to_string(),
            "organizations-seaorm".to_string(),
        ],
        has_tideway_features: true,
        has_auth_feature: true,
        has_auth_mfa_feature: false,
        has_database_feature: true,
        has_billing_feature: false,
        has_openapi_feature: false,
        needs_arc: true,
        has_config: false,
    };

    let engine = BackendTemplateEngine::new(context)?;
    let src_dir = project_dir.join("src");
    let org_dir = src_dir.join("organizations");
    ensure_dir(&org_dir).with_context(|| format!("Failed to create {}", org_dir.display()))?;

    write_file_with_force(
        &org_dir.join("mod.rs"),
        &engine.render("organizations/mod")?,
        force,
    )?;
    write_file_with_force(
        &org_dir.join("routes.rs"),
        &engine.render("organizations/routes")?,
        force,
    )?;

    if db {
        let entities_dir = src_dir.join("entities");
        ensure_dir(&entities_dir)
            .with_context(|| format!("Failed to create {}", entities_dir.display()))?;
        write_file_with_force(
            &entities_dir.join("organization.rs"),
            &engine.render("entities/organization")?,
            force,
        )?;
        write_file_with_force(
            &entities_dir.join("organization_member.rs"),
            &engine.render("entities/organization_member")?,
            force,
        )?;
        ensure_entities_mod_decl(&entities_dir.join("mod.rs"), "organization")?;
        ensure_entities_mod_decl(&entities_dir.join("mod.rs"), "organization_member")?;

        let migrations_dir = project_dir.join("migration/src");
        ensure_dir(&migrations_dir)
            .with_context(|| format!("Failed to create {}", migrations_dir.display()))?;
        write_file_with_force(
            &migrations_dir.join("m005_create_organizations.rs"),
            &engine.render("migrations/m005_create_organizations")?,
            force,
        )?;
        write_file_with_force(
            &migrations_dir.join("m006_create_organization_members.rs"),
            &engine.render("migrations/m006_create_organization_members")?,
            force,
        )?;
        ensure_migration_registered(&migrations_dir.join("lib.rs"), "m005_create_organizations")?;
        ensure_migration_registered(
            &migrations_dir.join("lib.rs"),
            "m006_create_organization_members",
        )?;
    }

    Ok(())
}

fn ensure_entities_mod_decl(path: &Path, module: &str) -> Result<()> {
    let contents = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?
    } else {
        "//! Database entities.\n\n".to_string()
    };

    let updated = ensure_module_decl(&contents, module);
    write_file(path, &updated).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn ensure_migration_registered(path: &Path, migration: &str) -> Result<()> {
    let mut contents = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?
    } else {
        "//! Database migrations.\n\npub use sea_orm_migration::prelude::*;\n\npub struct Migrator;\n\n#[async_trait::async_trait]\nimpl MigratorTrait for Migrator {\n    fn migrations() -> Vec<Box<dyn MigrationTrait>> {\n        vec![\n        ]\n    }\n}\n".to_string()
    };

    let mod_line = format!("mod {migration};");
    if !contents.contains(&mod_line) {
        if let Some(insert_at) = contents.find("pub struct Migrator") {
            contents.insert_str(insert_at, &format!("{mod_line}\n"));
        } else {
            contents.push_str(&format!("\n{mod_line}\n"));
        }
    }

    let migration_entry = format!("Box::new({migration}::Migration)");
    if !contents.contains(&migration_entry) {
        let insert_at = find_migrations_vec_close(&contents).ok_or_else(|| {
            anyhow::anyhow!(error_contract(
                &format!("Could not register migration `{migration}` in migration/src/lib.rs"),
                "Expected a `fn migrations()` implementation that returns a `vec![...]` migration list.",
                "Add the migration module and `Box::new(...::Migration)` entry manually, then rerun if needed.",
            ))
        })?;
        contents.insert_str(insert_at, &format!("            {migration_entry},\n"));
    }

    write_file(path, &contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn find_migrations_vec_close(contents: &str) -> Option<usize> {
    let migrations_fn = contents.find("fn migrations()")?;
    let vec_pos = find_token_outside_comments_and_strings(contents, migrations_fn, "vec![")?;
    let open_bracket = contents[vec_pos..].find('[')? + vec_pos;
    find_matching_bracket(contents, open_bracket)
}

fn find_token_outside_comments_and_strings(
    contents: &str,
    start: usize,
    token: &str,
) -> Option<usize> {
    let bytes = contents.as_bytes();
    let token = token.as_bytes();
    let mut i = start;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape = false;

    while i < bytes.len() {
        if !in_single_quote
            && !in_double_quote
            && i + token.len() <= bytes.len()
            && &bytes[i..i + token.len()] == token
        {
            return Some(i);
        }

        let b = bytes[i];

        if !in_single_quote
            && !in_double_quote
            && i + 1 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'/'
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if !in_single_quote
            && !in_double_quote
            && i + 1 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'*'
        {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        if escape {
            escape = false;
            i += 1;
            continue;
        }

        if in_single_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'\'' {
                in_single_quote = false;
            }
            i += 1;
            continue;
        }

        if in_double_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_double_quote = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            _ => {}
        }

        i += 1;
    }

    None
}

fn find_matching_bracket(contents: &str, open_bracket: usize) -> Option<usize> {
    let bytes = contents.as_bytes();
    if bytes.get(open_bracket) != Some(&b'[') {
        return None;
    }

    let mut i = open_bracket;
    let mut depth = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape = false;

    while i < bytes.len() {
        let b = bytes[i];

        if !in_single_quote
            && !in_double_quote
            && i + 1 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'/'
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if !in_single_quote
            && !in_double_quote
            && i + 1 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'*'
        {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        if escape {
            escape = false;
            i += 1;
            continue;
        }

        if in_single_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'\'' {
                in_single_quote = false;
            }
            i += 1;
            continue;
        }

        if in_double_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_double_quote = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            b'[' => depth += 1,
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }

        i += 1;
    }

    None
}

fn wire_organizations_in_main(project_dir: &Path) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    let needs_module_init = !contents.contains("let organization_module");
    let db_var = if needs_module_init {
        match find_database_connection_var(&contents) {
            Some(var) => Some(var),
            None => {
                print_warning(
                    "Could not find a SeaORM database connection variable in src/main.rs; skipping organizations auto-wiring",
                );
                return Ok(());
            }
        }
    } else {
        None
    };

    contents = ensure_module_decl(&contents, "organizations");
    contents = ensure_use_line(
        contents,
        "use crate::organizations::OrganizationModule;",
        "use crate::",
    );

    if let Some(db_var) = db_var {
        contents = ensure_use_line(contents, "use std::sync::Arc;", "use tideway::");
        let block = format!(
            "    let organization_module = OrganizationModule::new(\n        Arc::new({db_var}.clone()),\n        std::env::var(\"JWT_SECRET\").expect(\"JWT_SECRET is not set\"),\n    );\n\n"
        );
        let Some(updated) = insert_before_any_app_builder(contents, &block)? else {
            print_warning("Could not find app builder; skipping organizations auto-wiring");
            return Ok(());
        };
        contents = updated;
    }

    if !contents.contains("register_module(organization_module)") {
        let (updated, registered) = insert_organization_into_app_builder(contents)?;
        if !registered {
            print_warning("Could not find app builder; skipping organizations auto-wiring");
            return Ok(());
        }
        contents = updated;
    }

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired organizations into src/main.rs");
    Ok(())
}

fn find_database_connection_var(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("let ") {
            continue;
        }

        let Some((binding, expression)) = trimmed.split_once('=') else {
            continue;
        };

        if !expression.contains("sea_orm::Database::connect")
            && !expression.contains("Database::connect")
        {
            continue;
        }

        let binding = binding.trim_start_matches("let ").trim();
        let binding = binding.strip_prefix("mut ").unwrap_or(binding).trim();
        let name = binding.split(':').next().unwrap_or(binding).trim();
        if is_rust_identifier(name) {
            return Some(name.to_string());
        }
    }

    None
}

fn is_rust_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn insert_organization_into_app_builder(mut contents: String) -> Result<(String, bool)> {
    let insert = ".register_module(organization_module)";
    if let Some((start, end)) = find_app_builder_marker_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok((contents, true));
        }
        print_warning("Could not update app builder; skipping organizations module registration");
        return Ok((contents, false));
    }

    if let Some((start, end)) = find_unmarked_app_builder_statement_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok((contents, true));
        }
        print_warning("Could not update app builder; skipping organizations module registration");
        return Ok((contents, false));
    }

    if let Some((start, end)) = find_fluent_app_builder_statement_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok((contents, true));
        }
        print_warning("Could not update app builder; skipping organizations module registration");
        return Ok((contents, false));
    }

    print_warning("Could not find app builder; skipping organizations module registration");
    Ok((contents, false))
}

fn wire_auth_in_main(project_dir: &Path, project_name: &str) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    contents = ensure_module_decl(&contents, "auth");

    contents = ensure_use_line(contents, "use axum::Extension;", "use tideway::auth");
    contents = ensure_use_line(
        contents,
        "use crate::auth::{AuthModule, SimpleAuthProvider};",
        "use tideway::auth",
    );
    contents = ensure_use_line(contents, "use std::sync::Arc;", "use tideway::");
    contents = ensure_use_line(
        contents,
        "use tideway::auth::{JwtIssuer, JwtIssuerConfig};",
        "use tideway::auth",
    );

    let has_jwt_secret = contents.contains("let jwt_secret");
    let has_jwt_issuer = contents.contains("let jwt_issuer");
    let has_auth_provider = contents.contains("auth_provider");
    let has_auth_module = contents.contains("auth_module");

    if has_jwt_secret && has_jwt_issuer {
        if (!has_auth_provider || !has_auth_module)
            && let Some(insert_at) = contents.find("let jwt_issuer")
        {
            let after = contents[insert_at..]
                .find(";\n")
                .map(|idx| insert_at + idx + 2)
                .unwrap_or(insert_at);
            let insert = "    let auth_provider = SimpleAuthProvider::from_secret(&jwt_secret);\n    let auth_module = AuthModule::new(jwt_issuer.clone());\n".to_string();
            contents.insert_str(after, &insert);
        }
    } else {
        let block = format!(
            "    let jwt_secret = std::env::var(\"JWT_SECRET\").expect(\"JWT_SECRET is not set\");\n    let jwt_issuer = Arc::new(JwtIssuer::new(JwtIssuerConfig::with_secure_secret(\n        &jwt_secret,\n        \"{}\",\n    ).expect(\"JWT_SECRET must be at least 32 bytes\").audience(env!(\"CARGO_PKG_NAME\"))).expect(\"Failed to create JWT issuer\"));\n    let auth_provider = SimpleAuthProvider::from_secret(&jwt_secret);\n    let auth_module = AuthModule::new(jwt_issuer.clone());\n\n",
            project_name
        );
        if let Some(updated) = insert_before_app_builder(contents, &block)? {
            contents = updated;
        } else {
            print_warning("Could not find app builder; skipping auth wiring");
            return Ok(());
        }
    }

    contents = insert_auth_into_app_builder(contents)?;

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired auth into src/main.rs");
    Ok(())
}

pub fn wire_database_in_main(project_dir: &Path) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if !contents.contains("async fn main") {
        print_warning("main.rs is not async; skipping database wiring");
        return Ok(());
    }

    let has_database_block = contents.contains("DATABASE_URL")
        || contents.contains("sea_orm::Database::connect")
        || contents.contains("with_database");
    let has_database_context = contents.contains(".with_database(");

    if has_database_block && has_database_context {
        return Ok(());
    }

    contents = ensure_use_line(
        contents,
        "use tideway::{AppContext, SeaOrmPool};",
        "use tideway::",
    );
    contents = ensure_use_line(contents, "use std::sync::Arc;", "use tideway::");

    if !has_database_block {
        let block = "    let database_url = std::env::var(\"DATABASE_URL\").expect(\"DATABASE_URL is not set\");\n    let db = sea_orm::Database::connect(&database_url)\n        .await\n        .expect(\"Failed to connect to database\");\n\n";
        if let Some(updated) = insert_before_app_builder(contents, block)? {
            contents = updated;
        } else {
            print_warning("Could not find app builder; skipping database wiring");
            return Ok(());
        }
    }

    if !contents.contains(".with_database(") {
        contents = insert_database_into_app_builder(contents)?;
    }

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired database into src/main.rs");
    Ok(())
}

fn ensure_use_line(mut contents: String, line: &str, anchor: &str) -> String {
    if contents.contains(line) {
        return contents;
    }

    if let Some(pos) = contents.find(anchor) {
        let mut insert_at = pos;
        let mut lines = contents[pos..].split_inclusive('\n');

        if let Some(first_line) = lines.next() {
            insert_at += first_line.len();
            let mut in_group = first_line.contains('{') && !first_line.trim_end().ends_with("};");

            while in_group {
                let Some(group_line) = lines.next() else {
                    break;
                };
                insert_at += group_line.len();
                if group_line.trim_end().ends_with("};") {
                    in_group = false;
                }
            }

            contents.insert_str(insert_at, &format!("{}\n", line));
            return contents;
        }
    }

    contents = format!("{}\n{}", line, contents);
    contents
}

fn insert_before_app_builder(mut contents: String, block: &str) -> Result<Option<String>> {
    if let Some((start, _)) = find_app_builder_marker_range(&contents) {
        contents.insert_str(start, block);
        return Ok(Some(contents));
    }

    if let Some((start, _)) = find_unmarked_app_builder_statement_range(&contents) {
        contents.insert_str(start, block);
        return Ok(Some(contents));
    }

    Ok(None)
}

fn insert_before_any_app_builder(mut contents: String, block: &str) -> Result<Option<String>> {
    if let Some(updated) = insert_before_app_builder(contents.clone(), block)? {
        return Ok(Some(updated));
    }

    if let Some((start, _)) = find_fluent_app_builder_statement_range(&contents) {
        contents.insert_str(start, block);
        return Ok(Some(contents));
    }

    Ok(None)
}

fn find_fluent_app_builder_statement_range(contents: &str) -> Option<(usize, usize)> {
    let mut search_from = 0;
    for needle in ["App::with_config(", "App::new()"] {
        while let Some(rel_pos) = contents[search_from..].find(needle) {
            let abs_pos = search_from + rel_pos;
            let line_start = contents[..abs_pos]
                .rfind('\n')
                .map(|idx| idx + 1)
                .unwrap_or(0);
            let line = contents[line_start..]
                .lines()
                .next()
                .unwrap_or("")
                .trim_start();
            if line.starts_with(needle)
                && let Some(end) = find_statement_terminator(contents, line_start)
            {
                return Some((line_start, end));
            }
            search_from = abs_pos + needle.len();
        }
        search_from = 0;
    }

    None
}

fn insert_auth_into_app_builder(mut contents: String) -> Result<String> {
    if contents.contains("register_module(auth_module)") {
        return Ok(contents);
    }

    let insert = ".with_global_layer(Extension(auth_provider))\n.register_module(auth_module)";
    if let Some((start, end)) = find_app_builder_marker_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping auth module registration");
        return Ok(contents);
    }

    if let Some((start, end)) = find_unmarked_app_builder_statement_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping auth module registration");
        return Ok(contents);
    }

    print_warning("Could not find app builder; skipping auth module registration");
    Ok(contents)
}

fn insert_database_into_app_builder(mut contents: String) -> Result<String> {
    if contents.contains(".with_database(") {
        return Ok(contents);
    }

    let insert = ".with_context(\n    AppContext::builder()\n        .with_database(Arc::new(SeaOrmPool::new(db, database_url)))\n        .build()\n)";

    if let Some((start, end)) = find_app_builder_marker_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping database wiring");
        return Ok(contents);
    }

    if let Some((start, end)) = find_unmarked_app_builder_statement_range(&contents) {
        let statement = &contents[start..=end];
        if let Some(updated) = insert_snippet_into_builder_block(statement, insert) {
            contents.replace_range(start..=end, &updated);
            return Ok(contents);
        }
        print_warning("Could not update app builder; skipping database wiring");
        return Ok(contents);
    }

    print_warning("Could not find app builder; skipping database wiring");
    Ok(contents)
}

fn wire_openapi_in_main(project_dir: &Path) -> Result<()> {
    let main_path = project_dir.join("src").join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto-wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if contents.contains("openapi::create_openapi_router")
        || contents.contains("openapi_merge_module")
    {
        print_info("OpenAPI already appears wired in main.rs");
        return Ok(());
    }

    contents = ensure_use_line(contents, "use tideway::ConfigBuilder;", "use tideway::");
    if contents.contains("mod config;") {
        contents = ensure_use_line(contents, "use crate::config::AppConfig;", "use tideway::");
    }
    contents = ensure_use_line(contents, "use tideway::openapi;", "use tideway::");

    if !contents.contains("mod openapi_docs;") {
        contents = ensure_module_decl(&contents, "openapi_docs");
    }

    let has_config_var = contents.contains("let config = ConfigBuilder::new()")
        || contents.contains("let config = AppConfig::from_env()");
    let config_available =
        contents.contains("ConfigBuilder::new()") || contents.contains("AppConfig::from_env()");

    if !has_config_var && config_available {
        let config_block = "    let config = ConfigBuilder::new()\n        .from_env()\n        .build()\n        .expect(\"Invalid TIDEWAY_* config\");\n\n";
        if let Some(updated) = insert_before_app_builder(contents, config_block)? {
            contents = updated;
        } else {
            print_warning("Could not find app builder; skipping OpenAPI wiring");
            return Ok(());
        }
    }

    if contents.contains("let config = AppConfig::from_env()") {
        contents = insert_openapi_into_app_builder(contents, "config.tideway")?;
    } else {
        contents = insert_openapi_into_app_builder(contents, "config")?;
    }

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Wired OpenAPI into src/main.rs");
    Ok(())
}

fn insert_openapi_into_app_builder(mut contents: String, config_ref: &str) -> Result<String> {
    if contents.contains("create_openapi_router") {
        return Ok(contents);
    }

    if let Some(pos) = find_app_builder_start(&contents) {
        let app_var =
            find_app_builder_var_name(&contents, pos).unwrap_or_else(|| "app".to_string());
        // Insert after app builder block to keep code readable.
        if let Some(insert_at) = find_app_builder_end_insert_at(&contents, pos) {
            let block = format!(
                "\n    if {config_ref}.openapi.enabled {{\n        let openapi = tideway::openapi_merge_module!(openapi_docs, ApiDoc);\n        let openapi_router = tideway::openapi::create_openapi_router(openapi, &{config_ref}.openapi);\n        {app_var} = {app_var}.merge_router(openapi_router);\n    }}\n"
            );
            contents.insert_str(insert_at, &block);
        } else {
            print_warning("Could not find app builder termination; skipping OpenAPI wiring");
        }
        Ok(contents)
    } else {
        print_warning("Could not find app builder; skipping OpenAPI wiring");
        Ok(contents)
    }
}

fn ensure_openapi_docs_file(project_dir: &Path) -> Result<()> {
    let docs_path = project_dir.join("src").join("openapi_docs.rs");
    if docs_path.exists() {
        return Ok(());
    }

    let contents = r#"tideway::openapi_doc!(pub(crate) ApiDoc, paths());
"#;

    if let Some(parent) = docs_path.parent() {
        ensure_dir(parent).with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    write_file(&docs_path, contents)
        .with_context(|| format!("Failed to write {}", docs_path.display()))?;
    print_success("Created src/openapi_docs.rs");
    Ok(())
}

fn project_name_from_cargo(contents: &str, project_dir: &Path) -> String {
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|doc| doc["package"]["name"].as_str().map(|s| s.to_string()));

    doc.unwrap_or_else(|| {
        project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my_app")
            .to_string()
    })
    .replace('-', "_")
}

pub fn array_value(values: &[&str]) -> toml_edit::Value {
    let mut array = toml_edit::Array::new();
    for value in values {
        array.push(*value);
    }
    toml_edit::Value::Array(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_cargo_toml_rejects_non_table_dependencies() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Cargo.toml");
        let error = update_cargo_toml(
            &path,
            "dependencies = \"invalid\"\n\n[package]\nname = \"example\"\nversion = \"0.1.0\"\n",
            AddFeature::Auth,
        )
        .expect_err("invalid dependencies should be rejected");

        assert!(
            error
                .to_string()
                .contains("[dependencies] must be a TOML table")
        );
    }

    #[test]
    fn update_cargo_toml_rejects_non_array_tideway_features() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Cargo.toml");
        let error = update_cargo_toml(
            &path,
            "[package]\nname = \"example\"\nversion = \"0.1.0\"\n\n[dependencies]\ntideway = { version = \"0.7\", features = \"auth\" }\n",
            AddFeature::Auth,
        )
        .expect_err("invalid Tideway features should be rejected");

        assert!(
            error
                .to_string()
                .contains("dependencies.tideway.features must be an array")
        );
    }
}
