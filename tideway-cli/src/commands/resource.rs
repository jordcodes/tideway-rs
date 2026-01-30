//! Resource command - generate CRUD modules for API development.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{DbBackend, ResourceArgs};
use crate::commands::add::wire_database_in_main;
use crate::{print_info, print_success, print_warning};

pub fn run(args: ResourceArgs) -> Result<()> {
    let project_dir = PathBuf::from(&args.path);
    let src_dir = project_dir.join("src");
    if !src_dir.exists() {
        return Err(anyhow::anyhow!("src/ not found in {}", project_dir.display()));
    }

    let resource_name = normalize_name(&args.name);
    let resource_pascal = to_pascal_case(&resource_name);
    let resource_plural = pluralize(&resource_name);

    let cargo_path = project_dir.join("Cargo.toml");
    let has_openapi = has_feature(&cargo_path, "openapi");
    let has_database = has_feature(&cargo_path, "database");

    let routes_dir = src_dir.join("routes");
    fs::create_dir_all(&routes_dir)
        .with_context(|| format!("Failed to create {}", routes_dir.display()))?;

    let resource_path = routes_dir.join(format!("{}.rs", resource_name));
    let contents = render_resource_module(
        &resource_pascal,
        &resource_name,
        &resource_plural,
        args.with_tests,
        has_openapi,
        args.db,
        args.repo,
        args.service,
    );
    write_file(&resource_path, &contents, false)?;

    if args.wire {
        wire_routes_mod(&routes_dir, &resource_name)?;
        wire_main_rs(&src_dir, &resource_name, &resource_pascal)?;
        if has_openapi {
            wire_openapi_docs(&src_dir, &resource_name, &resource_plural)?;
        }
    } else {
        print_info("Next steps: add the module to routes/mod.rs and register it in main.rs");
    }

    if args.repo && !args.db {
        return Err(anyhow::anyhow!(
            "Repository scaffolding requires --db (run `tideway resource {} --db --repo`)",
            resource_name
        ));
    }

    if args.repo_tests && !args.repo {
        return Err(anyhow::anyhow!(
            "Repository tests require --repo (run `tideway resource {} --db --repo --repo-tests`)",
            resource_name
        ));
    }

    if args.service && !args.repo {
        return Err(anyhow::anyhow!(
            "Service scaffolding requires --repo (run `tideway resource {} --db --repo --service`)",
            resource_name
        ));
    }

    if args.db {
        if !has_database {
            return Err(anyhow::anyhow!(
                "Database scaffolding requires the Tideway `database` feature (run `tideway add database`)"
            ));
        }
        if !has_dependency(&cargo_path, "sea-orm") {
            return Err(anyhow::anyhow!(
                "SeaORM dependency not found (run `tideway add database`)"
            ));
        }
        let backend = resolve_db_backend(&project_dir, args.db_backend)?;
        match backend {
            DbBackend::SeaOrm => generate_sea_orm_scaffold(
                &project_dir,
                &resource_name,
                &resource_plural,
            )?,
            DbBackend::Auto => {
                return Err(anyhow::anyhow!(
                    "Unable to detect database backend (use --db-backend)"
                ));
            }
        }

        if args.repo {
            generate_repository(&project_dir, &resource_name)?;
            if args.repo_tests {
                let project_name = project_name_from_cargo(&cargo_path, &project_dir);
                generate_repository_tests(&project_dir, &project_name, &resource_name)?;
            }
            if args.service {
                generate_service(&project_dir, &resource_name)?;
            }
        }

        if args.wire {
            wire_database_in_main(&project_dir)?;
            wire_entities_in_main(&src_dir)?;
            if args.repo {
                wire_repositories_in_main(&src_dir)?;
            }
            if args.service {
                wire_services_in_main(&src_dir)?;
            }
        } else {
            print_info("Next steps: wire database into main.rs (tideway add database --wire)");
        }
    }

    if args.with_tests {
        print_info("Added unit tests to the resource module");
    }

    print_success(&format!("Generated {} resource", resource_name));
    Ok(())
}

fn resolve_db_backend(project_dir: &Path, backend: DbBackend) -> Result<DbBackend> {
    match backend {
        DbBackend::Auto => detect_db_backend(project_dir),
        DbBackend::SeaOrm => Ok(DbBackend::SeaOrm),
    }
}

fn detect_db_backend(project_dir: &Path) -> Result<DbBackend> {
    let cargo_path = project_dir.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    let deps = doc.get("dependencies");
    let has_sea_orm = deps
        .and_then(|deps| deps.get("sea-orm"))
        .is_some();
    let has_tideway_db = deps
        .and_then(|deps| deps.get("tideway"))
        .and_then(|item| item.get("features"))
        .and_then(|item| item.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some("database")))
        .unwrap_or(false);

    if has_sea_orm || has_tideway_db {
        Ok(DbBackend::SeaOrm)
    } else {
        Err(anyhow::anyhow!(
            "Could not detect database backend (add sea-orm or pass --db-backend)"
        ))
    }
}

fn render_resource_module(
    resource_pascal: &str,
    resource_name: &str,
    resource_plural: &str,
    with_tests: bool,
    has_openapi: bool,
    with_db: bool,
    with_repo: bool,
    with_service: bool,
) -> String {
    let body_extractor = "Json(body): Json<CreateRequest>";
    let tests_block = if with_tests {
        format!(
            r#"

#[cfg(test)]
mod tests {{
    use super::*;
    use tideway::testing::{{get, post}};
    use tideway::App;

    #[tokio::test]
    async fn list_{resource_plural}_ok() {{
        let app = App::new()
            .register_module({resource_pascal}Module)
            .into_router();

        get(app, "/api/{resource_plural}")
            .execute()
            .await
            .assert_ok();
    }}

    #[tokio::test]
    async fn create_{resource_name}_ok() {{
        let app = App::new()
            .register_module({resource_pascal}Module)
            .into_router();

        post(app, "/api/{resource_plural}")
            .with_json(&serde_json::json!({{ "name": "Example" }}))
            .execute()
            .await
            .assert_ok();
    }}
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };
    let openapi_import = if has_openapi {
        "use utoipa::ToSchema;\n"
    } else {
        ""
    };

    let openapi_schema = if has_openapi {
        "#[derive(ToSchema)]"
    } else {
        ""
    };

    let openapi_paths = if has_openapi {
        format!(
            r#"
#[cfg(feature = "openapi")]
mod openapi_docs {{
    use super::*;
    use utoipa::OpenApi;

    #[derive(OpenApi)]
    #[openapi(
        paths(
            list_{resource_plural},
            get_{resource_name},
            create_{resource_name},
            update_{resource_name},
            delete_{resource_name}
        ),
        components(schemas({resource_pascal}, CreateRequest, UpdateRequest))
    )]
    pub struct {resource_pascal}Api;
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let openapi_attrs = if has_openapi {
        format!(
            r#"
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/{resource_plural}",
    responses((status = 200, body = [{resource_pascal}]))
))]
"#,
            resource_plural = resource_plural,
            resource_pascal = resource_pascal,
        )
    } else {
        String::new()
    };

    let openapi_attrs_get = if has_openapi {
        format!(
            r#"
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/{resource_plural}/{{id}}",
    responses((status = 200, body = {resource_pascal}))
))]
"#,
            resource_plural = resource_plural,
            resource_pascal = resource_pascal,
        )
    } else {
        String::new()
    };

    let openapi_attrs_create = if has_openapi {
        format!(
            r#"
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/{resource_plural}",
    request_body = CreateRequest,
    responses((status = 200, body = MessageResponse))
))]
"#,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let openapi_attrs_update = if has_openapi {
        format!(
            r#"
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/{resource_plural}/{{id}}",
    request_body = UpdateRequest,
    responses((status = 200, body = MessageResponse))
))]
"#,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let openapi_attrs_delete = if has_openapi {
        format!(
            r#"
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/{resource_plural}/{{id}}",
    responses((status = 200, body = MessageResponse))
))]
"#,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let extract_import = if with_db {
        "extract::{Path, State}, "
    } else {
        ""
    };
    let sea_orm_imports = if with_db {
        "use sea_orm::{ActiveModelTrait, EntityTrait, Set};\n"
    } else {
        ""
    };
    let entities_import = if with_db {
        format!("use crate::entities::{resource_name};\n")
    } else {
        String::new()
    };
    let repositories_import = if with_repo {
        format!("use crate::repositories::{resource_name}::{resource_pascal}Repository;\n")
    } else {
        String::new()
    };
    let services_import = if with_service {
        format!("use crate::services::{resource_name}::{resource_pascal}Service;\n")
    } else {
        String::new()
    };

    let handlers = if with_db && with_repo && with_service {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(State(ctx): State<AppContext>) -> Result<Json<Vec<{resource_pascal}>>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    let models = service.list().await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
            id: model.id.to_string(),
            name: model.name,
        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
) -> Result<Json<{resource_pascal}>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    let model = service
        .get(id)
        .await?
        .ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    Ok(Json({resource_pascal} {{
        id: model.id.to_string(),
        name: model.name,
    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    {body_extractor},
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    service.create(body.name).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    service.update(id, body.name).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    service.delete(id).await?;
    Ok(MessageResponse::success("Deleted"))
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
            openapi_attrs = openapi_attrs,
            openapi_attrs_get = openapi_attrs_get,
            openapi_attrs_create = openapi_attrs_create,
            openapi_attrs_update = openapi_attrs_update,
            openapi_attrs_delete = openapi_attrs_delete,
            body_extractor = body_extractor,
        )
    } else if with_db && with_repo {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(State(ctx): State<AppContext>) -> Result<Json<Vec<{resource_pascal}>>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let models = repo.list().await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
            id: model.id.to_string(),
            name: model.name,
        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
) -> Result<Json<{resource_pascal}>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let model = repo
        .get(id)
        .await?
        .ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    Ok(Json({resource_pascal} {{
        id: model.id.to_string(),
        name: model.name,
    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    {body_extractor},
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    repo.create(body.name).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    repo.update(id, body.name).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    repo.delete(id).await?;
    Ok(MessageResponse::success("Deleted"))
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
            openapi_attrs = openapi_attrs,
            openapi_attrs_get = openapi_attrs_get,
            openapi_attrs_create = openapi_attrs_create,
            openapi_attrs_update = openapi_attrs_update,
            openapi_attrs_delete = openapi_attrs_delete,
            body_extractor = body_extractor,
        )
    } else if with_db {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(State(ctx): State<AppContext>) -> Result<Json<Vec<{resource_pascal}>>> {{
    let db = ctx.sea_orm_connection()?;
    let models = {resource_name}::Entity::find().all(&db).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
            id: model.id.to_string(),
            name: model.name,
        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
) -> Result<Json<{resource_pascal}>> {{
    let db = ctx.sea_orm_connection()?;
    let model = {resource_name}::Entity::find_by_id(id).one(&db).await?;
    let model = model.ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    Ok(Json({resource_pascal} {{
        id: model.id.to_string(),
        name: model.name,
    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    {body_extractor},
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let active = {resource_name}::ActiveModel {{
        name: Set(body.name),
        ..Default::default()
    }};
    active.insert(&db).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let model = {resource_name}::Entity::find_by_id(id).one(&db).await?;
    let model = model.ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    let mut active: {resource_name}::ActiveModel = model.into();
    if let Some(name) = body.name {{
        active.name = Set(name);
    }}
    active.update(&db).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<i32>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    {resource_name}::Entity::delete_by_id(id).exec(&db).await?;
    Ok(MessageResponse::success("Deleted"))
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
            openapi_attrs = openapi_attrs,
            openapi_attrs_get = openapi_attrs_get,
            openapi_attrs_create = openapi_attrs_create,
            openapi_attrs_update = openapi_attrs_update,
            openapi_attrs_delete = openapi_attrs_delete,
            body_extractor = body_extractor,
        )
    } else {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}() -> Json<Vec<{resource_pascal}>> {{
    Json(Vec::new())
}}

{openapi_attrs_get}
async fn get_{resource_name}() -> Result<Json<{resource_pascal}>> {{
    Ok(Json({resource_pascal} {{
        id: "demo".to_string(),
        name: "{resource_pascal}".to_string(),
    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}({body_extractor}) -> Result<MessageResponse> {{
    Ok(MessageResponse::success(format!("Created {{}}", body.name)))
}}

{openapi_attrs_update}
async fn update_{resource_name}({body_extractor}) -> Result<MessageResponse> {{
    let name = body.name.unwrap_or_else(|| "{resource_pascal}".to_string());
    Ok(MessageResponse::success(format!("Updated {{}}", name)))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}() -> Result<MessageResponse> {{
    Ok(MessageResponse::success("Deleted"))
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
            openapi_attrs = openapi_attrs,
            openapi_attrs_get = openapi_attrs_get,
            openapi_attrs_create = openapi_attrs_create,
            openapi_attrs_update = openapi_attrs_update,
            openapi_attrs_delete = openapi_attrs_delete,
            body_extractor = body_extractor,
        )
    };

    format!(
        r#"//! {resource_pascal} routes.

use axum::{{routing::{{delete, get, post, put}}, {extract_import}Json, Router}};
use serde::{{Deserialize, Serialize}};
use tideway::{{AppContext, MessageResponse, Result, RouteModule}};
{openapi_import}
{sea_orm_imports}
{entities_import}
{repositories_import}
{services_import}

pub struct {resource_pascal}Module;

impl RouteModule for {resource_pascal}Module {{
    fn routes(&self) -> Router<AppContext> {{
        Router::new()
            .route("/", get(list_{resource_plural}).post(create_{resource_name}))
            .route("/:id", get(get_{resource_name}).put(update_{resource_name}).delete(delete_{resource_name}))
    }}

    fn prefix(&self) -> Option<&str> {{
        Some("/api/{resource_plural}")
    }}
}}

#[derive(Debug, Serialize)]
{openapi_schema}
pub struct {resource_pascal} {{
    pub id: String,
    pub name: String,
}}

#[derive(Deserialize)]
{openapi_schema}
pub struct CreateRequest {{
    pub name: String,
}}

#[derive(Deserialize)]
{openapi_schema}
pub struct UpdateRequest {{
    pub name: Option<String>,
}}

{handlers}
{tests_block}
{openapi_paths}
"#,
        resource_pascal = resource_pascal,
        resource_name = resource_name,
        resource_plural = resource_plural,
        tests_block = tests_block,
        openapi_import = openapi_import,
        openapi_schema = openapi_schema,
        openapi_paths = openapi_paths,
        handlers = handlers,
        extract_import = extract_import,
        sea_orm_imports = sea_orm_imports,
        entities_import = entities_import,
        repositories_import = repositories_import,
        services_import = services_import,
    )
}

fn wire_openapi_docs(src_dir: &Path, resource_name: &str, resource_plural: &str) -> Result<()> {
    let docs_path = src_dir.join("openapi_docs.rs");
    let paths = [
        format!("crate::routes::{resource_name}::list_{resource_plural}"),
        format!("crate::routes::{resource_name}::get_{resource_name}"),
        format!("crate::routes::{resource_name}::create_{resource_name}"),
        format!("crate::routes::{resource_name}::update_{resource_name}"),
        format!("crate::routes::{resource_name}::delete_{resource_name}"),
    ];

    if !docs_path.exists() {
        let contents = render_openapi_docs_file(&paths);
        write_file(&docs_path, &contents, false)?;
        print_success("Created src/openapi_docs.rs");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&docs_path)
        .with_context(|| format!("Failed to read {}", docs_path.display()))?;

    if !contents.contains("openapi_doc!") || !contents.contains("paths(") {
        print_warning("Could not find OpenAPI doc paths; skipping openapi_docs.rs update");
        return Ok(());
    }

    if paths.iter().all(|path| contents.contains(path)) {
        return Ok(());
    }

    let mut lines = contents.lines().map(|line| line.to_string()).collect::<Vec<_>>();
    let mut start = None;
    let mut end = None;

    for (idx, line) in lines.iter().enumerate() {
        if start.is_none() && line.contains("paths(") {
            start = Some(idx);
            continue;
        }
        if start.is_some() && line.trim_start().starts_with(")") {
            end = Some(idx);
            break;
        }
    }

    let (start, mut end) = match (start, end) {
        (Some(start), Some(end)) if end > start => (start, end),
        _ => {
            print_warning("Could not locate OpenAPI paths block; skipping openapi_docs.rs update");
            return Ok(());
        }
    };

    let base_indent = lines[start]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect::<String>();
    let entry_indent = format!("{base_indent}    ");

    for path in paths {
        if contents.contains(&path) {
            continue;
        }
        lines.insert(end, format!("{entry_indent}{path},"));
        end += 1;
    }

    contents = lines.join("\n");
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    fs::write(&docs_path, contents)
        .with_context(|| format!("Failed to write {}", docs_path.display()))?;
    print_success("Updated src/openapi_docs.rs");
    Ok(())
}

fn wire_entities_in_main(src_dir: &Path) -> Result<()> {
    let main_path = src_dir.join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping entities wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if contents.contains("mod entities;") {
        return Ok(());
    }

    if contents.contains("mod routes;") {
        contents = contents.replace("mod routes;\n", "mod routes;\nmod entities;\n");
    } else {
        contents = format!("mod entities;\n{}", contents);
    }

    fs::write(&main_path, contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Added mod entities to src/main.rs");
    Ok(())
}

fn wire_repositories_in_main(src_dir: &Path) -> Result<()> {
    let main_path = src_dir.join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping repositories wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if contents.contains("mod repositories;") {
        return Ok(());
    }

    if contents.contains("mod routes;") {
        contents = contents.replace("mod routes;\n", "mod routes;\nmod repositories;\n");
    } else {
        contents = format!("mod repositories;\n{}", contents);
    }

    fs::write(&main_path, contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Added mod repositories to src/main.rs");
    Ok(())
}

fn wire_services_in_main(src_dir: &Path) -> Result<()> {
    let main_path = src_dir.join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping services wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    if contents.contains("mod services;") {
        return Ok(());
    }

    if contents.contains("mod routes;") {
        contents = contents.replace("mod routes;\n", "mod routes;\nmod services;\n");
    } else {
        contents = format!("mod services;\n{}", contents);
    }

    fs::write(&main_path, contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success("Added mod services to src/main.rs");
    Ok(())
}

fn render_openapi_docs_file(paths: &[String]) -> String {
    let mut output = String::new();
    output.push_str("#[cfg(feature = \"openapi\")]\n");
    output.push_str("tideway::openapi_doc!(\n");
    output.push_str("    pub(crate) ApiDoc,\n");
    output.push_str("    paths(\n");
    for path in paths {
        output.push_str("        ");
        output.push_str(path);
        output.push_str(",\n");
    }
    output.push_str("    )\n");
    output.push_str(");\n");
    output
}

fn generate_sea_orm_scaffold(
    project_dir: &Path,
    resource_name: &str,
    resource_plural: &str,
) -> Result<()> {
    let src_dir = project_dir.join("src");
    let entities_dir = src_dir.join("entities");
    fs::create_dir_all(&entities_dir)
        .with_context(|| format!("Failed to create {}", entities_dir.display()))?;

    let entities_mod = entities_dir.join("mod.rs");
    if !entities_mod.exists() {
        let contents = "//! Database entities.\n\n";
        write_file(&entities_mod, contents, false)?;
        print_success("Created src/entities/mod.rs");
    }
    wire_entities_mod(&entities_mod, resource_name)?;

    let entity_path = entities_dir.join(format!("{}.rs", resource_name));
    let entity_contents = render_sea_orm_entity(resource_name, resource_plural);
    write_file(&entity_path, &entity_contents, false)?;

    let migration_root = project_dir.join("migration");
    let migration_src = migration_root.join("src");
    if !migration_src.exists() {
        fs::create_dir_all(&migration_src)
            .with_context(|| format!("Failed to create {}", migration_src.display()))?;
    }
    if !migration_root.join("Cargo.toml").exists() {
        print_warning("migration/Cargo.toml not found (run `sea-orm-cli migrate init` if needed)");
    }

    let (migration_mod, migration_file) =
        next_migration_name(&migration_src, resource_plural)?;
    let migration_contents = render_sea_orm_migration(resource_plural);
    let migration_path = migration_src.join(&migration_file);
    write_file(&migration_path, &migration_contents, false)?;

    let migration_lib = migration_src.join("lib.rs");
    if !migration_lib.exists() {
        let contents = render_migration_lib(&migration_mod);
        write_file(&migration_lib, &contents, false)?;
        print_success("Created migration/src/lib.rs");
    } else {
        update_migration_lib(&migration_lib, &migration_mod)?;
    }

    print_success("Generated SeaORM entity + migration");
    Ok(())
}

fn wire_entities_mod(mod_path: &Path, resource_name: &str) -> Result<()> {
    let mut contents = fs::read_to_string(mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        fs::write(mod_path, contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn render_sea_orm_entity(resource_name: &str, resource_plural: &str) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    format!(
        r#"//! SeaORM entity for {resource_pascal}.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "{resource_plural}")]
pub struct Model {{
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub name: String,
}}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {{}}

impl ActiveModelBehavior for ActiveModel {{}}
"#,
        resource_pascal = resource_pascal,
        resource_plural = resource_plural
    )
}

fn next_migration_name(migration_src: &Path, resource_plural: &str) -> Result<(String, String)> {
    let mut max_num = 0u64;
    let mut width = 3usize;

    if migration_src.exists() {
        for entry in fs::read_dir(migration_src)
            .with_context(|| format!("Failed to read {}", migration_src.display()))?
        {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };
            if !name.starts_with('m') || !name.ends_with(".rs") {
                continue;
            }
            let stem = name.trim_end_matches(".rs");
            let number_part = stem
                .trim_start_matches('m')
                .split('_')
                .next()
                .unwrap_or("");
            if number_part.chars().all(|c| c.is_ascii_digit()) && !number_part.is_empty() {
                if let Ok(num) = number_part.parse::<u64>() {
                    max_num = max_num.max(num);
                    width = width.max(number_part.len());
                }
            }
        }
    }

    let next = max_num + 1;
    let prefix = format!("m{:0width$}", next, width = width);
    let mod_name = format!("{prefix}_create_{resource_plural}");
    let file_name = format!("{mod_name}.rs");
    Ok((mod_name, file_name))
}

fn render_sea_orm_migration(resource_plural: &str) -> String {
    let table_enum = to_pascal_case(resource_plural);
    format!(
        r#"use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .create_table(
                Table::create()
                    .table({table_enum}::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new({table_enum}::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new({table_enum}::Name).string().not_null())
                    .to_owned(),
            )
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .drop_table(Table::drop().table({table_enum}::Table).to_owned())
            .await
    }}
}}

#[derive(Iden)]
enum {table_enum} {{
    Table,
    Id,
    Name,
}}
"#,
        table_enum = table_enum
    )
}

fn render_migration_lib(mod_name: &str) -> String {
    format!(
        r#"//! Database migrations.

pub use sea_orm_migration::prelude::*;

mod {mod_name};

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {{
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {{
        vec![Box::new({mod_name}::Migration)]
    }}
}}
"#,
        mod_name = mod_name
    )
}

fn update_migration_lib(path: &Path, mod_name: &str) -> Result<()> {
    let mut contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mod_line = format!("mod {};", mod_name);
    if !contents.contains(&mod_line) {
        let mut lines = contents.lines().map(|line| line.to_string()).collect::<Vec<_>>();
        let mut insert_at = None;
        for (idx, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("mod ") {
                insert_at = Some(idx + 1);
            }
        }
        let insert_at = insert_at.unwrap_or_else(|| {
            let prelude_line = lines
                .iter()
                .position(|line| line.contains("sea_orm_migration::prelude"))
                .map(|idx| idx + 1)
                .unwrap_or(0);
            prelude_line
        });
        lines.insert(insert_at, mod_line);
        contents = lines.join("\n");
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }

    if !contents.contains(&format!("{}::Migration", mod_name)) {
        let mut lines = contents.lines().map(|line| line.to_string()).collect::<Vec<_>>();
        let mut vec_start = None;
        let mut vec_end = None;
        for (idx, line) in lines.iter().enumerate() {
            if vec_start.is_none() && line.contains("vec![") {
                vec_start = Some(idx);
                continue;
            }
            if vec_start.is_some() && line.trim_start().starts_with(']') {
                vec_end = Some(idx);
                break;
            }
        }
        if let (Some(start), Some(end)) = (vec_start, vec_end) {
            let base_indent = lines[start]
                .chars()
                .take_while(|c| c.is_whitespace())
                .collect::<String>();
            let entry_indent = format!("{base_indent}    ");
            lines.insert(end, format!("{entry_indent}Box::new({}::Migration),", mod_name));
            contents = lines.join("\n");
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
        } else {
            print_warning("Could not find migrations vector in migration/src/lib.rs");
        }
    }

    fs::write(path, contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}
fn wire_routes_mod(routes_dir: &Path, resource_name: &str) -> Result<()> {
    let mod_path = routes_dir.join("mod.rs");
    if !mod_path.exists() {
        print_warning("routes/mod.rs not found; skipping auto wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        fs::write(&mod_path, contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn generate_repository(project_dir: &Path, resource_name: &str) -> Result<()> {
    let src_dir = project_dir.join("src");
    let repos_dir = src_dir.join("repositories");
    fs::create_dir_all(&repos_dir)
        .with_context(|| format!("Failed to create {}", repos_dir.display()))?;

    let repos_mod = repos_dir.join("mod.rs");
    if !repos_mod.exists() {
        let contents = "//! Repository layer.\n\n";
        write_file(&repos_mod, contents, false)?;
        print_success("Created src/repositories/mod.rs");
    }
    wire_repositories_mod(&repos_mod, resource_name)?;

    let repo_path = repos_dir.join(format!("{}.rs", resource_name));
    let repo_contents = render_repository(resource_name);
    write_file(&repo_path, &repo_contents, false)?;
    print_success("Generated repository");
    Ok(())
}

fn wire_repositories_mod(mod_path: &Path, resource_name: &str) -> Result<()> {
    let mut contents = fs::read_to_string(mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        fs::write(mod_path, contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn render_repository(resource_name: &str) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    format!(
        r#"use sea_orm::{{ActiveModelTrait, EntityTrait, Set}};
use tideway::Result;

use crate::entities::{resource_name};

pub struct {resource_pascal}Repository {{
    db: sea_orm::DatabaseConnection,
}}

impl {resource_pascal}Repository {{
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {{
        Self {{ db }}
    }}

    pub async fn list(&self) -> Result<Vec<{resource_name}::Model>> {{
        Ok({resource_name}::Entity::find().all(&self.db).await?)
    }}

    pub async fn get(&self, id: i32) -> Result<Option<{resource_name}::Model>> {{
        Ok({resource_name}::Entity::find_by_id(id).one(&self.db).await?)
    }}

    pub async fn create(&self, name: String) -> Result<{resource_name}::Model> {{
        let active = {resource_name}::ActiveModel {{
            name: Set(name),
            ..Default::default()
        }};
        Ok(active.insert(&self.db).await?)
    }}

    pub async fn update(&self, id: i32, name: Option<String>) -> Result<{resource_name}::Model> {{
        let model = {resource_name}::Entity::find_by_id(id).one(&self.db).await?;
        let model =
            model.ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
        let mut active: {resource_name}::ActiveModel = model.into();
        if let Some(name) = name {{
            active.name = Set(name);
        }}
        Ok(active.update(&self.db).await?)
    }}

    pub async fn delete(&self, id: i32) -> Result<()> {{
        {resource_name}::Entity::delete_by_id(id)
            .exec(&self.db)
            .await?;
        Ok(())
    }}
}}
"#,
        resource_name = resource_name,
        resource_pascal = resource_pascal
    )
}

fn generate_service(project_dir: &Path, resource_name: &str) -> Result<()> {
    let src_dir = project_dir.join("src");
    let services_dir = src_dir.join("services");
    fs::create_dir_all(&services_dir)
        .with_context(|| format!("Failed to create {}", services_dir.display()))?;

    let services_mod = services_dir.join("mod.rs");
    if !services_mod.exists() {
        let contents = "//! Service layer.\n\n";
        write_file(&services_mod, contents, false)?;
        print_success("Created src/services/mod.rs");
    }
    wire_services_mod(&services_mod, resource_name)?;

    let service_path = services_dir.join(format!("{}.rs", resource_name));
    let service_contents = render_service(resource_name);
    write_file(&service_path, &service_contents, false)?;
    print_success("Generated service");
    Ok(())
}

fn wire_services_mod(mod_path: &Path, resource_name: &str) -> Result<()> {
    let mut contents = fs::read_to_string(mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        fs::write(mod_path, contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn render_service(resource_name: &str) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    format!(
        r#"use tideway::Result;

use crate::repositories::{resource_name}::{resource_pascal}Repository;

pub struct {resource_pascal}Service {{
    repo: {resource_pascal}Repository,
}}

impl {resource_pascal}Service {{
    pub fn new(repo: {resource_pascal}Repository) -> Self {{
        Self {{ repo }}
    }}

    pub async fn list(&self) -> Result<Vec<crate::entities::{resource_name}::Model>> {{
        self.repo.list().await
    }}

    pub async fn get(&self, id: i32) -> Result<Option<crate::entities::{resource_name}::Model>> {{
        self.repo.get(id).await
    }}

    pub async fn create(&self, name: String) -> Result<crate::entities::{resource_name}::Model> {{
        self.repo.create(name).await
    }}

    pub async fn update(
        &self,
        id: i32,
        name: Option<String>,
    ) -> Result<crate::entities::{resource_name}::Model> {{
        self.repo.update(id, name).await
    }}

    pub async fn delete(&self, id: i32) -> Result<()> {{
        self.repo.delete(id).await
    }}
}}
"#,
        resource_name = resource_name,
        resource_pascal = resource_pascal
    )
}

fn generate_repository_tests(
    project_dir: &Path,
    project_name: &str,
    resource_name: &str,
) -> Result<()> {
    let tests_dir = project_dir.join("tests");
    fs::create_dir_all(&tests_dir)
        .with_context(|| format!("Failed to create {}", tests_dir.display()))?;

    let file_path = tests_dir.join(format!("repository_{}.rs", resource_name));
    let contents = render_repository_tests(project_name, resource_name);
    write_file(&file_path, &contents, false)?;
    print_success("Generated repository tests");
    Ok(())
}

fn render_repository_tests(project_name: &str, resource_name: &str) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    format!(
        r#"use sea_orm::Database;
use tideway::Result;

use {project_name}::repositories::{resource_name}::{resource_pascal}Repository;

#[tokio::test]
#[ignore = "Requires DATABASE_URL and existing migrations"]
async fn repository_crud_smoke() -> Result<()> {{
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL is required for repository tests");
    let db = Database::connect(&database_url).await?;
    let repo = {resource_pascal}Repository::new(db);

    let created = repo.create("Example".to_string()).await?;
    let _ = repo.list().await?;
    repo.delete(created.id).await?;
    Ok(())
}}
"#,
        project_name = project_name,
        resource_name = resource_name,
        resource_pascal = resource_pascal
    )
}

fn wire_main_rs(src_dir: &Path, resource_name: &str, resource_pascal: &str) -> Result<()> {
    let main_path = src_dir.join("main.rs");
    if !main_path.exists() {
        print_warning("src/main.rs not found; skipping auto wiring");
        return Ok(());
    }

    let mut contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;

    let register_line = format!(
        ".register_module(routes::{}::{}Module)",
        resource_name, resource_pascal
    );
    if contents.contains(&register_line) {
        return Ok(());
    }

    if let Some(pos) = contents.find(".register_module(") {
        let line_end = contents[pos..]
            .find('\n')
            .map(|idx| pos + idx)
            .unwrap_or(contents.len());
        contents.insert_str(line_end + 1, &format!("        {}\n", register_line));
    } else {
        print_warning("Could not find register_module call in main.rs");
    }

    fs::write(&main_path, contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    Ok(())
}

fn write_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!(
            "Skipping {} (use --force to overwrite)",
            path.display()
        ));
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    fs::write(path, contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn normalize_name(name: &str) -> String {
    name.trim().to_lowercase().replace('-', "_")
}

fn pluralize(name: &str) -> String {
    if name.ends_with('s') {
        format!("{}es", name)
    } else {
        format!("{}s", name)
    }
}

fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

fn has_feature(cargo_path: &Path, feature: &str) -> bool {
    let Ok(contents) = fs::read_to_string(cargo_path) else {
        return false;
    };
    let Ok(doc) = contents.parse::<toml_edit::DocumentMut>() else {
        return false;
    };

    let Some(tideway) = doc
        .get("dependencies")
        .and_then(|deps| deps.get("tideway"))
    else {
        return false;
    };

    let Some(features) = tideway.get("features").and_then(|item| item.as_array()) else {
        return false;
    };

    features.iter().any(|v| v.as_str() == Some(feature))
}

fn has_dependency(cargo_path: &Path, dependency: &str) -> bool {
    let Ok(contents) = fs::read_to_string(cargo_path) else {
        return false;
    };
    let Ok(doc) = contents.parse::<toml_edit::DocumentMut>() else {
        return false;
    };

    doc.get("dependencies")
        .and_then(|deps| deps.get(dependency))
        .is_some()
}

fn project_name_from_cargo(cargo_path: &Path, project_dir: &Path) -> String {
    let Ok(contents) = fs::read_to_string(cargo_path) else {
        return fallback_project_name(project_dir);
    };
    let Ok(doc) = contents.parse::<toml_edit::DocumentMut>() else {
        return fallback_project_name(project_dir);
    };

    doc.get("package")
        .and_then(|pkg| pkg.get("name"))
        .and_then(|value| value.as_str())
        .map(|name| name.replace('-', "_"))
        .unwrap_or_else(|| fallback_project_name(project_dir))
}

fn fallback_project_name(project_dir: &Path) -> String {
    project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my_app")
        .replace('-', "_")
}
