//! Resource command - generate CRUD modules for API development.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::ResourceArgs;
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

    let _has_validation = has_feature(&project_dir.join("Cargo.toml"), "validation");

    let routes_dir = src_dir.join("routes");
    fs::create_dir_all(&routes_dir)
        .with_context(|| format!("Failed to create {}", routes_dir.display()))?;

    let resource_path = routes_dir.join(format!("{}.rs", resource_name));
    let contents = render_resource_module(
        &resource_pascal,
        &resource_name,
        &resource_plural,
        args.with_tests,
    );
    write_file(&resource_path, &contents, false)?;

    if args.wire {
        wire_routes_mod(&routes_dir, &resource_name)?;
        wire_main_rs(&src_dir, &resource_name, &resource_pascal)?;
    } else {
        print_info("Next steps: add the module to routes/mod.rs and register it in main.rs");
    }

    if args.with_tests {
        print_info("Added unit tests to the resource module");
    }

    print_success(&format!("Generated {} resource", resource_name));
    Ok(())
}

fn render_resource_module(
    resource_pascal: &str,
    resource_name: &str,
    resource_plural: &str,
    with_tests: bool,
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
    format!(
        r#"//! {resource_pascal} routes.

use axum::{{routing::{{delete, get, post, put}}, Json, Router}};
use serde::{{Deserialize, Serialize}};
use tideway::{{AppContext, MessageResponse, Result, RouteModule}};

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
pub struct {resource_pascal} {{
    pub id: String,
    pub name: String,
}}

#[derive(Deserialize)]
pub struct CreateRequest {{
    pub name: String,
}}

#[derive(Deserialize)]
pub struct UpdateRequest {{
    pub name: Option<String>,
}}

async fn list_{resource_plural}() -> Json<Vec<{resource_pascal}>> {{
    Json(Vec::new())
}}

async fn get_{resource_name}() -> Result<Json<{resource_pascal}>> {{
    Ok(Json({resource_pascal} {{
        id: "demo".to_string(),
        name: "{resource_pascal}".to_string(),
    }}))
}}

async fn create_{resource_name}({body_extractor}) -> Result<MessageResponse> {{
    Ok(MessageResponse::success(format!("Created {{}}", body.name)))
}}

async fn update_{resource_name}({body_extractor}) -> Result<MessageResponse> {{
    let name = body.name.unwrap_or_else(|| "{resource_pascal}".to_string());
    Ok(MessageResponse::success(format!("Updated {{}}", name)))
}}

async fn delete_{resource_name}() -> Result<MessageResponse> {{
    Ok(MessageResponse::success("Deleted"))
}}
{tests_block}
"#,
        resource_pascal = resource_pascal,
        resource_name = resource_name,
        resource_plural = resource_plural,
        body_extractor = body_extractor,
        tests_block = tests_block,
    )
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
