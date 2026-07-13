//! Resource command - generate CRUD modules for API development.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{DbBackend, ResourceArgs, ResourceIdType, ResourceProfile};
use crate::commands::add::{array_value, wire_database_in_main};
use crate::commands::app_builder::{
    find_app_builder_marker_range, find_unmarked_app_builder_statement_range,
};
use crate::commands::file_ops::{ensure_module_decl, to_pascal_case, write_file_with_force};
use crate::commands::messaging::{
    DEV_FIX_ENV_COMMAND, GREENFIELD_NEW_APP_PRESET_API, NEW_APP_COMMAND,
    TIDEWAY_ADD_DATABASE_COMMAND, TIDEWAY_ADD_DATABASE_WIRE_COMMAND,
};
use crate::{
    CommandRuntime, ensure_dir, error_contract, print_info, print_success, print_warning,
    write_file,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceFieldType {
    String,
    Bool,
    I64,
}

impl ResourceFieldType {
    fn rust_type(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Bool => "bool",
            Self::I64 => "i64",
        }
    }

    fn migration_column(self, column_enum: &str) -> String {
        match self {
            Self::String => format!("ColumnDef::new({column_enum}).string().not_null()"),
            Self::Bool => format!("ColumnDef::new({column_enum}).boolean().not_null()"),
            Self::I64 => format!("ColumnDef::new({column_enum}).big_integer().not_null()"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FieldSource {
    Request,
    CurrentTimestamp,
}

#[derive(Clone, Copy, Debug)]
struct ResourceFieldSpec {
    name: &'static str,
    ty: ResourceFieldType,
    include_in_create: bool,
    include_in_update: bool,
    create_source: FieldSource,
    update_source: Option<FieldSource>,
    search: bool,
    stub_value: &'static str,
    json_value: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct ResourceSchema {
    display_field: &'static str,
    display_fallback: &'static str,
    fields: &'static [ResourceFieldSpec],
}

#[derive(Clone, Copy, Debug, Default)]
struct ResourceGenerationContext {
    shared_saas_actor: bool,
    saas_owned_scope: bool,
    saas_admin_guard: bool,
}

const NAME_FIELDS: [ResourceFieldSpec; 1] = [ResourceFieldSpec {
    name: "name",
    ty: ResourceFieldType::String,
    include_in_create: true,
    include_in_update: true,
    create_source: FieldSource::Request,
    update_source: Some(FieldSource::Request),
    search: true,
    stub_value: "\"User\".to_string()",
    json_value: "\"Example\"",
}];

const TENANT_FIELDS: [ResourceFieldSpec; 5] = [
    ResourceFieldSpec {
        name: "name",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: true,
        stub_value: "\"Acme\".to_string()",
        json_value: "\"Acme\"",
    },
    ResourceFieldSpec {
        name: "slug",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"acme\".to_string()",
        json_value: "\"acme\"",
    },
    ResourceFieldSpec {
        name: "status",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"active\".to_string()",
        json_value: "\"active\"",
    },
    ResourceFieldSpec {
        name: "created_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: None,
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
    ResourceFieldSpec {
        name: "updated_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: Some(FieldSource::CurrentTimestamp),
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
];

const OWNED_FIELDS: [ResourceFieldSpec; 6] = [
    ResourceFieldSpec {
        name: "organization_id",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"org_demo\".to_string()",
        json_value: "\"org_demo\"",
    },
    ResourceFieldSpec {
        name: "owner_id",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"user_demo\".to_string()",
        json_value: "\"user_demo\"",
    },
    ResourceFieldSpec {
        name: "name",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: true,
        stub_value: "\"Example\".to_string()",
        json_value: "\"Example\"",
    },
    ResourceFieldSpec {
        name: "status",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"active\".to_string()",
        json_value: "\"active\"",
    },
    ResourceFieldSpec {
        name: "created_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: None,
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
    ResourceFieldSpec {
        name: "updated_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: Some(FieldSource::CurrentTimestamp),
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
];

const ADMIN_FIELDS: [ResourceFieldSpec; 5] = [
    ResourceFieldSpec {
        name: "email",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: true,
        stub_value: "\"admin@example.com\".to_string()",
        json_value: "\"admin@example.com\"",
    },
    ResourceFieldSpec {
        name: "role",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"admin\".to_string()",
        json_value: "\"admin\"",
    },
    ResourceFieldSpec {
        name: "enabled",
        ty: ResourceFieldType::Bool,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "true",
        json_value: "true",
    },
    ResourceFieldSpec {
        name: "created_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: None,
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
    ResourceFieldSpec {
        name: "updated_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: Some(FieldSource::CurrentTimestamp),
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
];

const EVENT_FIELDS: [ResourceFieldSpec; 6] = [
    ResourceFieldSpec {
        name: "event_type",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: true,
        stub_value: "\"user.created\".to_string()",
        json_value: "\"user.created\"",
    },
    ResourceFieldSpec {
        name: "actor_id",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"user_demo\".to_string()",
        json_value: "\"user_demo\"",
    },
    ResourceFieldSpec {
        name: "subject_id",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"invoice_demo\".to_string()",
        json_value: "\"invoice_demo\"",
    },
    ResourceFieldSpec {
        name: "payload_json",
        ty: ResourceFieldType::String,
        include_in_create: true,
        include_in_update: true,
        create_source: FieldSource::Request,
        update_source: Some(FieldSource::Request),
        search: false,
        stub_value: "\"{\\\"source\\\":\\\"api\\\"}\".to_string()",
        json_value: "\"{\\\"source\\\":\\\"api\\\"}\"",
    },
    ResourceFieldSpec {
        name: "created_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: None,
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
    ResourceFieldSpec {
        name: "updated_at",
        ty: ResourceFieldType::I64,
        include_in_create: false,
        include_in_update: false,
        create_source: FieldSource::CurrentTimestamp,
        update_source: Some(FieldSource::CurrentTimestamp),
        search: false,
        stub_value: "1_700_000_000_i64",
        json_value: "1_700_000_000",
    },
];

fn resource_schema(profile: ResourceProfile) -> ResourceSchema {
    match profile {
        ResourceProfile::Api | ResourceProfile::Stub => ResourceSchema {
            display_field: "name",
            display_fallback: "User",
            fields: &NAME_FIELDS,
        },
        ResourceProfile::Tenant => ResourceSchema {
            display_field: "name",
            display_fallback: "Acme",
            fields: &TENANT_FIELDS,
        },
        ResourceProfile::Owned => ResourceSchema {
            display_field: "name",
            display_fallback: "Example",
            fields: &OWNED_FIELDS,
        },
        ResourceProfile::Admin => ResourceSchema {
            display_field: "email",
            display_fallback: "admin@example.com",
            fields: &ADMIN_FIELDS,
        },
        ResourceProfile::Event => ResourceSchema {
            display_field: "event_type",
            display_fallback: "user.created",
            fields: &EVENT_FIELDS,
        },
    }
}

fn create_request_fields(schema: ResourceSchema) -> Vec<ResourceFieldSpec> {
    schema
        .fields
        .iter()
        .copied()
        .filter(|field| field.include_in_create)
        .collect()
}

fn update_request_fields(schema: ResourceSchema) -> Vec<ResourceFieldSpec> {
    schema
        .fields
        .iter()
        .copied()
        .filter(|field| field.include_in_update)
        .collect()
}

fn route_request_fields(
    schema: ResourceSchema,
    profile: ResourceProfile,
    context: ResourceGenerationContext,
    optional: bool,
) -> Vec<ResourceFieldSpec> {
    let mut fields = if optional {
        update_request_fields(schema)
    } else {
        create_request_fields(schema)
    };

    if context.saas_owned_scope && matches!(profile, ResourceProfile::Owned) {
        fields.retain(|field| !matches!(field.name, "organization_id" | "owner_id"));
    }

    fields
}

fn search_field(schema: ResourceSchema) -> Option<ResourceFieldSpec> {
    schema.fields.iter().copied().find(|field| field.search)
}

fn uses_generated_timestamps(schema: ResourceSchema) -> bool {
    schema.fields.iter().any(|field| {
        field.create_source == FieldSource::CurrentTimestamp
            || field.update_source == Some(FieldSource::CurrentTimestamp)
    })
}

fn current_timestamp_helper() -> &'static str {
    r#"
fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
"#
}

fn render_response_struct_fields(schema: ResourceSchema) -> String {
    let mut output = String::from("    pub id: String,\n");
    for field in schema.fields {
        output.push_str(&format!(
            "    pub {}: {},\n",
            field.name,
            field.ty.rust_type()
        ));
    }
    output
}

fn render_request_struct_fields(fields: &[ResourceFieldSpec], optional: bool) -> String {
    let mut output = String::new();
    for field in fields {
        let ty = if optional {
            format!("Option<{}>", field.ty.rust_type())
        } else {
            field.ty.rust_type().to_string()
        };
        output.push_str(&format!("    pub {}: {},\n", field.name, ty));
    }
    output
}

fn render_response_init_fields(schema: ResourceSchema, source: &str, indent: &str) -> String {
    let mut output = format!("{indent}id: {source}.id.to_string(),\n");
    for field in schema.fields {
        output.push_str(&format!(
            "{indent}{}: {}.{},\n",
            field.name, source, field.name
        ));
    }
    output
}

fn render_stub_response_fields(
    schema: ResourceSchema,
    indent: &str,
    default_display: &str,
) -> String {
    let mut output = format!("{indent}id: \"demo\".to_string(),\n");
    for field in schema.fields {
        let value = if schema.fields.len() == 1 && field.name == schema.display_field {
            format!("\"{}\".to_string()", default_display)
        } else {
            field.stub_value.to_string()
        };
        output.push_str(&format!("{indent}{}: {},\n", field.name, value));
    }
    output
}

fn render_active_model_create_assignments(
    schema: ResourceSchema,
    source: &str,
    indent: &str,
) -> String {
    let mut output = String::new();
    for field in schema.fields {
        let value = match field.create_source {
            FieldSource::Request => format!("{source}.{}", field.name),
            FieldSource::CurrentTimestamp => "current_timestamp()".to_string(),
        };
        output.push_str(&format!("{indent}{}: Set({}),\n", field.name, value));
    }
    output
}

fn render_active_model_update_assignments(
    schema: ResourceSchema,
    source: &str,
    target: &str,
    indent: &str,
) -> String {
    let mut output = String::new();
    for field in schema.fields {
        match field.update_source {
            Some(FieldSource::Request) => {
                output.push_str(&format!(
                    "{indent}if let Some({name}) = {source}.{name} {{\n{indent}    {target}.{name} = Set({name});\n{indent}}}\n",
                    name = field.name,
                ));
            }
            Some(FieldSource::CurrentTimestamp) => {
                output.push_str(&format!(
                    "{indent}{target}.{name} = Set(current_timestamp());\n",
                    name = field.name,
                ));
            }
            None => {}
        }
    }
    output
}

fn render_create_test_json_fields_for_fields(fields: &[ResourceFieldSpec]) -> String {
    fields
        .iter()
        .map(|field| format!("\"{}\": {}", field.name, field.json_value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_signature_args_from_fields(fields: &[ResourceFieldSpec], optional: bool) -> String {
    fields
        .iter()
        .map(|field| {
            let ty = if optional {
                format!("Option<{}>", field.ty.rust_type())
            } else {
                field.ty.rust_type().to_string()
            };
            format!("{}: {}", field.name, ty)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_create_signature_args(schema: ResourceSchema, optional: bool) -> String {
    let fields = if optional {
        update_request_fields(schema)
    } else {
        create_request_fields(schema)
    };
    render_signature_args_from_fields(&fields, optional)
}

fn render_call_args_from_fields(fields: &[ResourceFieldSpec], source: &str) -> String {
    fields
        .iter()
        .map(|field| format!("{source}.{}", field.name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_call_args(schema: ResourceSchema, source: &str, optional: bool) -> String {
    let fields = if optional {
        update_request_fields(schema)
    } else {
        create_request_fields(schema)
    };
    render_call_args_from_fields(&fields, source)
}

fn render_param_names_from_fields(fields: &[ResourceFieldSpec]) -> String {
    fields
        .iter()
        .map(|field| field.name.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_param_names(schema: ResourceSchema, optional: bool) -> String {
    let fields = if optional {
        update_request_fields(schema)
    } else {
        create_request_fields(schema)
    };
    render_param_names_from_fields(&fields)
}

fn render_stub_call_args(schema: ResourceSchema, optional: bool) -> String {
    let fields = if optional {
        update_request_fields(schema)
    } else {
        create_request_fields(schema)
    };
    fields
        .iter()
        .map(|field| field.stub_value.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn display_fallback_value(schema: ResourceSchema, default_display: &str) -> String {
    if schema.fields.len() == 1 && schema.display_field == "name" {
        format!("\"{}\".to_string()", default_display)
    } else {
        format!("\"{}\".to_string()", schema.display_fallback)
    }
}

fn render_entity_fields(schema: ResourceSchema) -> String {
    let mut output = String::new();
    for field in schema.fields {
        output.push_str(&format!(
            "    pub {}: {},\n",
            field.name,
            field.ty.rust_type()
        ));
    }
    output
}

fn render_migration_columns(schema: ResourceSchema, table_enum: &str) -> String {
    schema
        .fields
        .iter()
        .map(|field| {
            let column_enum = to_pascal_case(field.name);
            format!(
                "                    .col({})\n",
                field
                    .ty
                    .migration_column(&format!("{table_enum}::{column_enum}"))
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_timestamp_helper_if_needed(schema: ResourceSchema) -> String {
    if uses_generated_timestamps(schema) {
        current_timestamp_helper().to_string()
    } else {
        String::new()
    }
}

fn search_column_expr(resource_name: &str, schema: ResourceSchema) -> Option<String> {
    search_field(schema)
        .map(|field| format!("{resource_name}::Column::{}", to_pascal_case(field.name)))
}

fn render_search_query(resource_name: &str, schema: ResourceSchema, search_var: &str) -> String {
    let Some(column) = search_column_expr(resource_name, schema) else {
        return String::new();
    };
    format!(
        "        if let Some(search) = {search_var}.as_deref() {{ query = query.filter({column}.contains(search)); }}\n"
    )
}

fn render_param_create_assignments(schema: ResourceSchema, indent: &str) -> String {
    let mut output = String::new();
    for field in schema.fields {
        let value = match field.create_source {
            FieldSource::Request => field.name.to_string(),
            FieldSource::CurrentTimestamp => "current_timestamp()".to_string(),
        };
        output.push_str(&format!("{indent}{}: Set({}),\n", field.name, value));
    }
    output
}

fn render_param_update_assignments(schema: ResourceSchema, target: &str, indent: &str) -> String {
    let mut output = String::new();
    for field in schema.fields {
        match field.update_source {
            Some(FieldSource::Request) => {
                output.push_str(&format!(
                    "{indent}if let Some({name}) = {name} {{\n{indent}    {target}.{name} = Set({name});\n{indent}}}\n",
                    name = field.name,
                ));
            }
            Some(FieldSource::CurrentTimestamp) => {
                output.push_str(&format!(
                    "{indent}{target}.{name} = Set(current_timestamp());\n",
                    name = field.name,
                ));
            }
            None => {}
        }
    }
    output
}

fn render_migration_idents(schema: ResourceSchema) -> String {
    schema
        .fields
        .iter()
        .map(|field| format!("    {},\n", to_pascal_case(field.name)))
        .collect::<Vec<_>>()
        .join("")
}

fn render_search_stub_value(schema: ResourceSchema) -> String {
    search_field(schema)
        .map(|field| field.stub_value.to_string())
        .unwrap_or_else(|| "\"Example\".to_string()".to_string())
}

fn render_service_string_normalization_lines(schema: ResourceSchema, optional: bool) -> String {
    let fields = if optional {
        update_request_fields(schema)
    } else {
        create_request_fields(schema)
    };

    fields
        .iter()
        .filter(|field| field.ty == ResourceFieldType::String)
        .map(|field| {
            let expr = match (field.name, optional) {
                ("slug", false) => "Self::normalize_slug(slug)?".to_string(),
                ("slug", true) => "Self::normalize_optional_slug(slug)?".to_string(),
                ("email", false) => "Self::normalize_email(email)?".to_string(),
                ("email", true) => "Self::normalize_optional_email(email)?".to_string(),
                ("status" | "role" | "event_type", false) => format!(
                    "Self::normalize_lowercase_required(\"{name}\", {name})?",
                    name = field.name
                ),
                ("status" | "role" | "event_type", true) => format!(
                    "Self::normalize_lowercase_optional(\"{name}\", {name})?",
                    name = field.name
                ),
                (_, false) => format!(
                    "Self::normalize_required_string(\"{name}\", {name})?",
                    name = field.name
                ),
                (_, true) => format!(
                    "Self::normalize_optional_string(\"{name}\", {name})?",
                    name = field.name
                ),
            };
            format!("        let {name} = {expr};\n", name = field.name)
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_service_validation_helpers(schema: ResourceSchema) -> String {
    let mut output = String::from(
        r#"
    fn normalize_required_string(field: &str, value: String) -> Result<String> {
        let value = value.trim().to_string();
        ensure!(
            !value.is_empty(),
            TidewayError::bad_request(format!("{field} is required"))
        );
        Ok(value)
    }

    fn normalize_optional_string(field: &str, value: Option<String>) -> Result<Option<String>> {
        value
            .map(|value| Self::normalize_required_string(field, value))
            .transpose()
    }
"#,
    );

    if schema
        .fields
        .iter()
        .any(|field| matches!(field.name, "status" | "role" | "event_type"))
    {
        output.push_str(
            r#"

    fn normalize_lowercase_required(field: &str, value: String) -> Result<String> {
        Ok(Self::normalize_required_string(field, value)?.to_lowercase())
    }

    fn normalize_lowercase_optional(
        field: &str,
        value: Option<String>,
    ) -> Result<Option<String>> {
        value
            .map(|value| Self::normalize_lowercase_required(field, value))
            .transpose()
    }
"#,
        );
    }

    if schema.fields.iter().any(|field| field.name == "slug") {
        output.push_str(
            r#"

    fn normalize_slug(value: String) -> Result<String> {
        let slug = Self::normalize_required_string("slug", value)?
            .to_lowercase()
            .chars()
            .map(|ch| match ch {
                'a'..='z' | '0'..='9' => ch,
                _ => '-',
            })
            .collect::<String>()
            .split('-')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        ensure!(
            !slug.is_empty(),
            TidewayError::bad_request("slug must contain letters or numbers")
        );
        Ok(slug)
    }

    fn normalize_optional_slug(value: Option<String>) -> Result<Option<String>> {
        value.map(Self::normalize_slug).transpose()
    }
"#,
        );
    }

    if schema.fields.iter().any(|field| field.name == "email") {
        output.push_str(
            r#"

    fn normalize_email(value: String) -> Result<String> {
        let email = Self::normalize_required_string("email", value)?.to_lowercase();
        ensure!(
            email.contains('@'),
            TidewayError::bad_request("email must contain @")
        );
        Ok(email)
    }

    fn normalize_optional_email(value: Option<String>) -> Result<Option<String>> {
        value.map(Self::normalize_email).transpose()
    }
"#,
        );
    }

    output
}

fn render_repository_list_signature(
    resource_name: &str,
    schema: ResourceSchema,
    paginate: bool,
    search: bool,
) -> String {
    if paginate {
        if search {
            format!(
                "pub async fn list(&self, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<{resource_name}::Model>> {{"
            )
        } else {
            format!(
                "pub async fn list(&self, limit: Option<u64>, offset: Option<u64>) -> Result<Vec<{resource_name}::Model>> {{"
            )
        }
    } else {
        let _ = schema;
        format!("pub async fn list(&self) -> Result<Vec<{resource_name}::Model>> {{")
    }
}

fn render_repository_list_body(
    resource_name: &str,
    schema: ResourceSchema,
    paginate: bool,
    search: bool,
) -> String {
    if paginate {
        let search_query = if search {
            render_search_query(resource_name, schema, "search")
        } else {
            String::new()
        };
        format!(
            "        let mut query = {resource_name}::Entity::find();\n        query = query.limit(limit.unwrap_or(20).clamp(1, 100));\n        if let Some(offset) = offset {{ query = query.offset(offset); }}\n{search_query}        Ok(query.all(&self.db).await?)",
        )
    } else {
        format!("        Ok({resource_name}::Entity::find().all(&self.db).await?)")
    }
}

fn detect_generation_context(project_dir: &Path, args: &ResourceArgs) -> ResourceGenerationContext {
    let src_dir = project_dir.join("src");
    let has_saas_auth =
        src_dir.join("auth/mod.rs").exists() && src_dir.join("entities/user.rs").exists();
    let has_saas_organizations = src_dir.join("entities/organization_member.rs").exists();
    let has_saas_admin = src_dir.join("admin/mod.rs").exists();
    let has_shared_saas_actor = src_dir.join("auth/actor.rs").exists();
    let full_stack = args.db && args.repo && args.service;

    ResourceGenerationContext {
        shared_saas_actor: has_shared_saas_actor,
        saas_owned_scope: full_stack
            && matches!(args.profile, ResourceProfile::Owned)
            && has_saas_auth
            && has_saas_organizations,
        saas_admin_guard: full_stack
            && matches!(args.profile, ResourceProfile::Admin)
            && has_saas_auth
            && has_saas_admin,
    }
}

pub fn run(args: ResourceArgs) -> Result<()> {
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(args: ResourceArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();

    let mut args = args;
    apply_profile_defaults(&mut args);

    let project_dir = PathBuf::from(&args.path);
    let src_dir = project_dir.join("src");
    if !src_dir.exists() {
        return Err(anyhow::anyhow!(error_contract(
            &format!("src/ not found in {}", project_dir.display()),
            "Run from a Tideway app root containing src/.",
            &format!(
                "For a new app, run {} then rerun this command.",
                NEW_APP_COMMAND
            )
        )));
    }

    let resource_name = normalize_name(&args.name);
    let resource_pascal = to_pascal_case(&resource_name);
    let resource_plural = pluralize(&resource_name);
    let generation_context = detect_generation_context(&project_dir, &args);

    let cargo_path = project_dir.join("Cargo.toml");
    let cargo_doc = read_cargo_manifest(&cargo_path);
    let has_openapi = manifest_has_tideway_feature(cargo_doc.as_ref(), "openapi");
    let has_database = manifest_has_tideway_feature(cargo_doc.as_ref(), "database");
    let has_sea_orm_dependency = manifest_has_dependency(cargo_doc.as_ref(), "sea-orm");
    let has_uuid_dependency = manifest_has_dependency(cargo_doc.as_ref(), "uuid");

    validate_resource_args(
        &args,
        &resource_name,
        has_database,
        has_sea_orm_dependency,
        has_uuid_dependency,
    )?;
    let db_backend = if args.db {
        Some(resolve_db_backend(cargo_doc.as_ref(), args.db_backend)?)
    } else {
        None
    };

    if args.db
        && matches!(args.id_type, ResourceIdType::Uuid)
        && args.add_uuid
        && !has_uuid_dependency
    {
        add_uuid_dependency(&cargo_path)?;
        print_success("Added uuid dependency to Cargo.toml");
    }

    let routes_dir = src_dir.join("routes");
    ensure_dir(&routes_dir)
        .with_context(|| format!("Failed to create {}", routes_dir.display()))?;

    let resource_path = routes_dir.join(format!("{}.rs", resource_name));
    let contents = render_resource_module(
        &resource_pascal,
        &resource_name,
        &resource_plural,
        args.with_tests,
        has_openapi,
        args.profile,
        args.db,
        args.repo,
        args.service,
        args.id_type,
        args.paginate,
        args.search,
        generation_context,
    );
    write_file_with_force(&resource_path, &contents, false)?;

    if args.wire {
        wire_routes_mod(&routes_dir, &resource_name)?;
        wire_routes_in_main(&src_dir)?;
        wire_main_rs(&src_dir, &resource_name, &resource_pascal)?;
        if has_openapi {
            wire_openapi_docs(&src_dir, &resource_name, &resource_plural)?;
        }
    } else {
        print_warning("Manual wiring mode is advanced. For the primary path, rerun with `--wire`.");
        print_info("Next steps: add the module to routes/mod.rs and register it in main.rs");
    }

    if args.db {
        let backend = db_backend.expect("db backend should be resolved when --db is enabled");
        match backend {
            DbBackend::SeaOrm => generate_sea_orm_scaffold(
                &project_dir,
                &resource_name,
                &resource_plural,
                args.id_type,
                args.profile,
            )?,
            DbBackend::Auto => {
                return Err(anyhow::anyhow!(error_contract(
                    "Unable to detect database backend.",
                    "Pass `--db-backend sea-orm`.",
                    "Add SeaORM dependencies, then rerun with `--db-backend auto`."
                )));
            }
        }

        if args.repo {
            generate_repository(
                &project_dir,
                &resource_name,
                args.id_type,
                args.paginate,
                args.search,
                args.profile,
                generation_context,
            )?;
            if args.repo_tests {
                let project_name = project_name_from_cargo(&cargo_path, &project_dir);
                generate_repository_tests(
                    &project_dir,
                    &project_name,
                    &resource_name,
                    args.id_type,
                    args.paginate,
                    args.search,
                    args.profile,
                )?;
            }
            if args.service {
                generate_service(
                    &project_dir,
                    &resource_name,
                    args.id_type,
                    args.paginate,
                    args.search,
                    args.profile,
                    generation_context,
                )?;
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
            print_info(&format!(
                "Next steps: wire database into main.rs (advanced: {})",
                TIDEWAY_ADD_DATABASE_WIRE_COMMAND
            ));
        }
    }

    if generation_context.saas_owned_scope {
        print_info(
            "Detected a SaaS scaffold; generated auth-scoped owned handlers that derive organization and owner context from the caller.",
        );
    } else if generation_context.saas_admin_guard {
        print_info("Detected a SaaS scaffold; generated admin-guarded handlers for this resource.");
    }

    if args.with_tests && !args.db {
        print_info("Added unit tests to the resource module");
    } else if args.with_tests && args.db {
        print_info("Skipped route unit tests for the DB-backed resource");
    }

    print_info(&format!(
        "Primary path reminder: run {} to boot and verify the new resource.",
        DEV_FIX_ENV_COMMAND
    ));
    print_success(&format!("Generated {} resource", resource_name));
    Ok(())
}

fn apply_profile_defaults(args: &mut ResourceArgs) {
    let has_shape_overrides =
        args.wire || args.db || args.repo || args.service || args.paginate || args.search;

    if !has_shape_overrides
        && matches!(
            args.profile,
            ResourceProfile::Api
                | ResourceProfile::Tenant
                | ResourceProfile::Owned
                | ResourceProfile::Admin
                | ResourceProfile::Event
        )
    {
        args.wire = true;
        args.db = true;
        args.repo = true;
        args.service = true;
        args.paginate = true;
        args.search = true;
    }
}

fn validate_resource_args(
    args: &ResourceArgs,
    resource_name: &str,
    has_database: bool,
    has_sea_orm_dependency: bool,
    has_uuid_dependency: bool,
) -> Result<()> {
    if args.repo && !args.db {
        return Err(anyhow::anyhow!(error_contract(
            "Repository scaffolding requires --db.",
            &format!("Run `tideway resource {} --db --repo`.", resource_name),
            "Skip `--repo` if you only want route stubs."
        )));
    }

    if args.repo_tests && !args.repo {
        return Err(anyhow::anyhow!(error_contract(
            "Repository tests require --repo.",
            &format!(
                "Run `tideway resource {} --db --repo --repo-tests`.",
                resource_name
            ),
            "Drop `--repo-tests` if repository scaffolding is not needed."
        )));
    }

    if args.service && !args.repo {
        return Err(anyhow::anyhow!(error_contract(
            "Service scaffolding requires --repo.",
            &format!(
                "Run `tideway resource {} --db --repo --service`.",
                resource_name
            ),
            "Drop `--service` if you only need route/repository layers."
        )));
    }

    if args.search && !args.paginate {
        return Err(anyhow::anyhow!(error_contract(
            "Search requires --paginate.",
            &format!(
                "Run `tideway resource {} --db --paginate --search`.",
                resource_name
            ),
            "Drop `--search` for basic list endpoints."
        )));
    }

    if args.search && !args.db {
        return Err(anyhow::anyhow!(error_contract(
            "Search requires --db.",
            &format!(
                "Run `tideway resource {} --db --paginate --search`.",
                resource_name
            ),
            "Drop `--search` if using non-DB stubs."
        )));
    }

    if args.paginate && !args.db {
        return Err(anyhow::anyhow!(error_contract(
            "Pagination requires --db.",
            &format!("Run `tideway resource {} --db --paginate`.", resource_name),
            "Drop `--paginate` for non-DB stubs."
        )));
    }

    if args.db {
        if !has_database {
            return Err(anyhow::anyhow!(error_contract(
                "Database scaffolding requires the Tideway `database` feature.",
                GREENFIELD_NEW_APP_PRESET_API,
                &format!("For existing apps, run {}.", TIDEWAY_ADD_DATABASE_COMMAND)
            )));
        }
        if !has_sea_orm_dependency {
            return Err(anyhow::anyhow!(error_contract(
                "SeaORM dependency not found.",
                GREENFIELD_NEW_APP_PRESET_API,
                &format!("For existing apps, run {}.", TIDEWAY_ADD_DATABASE_COMMAND)
            )));
        }
        if matches!(args.id_type, ResourceIdType::Uuid) && !has_uuid_dependency && !args.add_uuid {
            return Err(anyhow::anyhow!(
                "{}",
                error_contract(
                    "UUID id type requires the `uuid` dependency.",
                    "Rerun with `--add-uuid`.",
                    "Add `uuid` manually in Cargo.toml then rerun."
                )
            ));
        }
    }

    Ok(())
}

fn resolve_db_backend(
    cargo_doc: Option<&toml_edit::DocumentMut>,
    backend: DbBackend,
) -> Result<DbBackend> {
    match backend {
        DbBackend::Auto => detect_db_backend(cargo_doc),
        DbBackend::SeaOrm => Ok(DbBackend::SeaOrm),
    }
}

fn detect_db_backend(cargo_doc: Option<&toml_edit::DocumentMut>) -> Result<DbBackend> {
    let Some(doc) = cargo_doc else {
        return Err(anyhow::anyhow!(
            "Could not detect database backend from Cargo.toml"
        ));
    };
    let has_sea_orm = has_dependency(doc, "sea-orm");
    let has_tideway_db = has_tideway_feature(doc, "database");

    if has_sea_orm || has_tideway_db {
        Ok(DbBackend::SeaOrm)
    } else {
        Err(anyhow::anyhow!(error_contract(
            "Could not detect database backend.",
            "Add SeaORM dependencies and Tideway `database` feature.",
            "Pass `--db-backend sea-orm` explicitly."
        )))
    }
}

fn read_cargo_manifest(cargo_path: &Path) -> Option<toml_edit::DocumentMut> {
    let contents = fs::read_to_string(cargo_path).ok()?;
    contents.parse::<toml_edit::DocumentMut>().ok()
}

fn manifest_has_tideway_feature(cargo_doc: Option<&toml_edit::DocumentMut>, feature: &str) -> bool {
    let Some(doc) = cargo_doc else {
        return false;
    };
    has_tideway_feature(doc, feature)
}

fn manifest_has_dependency(cargo_doc: Option<&toml_edit::DocumentMut>, dependency: &str) -> bool {
    let Some(doc) = cargo_doc else {
        return false;
    };
    has_dependency(doc, dependency)
}

fn has_tideway_feature(doc: &toml_edit::DocumentMut, feature: &str) -> bool {
    dependency_sections(doc)
        .into_iter()
        .filter_map(|deps| deps.get("tideway"))
        .filter_map(|tideway| tideway.get("features"))
        .filter_map(|features| features.as_array())
        .any(|arr| arr.iter().any(|value| value.as_str() == Some(feature)))
}

fn has_dependency(doc: &toml_edit::DocumentMut, dependency: &str) -> bool {
    dependency_sections(doc)
        .into_iter()
        .any(|deps| deps.get(dependency).is_some())
}

fn dependency_sections(doc: &toml_edit::DocumentMut) -> Vec<&toml_edit::Item> {
    let mut sections = Vec::new();

    if let Some(item) = doc.get("dependencies") {
        sections.push(item);
    }

    if let Some(item) = doc.get("build-dependencies") {
        sections.push(item);
    }

    if let Some(item) = doc.get("dev-dependencies") {
        sections.push(item);
    }

    if let Some(targets) = doc.get("target").and_then(|item| item.as_table()) {
        for (_, target) in targets.iter() {
            if let Some(deps) = target.get("dependencies") {
                sections.push(deps);
            }
        }
    }

    sections
}

fn render_saas_owned_route_support_code() -> &'static str {
    r#"
#[derive(Debug, Clone)]
struct OwnedActor {
    organization_id: String,
    owner_id: String,
}

fn jwt_verifier() -> Result<&'static JwtVerifier<AccessTokenClaims>> {
    static VERIFIER: std::sync::OnceLock<std::result::Result<JwtVerifier<AccessTokenClaims>, String>> =
        std::sync::OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let secret = std::env::var("JWT_SECRET")
                .map_err(|_| "JWT auth is not configured".to_string())?;
            JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())
                .map(|verifier| {
                    verifier
                        .with_issuer(env!("CARGO_PKG_NAME"))
                        .with_audience(env!("CARGO_PKG_NAME"))
                })
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| TidewayError::Unauthorized(error.clone()))
}

async fn authenticated_user(headers: &HeaderMap, db: &DatabaseConnection) -> Result<user::Model> {
    let auth_header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| TidewayError::Unauthorized("Missing authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| TidewayError::Unauthorized("Invalid authorization header".into()))?;

    let token_data = jwt_verifier()?.verify_access_token(token).await?;

    let user_id = Uuid::parse_str(&token_data.claims.standard.sub)
        .map_err(|_| TidewayError::Unauthorized("Invalid user ID in token".into()))?;

    user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|error| TidewayError::Database(error.to_string()))?
        .ok_or_else(|| TidewayError::Unauthorized("User not found".into()))
}

async fn resolve_owned_actor(headers: &HeaderMap, db: &DatabaseConnection) -> Result<OwnedActor> {
    let user = authenticated_user(headers, db).await?;
    let membership = resolve_current_membership(headers, db, &user).await?;

    Ok(OwnedActor {
        organization_id: membership.organization_id,
        owner_id: user.id.to_string(),
    })
}

async fn resolve_current_membership(
    headers: &HeaderMap,
    db: &DatabaseConnection,
    user: &user::Model,
) -> Result<organization_member::Model> {
    if let Some(org_id) = headers
        .get("x-organization-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return organization_member::Entity::find()
            .filter(organization_member::Column::OrganizationId.eq(org_id))
            .filter(organization_member::Column::UserId.eq(user.id))
            .one(db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?
            .ok_or_else(|| TidewayError::NotFound("Organization not found".into()));
    }

    if let Some(org_id) = user.organization_id.as_deref() {
        if let Some(membership) = organization_member::Entity::find()
            .filter(organization_member::Column::OrganizationId.eq(org_id))
            .filter(organization_member::Column::UserId.eq(user.id))
            .one(db)
            .await
            .map_err(|error| TidewayError::Database(error.to_string()))?
        {
            return Ok(membership);
        }
    }

    let mut memberships = organization_member::Entity::find()
        .filter(organization_member::Column::UserId.eq(user.id))
        .all(db)
        .await
        .map_err(|error| TidewayError::Database(error.to_string()))?;

    match memberships.len() {
        0 => Err(TidewayError::Forbidden(
            "Organization membership required".into(),
        )),
        1 => Ok(memberships.remove(0)),
        _ => Err(TidewayError::BadRequest(
            "Multiple organizations found; send x-organization-id".into(),
        )),
    }
}
"#
}

fn render_saas_admin_route_support_code() -> &'static str {
    r#"
fn jwt_verifier() -> Result<&'static JwtVerifier<AccessTokenClaims>> {
    static VERIFIER: std::sync::OnceLock<std::result::Result<JwtVerifier<AccessTokenClaims>, String>> =
        std::sync::OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let secret = std::env::var("JWT_SECRET")
                .map_err(|_| "JWT auth is not configured".to_string())?;
            JwtVerifier::<AccessTokenClaims>::from_secret_checked(secret.as_bytes())
                .map(|verifier| {
                    verifier
                        .with_issuer(env!("CARGO_PKG_NAME"))
                        .with_audience(env!("CARGO_PKG_NAME"))
                })
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| TidewayError::Unauthorized(error.clone()))
}

async fn require_admin_access(headers: &HeaderMap, db: &DatabaseConnection) -> Result<()> {
    let auth_header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| TidewayError::Unauthorized("Missing authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| TidewayError::Unauthorized("Invalid authorization header".into()))?;

    let token_data = jwt_verifier()?.verify_access_token(token).await?;

    let user_id = Uuid::parse_str(&token_data.claims.standard.sub)
        .map_err(|_| TidewayError::Unauthorized("Invalid user ID in token".into()))?;

    let user = user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|error| TidewayError::Database(error.to_string()))?
        .ok_or_else(|| TidewayError::Unauthorized("User not found".into()))?;

    if !user.is_platform_admin {
        return Err(TidewayError::Forbidden("Admin access required".into()));
    }

    Ok(())
}
"#
}

#[allow(clippy::too_many_arguments)]
fn render_resource_module(
    resource_pascal: &str,
    resource_name: &str,
    resource_plural: &str,
    with_tests: bool,
    has_openapi: bool,
    profile: ResourceProfile,
    with_db: bool,
    with_repo: bool,
    with_service: bool,
    id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    context: ResourceGenerationContext,
) -> String {
    let body_extractor = "Json(body): Json<CreateRequest>";
    let schema = resource_schema(profile);
    let route_create_fields = route_request_fields(schema, profile, context, false);
    let route_update_fields = route_request_fields(schema, profile, context, true);
    let uses_shared_saas_owned_actor = context.shared_saas_actor && context.saas_owned_scope;
    let uses_shared_saas_admin_actor = context.shared_saas_actor && context.saas_admin_guard;
    let uses_inline_auth_helpers =
        (context.saas_owned_scope || context.saas_admin_guard) && !context.shared_saas_actor;
    let uses_auth_headers = context.saas_owned_scope || context.saas_admin_guard;
    let id_type_str = if matches!(id_type, ResourceIdType::Uuid) {
        "uuid::Uuid"
    } else {
        "i32"
    };
    let uuid_import = if matches!(id_type, ResourceIdType::Uuid) || uses_inline_auth_helpers {
        "use uuid::Uuid;\n"
    } else {
        ""
    };
    let create_id_field = if matches!(id_type, ResourceIdType::Uuid) {
        "        id: Set(Uuid::new_v4()),\n"
    } else {
        ""
    };
    let response_struct_fields = render_response_struct_fields(schema);
    let create_request_struct_fields = render_request_struct_fields(&route_create_fields, false);
    let update_request_struct_fields = render_request_struct_fields(&route_update_fields, true);
    let create_call_args = render_call_args(schema, "body", false);
    let update_call_args = render_call_args(schema, "body", true);
    let scoped_create_call_args = render_call_args_from_fields(&route_create_fields, "body");
    let scoped_update_call_args = render_call_args_from_fields(&route_update_fields, "body");
    let create_active_model_assignments =
        render_active_model_create_assignments(schema, "body", "        ");
    let update_active_model_assignments =
        render_active_model_update_assignments(schema, "body", "active", "    ");
    let response_init_fields = render_response_init_fields(schema, "model", "            ");
    let single_response_init_fields = render_response_init_fields(schema, "model", "        ");
    let stub_response_init_fields =
        render_stub_response_fields(schema, "        ", resource_pascal);
    let create_test_json_fields = render_create_test_json_fields_for_fields(&route_create_fields);
    let display_fallback = display_fallback_value(schema, resource_pascal);
    let timestamp_helper = render_timestamp_helper_if_needed(schema);
    let tests_block = if with_tests && !with_db {
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
            .json(&serde_json::json!({{ {create_test_json_fields} }}))
            .execute()
            .await
            .assert_ok();
    }}
}}
"#,
            resource_pascal = resource_pascal,
            resource_name = resource_name,
            resource_plural = resource_plural,
            create_test_json_fields = create_test_json_fields,
        )
    } else {
        String::new()
    };
    let mut openapi_import = String::new();
    if has_openapi {
        openapi_import.push_str("use utoipa::ToSchema;\n");
        if paginate {
            openapi_import.push_str("use utoipa::IntoParams;\n");
        }
    }

    let openapi_schema = if has_openapi {
        "#[derive(ToSchema)]"
    } else {
        ""
    };

    let openapi_paths = String::new();

    let openapi_attrs = if has_openapi {
        format!(
            r#"
#[utoipa::path(
    get,
    path = "/api/{resource_plural}",
    {pagination_params}
    responses((status = 200, body = [{resource_pascal}]))
)]
"#,
            resource_plural = resource_plural,
            resource_pascal = resource_pascal,
            pagination_params = if paginate {
                "params(PaginationParams),"
            } else {
                ""
            },
        )
    } else {
        String::new()
    };

    let openapi_attrs_get = if has_openapi {
        format!(
            r#"
#[utoipa::path(
    get,
    path = "/api/{resource_plural}/{{id}}",
    responses((status = 200, body = {resource_pascal}))
)]
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
#[utoipa::path(
    post,
    path = "/api/{resource_plural}",
    request_body = CreateRequest,
    responses((status = 200, body = MessageResponse))
)]
"#,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let openapi_attrs_update = if has_openapi {
        format!(
            r#"
#[utoipa::path(
    put,
    path = "/api/{resource_plural}/{{id}}",
    request_body = UpdateRequest,
    responses((status = 200, body = MessageResponse))
)]
"#,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let openapi_attrs_delete = if has_openapi {
        format!(
            r#"
#[utoipa::path(
    delete,
    path = "/api/{resource_plural}/{{id}}",
    responses((status = 200, body = MessageResponse))
)]
"#,
            resource_plural = resource_plural,
        )
    } else {
        String::new()
    };

    let extract_import = if with_db {
        if paginate {
            if uses_auth_headers {
                "extract::{Path, Query, State}, http::HeaderMap, "
            } else {
                "extract::{Path, Query, State}, "
            }
        } else {
            if uses_auth_headers {
                "extract::{Path, State}, http::HeaderMap, "
            } else {
                "extract::{Path, State}, "
            }
        }
    } else {
        ""
    };
    let sea_orm_imports = if uses_inline_auth_helpers {
        "use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};\n"
    } else if with_db {
        match (paginate, search) {
            (true, true) => {
                "use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};\n"
            }
            (true, false) => "use sea_orm::{ActiveModelTrait, EntityTrait, QuerySelect, Set};\n",
            (false, true) => {
                "use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};\n"
            }
            (false, false) => "use sea_orm::{ActiveModelTrait, EntityTrait, Set};\n",
        }
    } else {
        ""
    };
    let actor_import =
        if context.shared_saas_actor && (context.saas_owned_scope || context.saas_admin_guard) {
            "use crate::auth::RequestActor;\n"
        } else {
            ""
        };
    let entities_import = if uses_inline_auth_helpers && context.saas_owned_scope {
        "use crate::entities::{organization_member, user};\n".to_string()
    } else if uses_inline_auth_helpers && context.saas_admin_guard {
        "use crate::entities::user;\n".to_string()
    } else if with_db {
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

    let pagination_struct = if paginate {
        let attrs = if has_openapi {
            "#[derive(IntoParams)]"
        } else {
            ""
        };
        let mut struct_body = format!(
            r#"
#[derive(Deserialize)]
{attrs}
pub struct PaginationParams {{
    pub limit: Option<u64>,
    pub offset: Option<u64>,
"#,
            attrs = attrs
        );
        if search {
            struct_body.push_str("    pub q: Option<String>,\n");
        }
        struct_body.push_str("}\n");
        struct_body
    } else {
        String::new()
    };
    let list_params = if paginate {
        "Query(params): Query<PaginationParams>"
    } else {
        ""
    };
    let list_param_prefix = if paginate { ", " } else { "" };
    let list_args = if paginate {
        if search {
            "params.limit, params.offset, params.q"
        } else {
            "params.limit, params.offset"
        }
    } else {
        ""
    };
    let pagination_query = if paginate {
        let search_query = if search {
            render_search_query(resource_name, schema, "params.q")
        } else {
            String::new()
        };
        format!(
            "    query = query.limit(params.limit.unwrap_or(20).clamp(1, 100));\n    if let Some(offset) = params.offset {{ query = query.offset(offset); }}\n{search_query}",
            search_query = search_query
        )
    } else {
        String::new()
    };
    let query_binding = if pagination_query.is_empty() {
        format!("    let query = {resource_name}::Entity::find();")
    } else {
        format!("    let mut query = {resource_name}::Entity::find();")
    };
    let auth_support_code = if uses_inline_auth_helpers && context.saas_owned_scope {
        render_saas_owned_route_support_code().to_string()
    } else if uses_inline_auth_helpers && context.saas_admin_guard {
        render_saas_admin_route_support_code().to_string()
    } else {
        String::new()
    };
    let tideway_imports = if uses_inline_auth_helpers {
        "use tideway::{AppContext, MessageResponse, Result, RouteModule, TidewayError};\n"
    } else {
        "use tideway::{AppContext, MessageResponse, Result, RouteModule};\n"
    };
    let auth_imports = if uses_inline_auth_helpers {
        "use tideway::auth::{AccessTokenClaims, JwtVerifier};\n"
    } else {
        ""
    };
    let list_args_with_prefix = if list_args.is_empty() {
        String::new()
    } else {
        format!(", {list_args}")
    };

    let handlers = if uses_shared_saas_owned_actor && with_db && with_repo && with_service {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(
    State(ctx): State<AppContext>,
    headers: HeaderMap{list_param_prefix}{list_params},
) -> Result<Json<Vec<{resource_pascal}>>> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::for_current_organization(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let models = service.list_for_actor(&actor{list_args_with_prefix}).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::for_current_organization(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let model = service.get_required_for_actor(&actor, id).await?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    {body_extractor},
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::for_current_organization(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.create_for_actor(&actor, {scoped_create_call_args}).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::for_current_organization(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service
        .update_for_actor(&actor, id, {scoped_update_call_args})
        .await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::for_current_organization(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.delete_for_actor(&actor, id).await?;
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
            id_type_str = id_type_str,
            list_param_prefix = list_param_prefix,
            list_params = list_params,
            list_args_with_prefix = list_args_with_prefix,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            scoped_create_call_args = scoped_create_call_args,
            scoped_update_call_args = scoped_update_call_args,
        )
    } else if uses_inline_auth_helpers
        && context.saas_owned_scope
        && with_db
        && with_repo
        && with_service
    {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(
    State(ctx): State<AppContext>,
    headers: HeaderMap{list_param_prefix}{list_params},
) -> Result<Json<Vec<{resource_pascal}>>> {{
    let db = ctx.sea_orm_connection()?;
    let actor = resolve_owned_actor(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let models = service
        .list_owned(&actor.organization_id, &actor.owner_id{list_args_with_prefix})
        .await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let db = ctx.sea_orm_connection()?;
    let actor = resolve_owned_actor(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let model = service
        .get_required_owned(id, &actor.organization_id, &actor.owner_id)
        .await?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    {body_extractor},
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = resolve_owned_actor(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service
        .create_owned(&actor.organization_id, &actor.owner_id, {scoped_create_call_args})
        .await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = resolve_owned_actor(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service
        .update_owned(id, &actor.organization_id, &actor.owner_id, {scoped_update_call_args})
        .await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = resolve_owned_actor(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service
        .delete_owned(id, &actor.organization_id, &actor.owner_id)
        .await?;
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
            id_type_str = id_type_str,
            list_param_prefix = list_param_prefix,
            list_params = list_params,
            list_args_with_prefix = list_args_with_prefix,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            scoped_create_call_args = scoped_create_call_args,
            scoped_update_call_args = scoped_update_call_args,
        )
    } else if uses_shared_saas_admin_actor && with_db && with_repo && with_service {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(
    State(ctx): State<AppContext>,
    headers: HeaderMap{list_param_prefix}{list_params},
) -> Result<Json<Vec<{resource_pascal}>>> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::from_headers(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let models = service.list_for_admin(&actor{list_args_with_prefix}).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::from_headers(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let model = service.get_required_for_admin(&actor, id).await?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    {body_extractor},
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::from_headers(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.create_for_admin(&actor, {create_call_args}).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::from_headers(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.update_for_admin(&actor, id, {update_call_args}).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let actor = RequestActor::from_headers(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.delete_for_admin(&actor, id).await?;
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
            id_type_str = id_type_str,
            list_param_prefix = list_param_prefix,
            list_params = list_params,
            list_args_with_prefix = list_args_with_prefix,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            create_call_args = create_call_args,
            update_call_args = update_call_args,
        )
    } else if uses_inline_auth_helpers
        && context.saas_admin_guard
        && with_db
        && with_repo
        && with_service
    {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(
    State(ctx): State<AppContext>,
    headers: HeaderMap{list_param_prefix}{list_params},
) -> Result<Json<Vec<{resource_pascal}>>> {{
    let db = ctx.sea_orm_connection()?;
    require_admin_access(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let models = service.list({list_args}).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let db = ctx.sea_orm_connection()?;
    require_admin_access(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    let model = service.get_required(id).await?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    {body_extractor},
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    require_admin_access(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.create({create_call_args}).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    require_admin_access(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
    let service = {resource_pascal}Service::new(repo);
    service.update(id, {update_call_args}).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Path(id): Path<{id_type_str}>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    require_admin_access(&headers, &db).await?;
    let repo = {resource_pascal}Repository::new(db);
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
            id_type_str = id_type_str,
            list_param_prefix = list_param_prefix,
            list_params = list_params,
            list_args = list_args,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            create_call_args = create_call_args,
            update_call_args = update_call_args,
        )
    } else if with_db && with_repo && with_service {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(State(ctx): State<AppContext>{list_param_prefix}{list_params}) -> Result<Json<Vec<{resource_pascal}>>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    let models = service.list({list_args}).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    let model = service.get_required(id).await?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    {body_extractor},
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    service.create({create_call_args}).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let service = {resource_pascal}Service::new(repo);
    service.update(id, {update_call_args}).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
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
            id_type_str = id_type_str,
            list_param_prefix = list_param_prefix,
            list_params = list_params,
            list_args = list_args,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            create_call_args = create_call_args,
            update_call_args = update_call_args,
        )
    } else if with_db && with_repo {
        format!(
            r#"
{openapi_attrs}
async fn list_{resource_plural}(State(ctx): State<AppContext>{list_param_prefix}{list_params}) -> Result<Json<Vec<{resource_pascal}>>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let models = repo.list({list_args}).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    let model = repo
        .get(id)
        .await?
        .ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    {body_extractor},
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    repo.create({create_call_args}).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let repo = {resource_pascal}Repository::new(ctx.sea_orm_connection()?);
    repo.update(id, {update_call_args}).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
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
            id_type_str = id_type_str,
            list_param_prefix = list_param_prefix,
            list_params = list_params,
            list_args = list_args,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            create_call_args = create_call_args,
            update_call_args = update_call_args,
        )
    } else if with_db {
        format!(
            r#"
{timestamp_helper}

{openapi_attrs}
async fn list_{resource_plural}(State(ctx): State<AppContext>{list_param_prefix}{list_params}) -> Result<Json<Vec<{resource_pascal}>>> {{
    let db = ctx.sea_orm_connection()?;
{query_binding}
{pagination_query}
    let models = query.all(&db).await?;
    let items = models
        .into_iter()
        .map(|model| {resource_pascal} {{
{response_init_fields}        }})
        .collect();
    Ok(Json(items))
}}

{openapi_attrs_get}
async fn get_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
) -> Result<Json<{resource_pascal}>> {{
    let db = ctx.sea_orm_connection()?;
    let model = {resource_name}::Entity::find_by_id(id).one(&db).await?;
    let model = model.ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    Ok(Json({resource_pascal} {{
{single_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}(
    State(ctx): State<AppContext>,
    {body_extractor},
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let active = {resource_name}::ActiveModel {{
{create_id_field}{create_active_model_assignments}        ..Default::default()
    }};
    active.insert(&db).await?;
    Ok(MessageResponse::success("Created"))
}}

{openapi_attrs_update}
async fn update_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
    Json(body): Json<UpdateRequest>,
) -> Result<MessageResponse> {{
    let db = ctx.sea_orm_connection()?;
    let model = {resource_name}::Entity::find_by_id(id).one(&db).await?;
    let model = model.ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
    let mut active: {resource_name}::ActiveModel = model.into();
{update_active_model_assignments}    active.update(&db).await?;
    Ok(MessageResponse::success("Updated"))
}}

{openapi_attrs_delete}
async fn delete_{resource_name}(
    State(ctx): State<AppContext>,
    Path(id): Path<{id_type_str}>,
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
            id_type_str = id_type_str,
            list_params = list_params,
            list_param_prefix = list_param_prefix,
            query_binding = query_binding,
            pagination_query = pagination_query,
            response_init_fields = response_init_fields,
            single_response_init_fields = single_response_init_fields,
            timestamp_helper = timestamp_helper,
            create_id_field = create_id_field,
            create_active_model_assignments = create_active_model_assignments,
            update_active_model_assignments = update_active_model_assignments,
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
{stub_response_init_fields}    }}))
}}

{openapi_attrs_create}
async fn create_{resource_name}({body_extractor}) -> Result<MessageResponse> {{
    Ok(MessageResponse::success(format!("Created {{}}", body.{display_field})))
}}

{openapi_attrs_update}
async fn update_{resource_name}(Json(body): Json<UpdateRequest>) -> Result<MessageResponse> {{
    let {display_field} = body.{display_field}.unwrap_or_else(|| {display_fallback});
    Ok(MessageResponse::success(format!("Updated {{}}", {display_field})))
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
            stub_response_init_fields = stub_response_init_fields,
            display_field = schema.display_field,
            display_fallback = display_fallback,
        )
    };

    format!(
        r#"//! {resource_pascal} routes.

use axum::{{routing::get, {extract_import}Json, Router}};
use serde::{{Deserialize, Serialize}};
{tideway_imports}
{auth_imports}
{openapi_import}
{sea_orm_imports}
{uuid_import}
{actor_import}
{entities_import}
{repositories_import}
{services_import}

pub struct {resource_pascal}Module;

impl RouteModule for {resource_pascal}Module {{
    fn routes(&self) -> Router<AppContext> {{
        Router::new()
            .route("/", get(list_{resource_plural}).post(create_{resource_name}))
            .route("/{{id}}", get(get_{resource_name}).put(update_{resource_name}).delete(delete_{resource_name}))
    }}

    fn prefix(&self) -> Option<&str> {{
        Some("/api/{resource_plural}")
    }}
}}

#[derive(Debug, Serialize)]
{openapi_schema}
pub struct {resource_pascal} {{
{response_struct_fields}}}

#[derive(Deserialize)]
{openapi_schema}
pub struct CreateRequest {{
{create_request_struct_fields}}}

#[derive(Deserialize)]
{openapi_schema}
pub struct UpdateRequest {{
{update_request_struct_fields}}}

{pagination_struct}
{auth_support_code}
{handlers}
{tests_block}
{openapi_paths}
"#,
        resource_pascal = resource_pascal,
        resource_name = resource_name,
        resource_plural = resource_plural,
        tests_block = tests_block,
        tideway_imports = tideway_imports,
        auth_imports = auth_imports,
        openapi_import = openapi_import,
        openapi_schema = openapi_schema,
        openapi_paths = openapi_paths,
        pagination_struct = pagination_struct,
        auth_support_code = auth_support_code,
        handlers = handlers,
        extract_import = extract_import,
        sea_orm_imports = sea_orm_imports,
        uuid_import = uuid_import,
        actor_import = actor_import,
        entities_import = entities_import,
        repositories_import = repositories_import,
        services_import = services_import,
        response_struct_fields = response_struct_fields,
        create_request_struct_fields = create_request_struct_fields,
        update_request_struct_fields = update_request_struct_fields,
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
        write_file_with_force(&docs_path, &contents, false)?;
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

    let mut lines = contents
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
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
    write_file(&docs_path, &contents)
        .with_context(|| format!("Failed to write {}", docs_path.display()))?;
    print_success("Updated src/openapi_docs.rs");
    Ok(())
}

fn wire_entities_in_main(src_dir: &Path) -> Result<()> {
    wire_module_in_main(src_dir, "entities")
}

fn wire_routes_in_main(src_dir: &Path) -> Result<()> {
    wire_module_in_main(src_dir, "routes")
}

fn wire_repositories_in_main(src_dir: &Path) -> Result<()> {
    wire_module_in_main(src_dir, "repositories")
}

fn wire_services_in_main(src_dir: &Path) -> Result<()> {
    wire_module_in_main(src_dir, "services")
}

fn wire_module_in_main(src_dir: &Path, module_name: &str) -> Result<()> {
    let main_path = src_dir.join("main.rs");
    if !main_path.exists() {
        print_warning(&format!(
            "src/main.rs not found; skipping {module_name} wiring"
        ));
        return Ok(());
    }

    let contents = fs::read_to_string(&main_path)
        .with_context(|| format!("Failed to read {}", main_path.display()))?;
    let updated_contents = ensure_module_decl(&contents, module_name);
    if updated_contents == contents {
        return Ok(());
    }

    write_file(&main_path, &updated_contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    print_success(&format!("Added mod {module_name} to src/main.rs"));
    Ok(())
}

fn render_openapi_docs_file(paths: &[String]) -> String {
    let mut output = String::new();
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
    id_type: ResourceIdType,
    profile: ResourceProfile,
) -> Result<()> {
    let src_dir = project_dir.join("src");
    let entities_dir = src_dir.join("entities");
    ensure_dir(&entities_dir)
        .with_context(|| format!("Failed to create {}", entities_dir.display()))?;

    let entities_mod = entities_dir.join("mod.rs");
    if !entities_mod.exists() {
        let contents = "//! Database entities.\n\n";
        write_file_with_force(&entities_mod, contents, false)?;
        print_success("Created src/entities/mod.rs");
    }
    wire_entities_mod(&entities_mod, resource_name)?;

    let entity_path = entities_dir.join(format!("{}.rs", resource_name));
    let entity_contents = render_sea_orm_entity(resource_name, resource_plural, id_type, profile);
    write_file_with_force(&entity_path, &entity_contents, false)?;

    let migration_root = project_dir.join("migration");
    let migration_src = migration_root.join("src");
    if !migration_src.exists() {
        ensure_dir(&migration_src)
            .with_context(|| format!("Failed to create {}", migration_src.display()))?;
    }
    if !migration_root.join("Cargo.toml").exists() {
        print_warning("migration/Cargo.toml not found (run `sea-orm-cli migrate init` if needed)");
    }

    let (migration_mod, migration_file) = next_migration_name(&migration_src, resource_plural)?;
    let migration_contents = render_sea_orm_migration(resource_plural, id_type, profile);
    let migration_path = migration_src.join(&migration_file);
    write_file_with_force(&migration_path, &migration_contents, false)?;

    let migration_lib = migration_src.join("lib.rs");
    if !migration_lib.exists() {
        let contents = render_migration_lib(&migration_mod);
        write_file_with_force(&migration_lib, &contents, false)?;
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
        write_file(mod_path, &contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn render_sea_orm_entity(
    resource_name: &str,
    resource_plural: &str,
    id_type: ResourceIdType,
    profile: ResourceProfile,
) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    let schema = resource_schema(profile);
    let entity_fields = render_entity_fields(schema);
    let id_field = if matches!(id_type, ResourceIdType::Uuid) {
        "    #[sea_orm(primary_key, auto_increment = false)]\n    pub id: Uuid,\n"
    } else {
        "    #[sea_orm(primary_key, auto_increment = true)]\n    pub id: i32,\n"
    };
    let uuid_import = if matches!(id_type, ResourceIdType::Uuid) {
        "use uuid::Uuid;\n"
    } else {
        ""
    };
    format!(
        r#"//! SeaORM entity for {resource_pascal}.

use sea_orm::entity::prelude::*;
{uuid_import}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "{resource_plural}")]
pub struct Model {{
{id_field}
{entity_fields}}}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {{}}

impl ActiveModelBehavior for ActiveModel {{}}
"#,
        resource_pascal = resource_pascal,
        resource_plural = resource_plural,
        id_field = id_field,
        uuid_import = uuid_import,
        entity_fields = entity_fields,
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
            let number_part = stem.trim_start_matches('m').split('_').next().unwrap_or("");
            if number_part.chars().all(|c| c.is_ascii_digit())
                && !number_part.is_empty()
                && let Ok(num) = number_part.parse::<u64>()
            {
                max_num = max_num.max(num);
                width = width.max(number_part.len());
            }
        }
    }

    let next = max_num + 1;
    let prefix = format!("m{:0width$}", next, width = width);
    let mod_name = format!("{prefix}_create_{resource_plural}");
    let file_name = format!("{mod_name}.rs");
    Ok((mod_name, file_name))
}

fn render_sea_orm_migration(
    resource_plural: &str,
    id_type: ResourceIdType,
    profile: ResourceProfile,
) -> String {
    let table_enum = to_pascal_case(resource_plural);
    let schema = resource_schema(profile);
    let columns = render_migration_columns(schema, &table_enum);
    let column_idents = render_migration_idents(schema);
    let id_column = if matches!(id_type, ResourceIdType::Uuid) {
        format!(
            "ColumnDef::new({table_enum}::Id)\n                            .uuid()\n                            .not_null()\n                            .primary_key()"
        )
    } else {
        format!(
            "ColumnDef::new({table_enum}::Id)\n                            .integer()\n                            .not_null()\n                            .auto_increment()\n                            .primary_key()"
        )
    };
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
                        {id_column},
                    )
{columns}                    .to_owned(),
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
{column_idents}}}
"#,
        table_enum = table_enum,
        id_column = id_column,
        columns = columns,
        column_idents = column_idents,
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
    let mut contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let mod_line = format!("mod {};", mod_name);
    if !contents.contains(&mod_line) {
        let mut lines = contents
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        let mut insert_at = None;
        for (idx, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("mod ") {
                insert_at = Some(idx + 1);
            }
        }
        let insert_at = insert_at.unwrap_or_else(|| {
            lines
                .iter()
                .position(|line| line.contains("sea_orm_migration::prelude"))
                .map(|idx| idx + 1)
                .unwrap_or(0)
        });
        lines.insert(insert_at, mod_line);
        contents = lines.join("\n");
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }

    if !contents.contains(&format!("{}::Migration", mod_name)) {
        let mut lines = contents
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
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
            lines.insert(
                end,
                format!("{entry_indent}Box::new({}::Migration),", mod_name),
            );
            contents = lines.join("\n");
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
        } else if let Some(line_idx) = lines.iter().position(|line| line.contains("vec![]")) {
            let base_indent = lines[line_idx]
                .chars()
                .take_while(|c| c.is_whitespace())
                .collect::<String>();
            let entry_indent = format!("{base_indent}    ");
            lines.splice(
                line_idx..=line_idx,
                [
                    format!("{base_indent}vec!["),
                    format!("{entry_indent}Box::new({}::Migration),", mod_name),
                    format!("{base_indent}]"),
                ],
            );
            contents = lines.join("\n");
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
        } else {
            print_warning("Could not find migrations vector in migration/src/lib.rs");
        }
    }

    write_file(path, &contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}
fn wire_routes_mod(routes_dir: &Path, resource_name: &str) -> Result<()> {
    let mod_path = routes_dir.join("mod.rs");
    if !mod_path.exists() {
        let contents = "//! Route modules.\n";
        write_file_with_force(&mod_path, contents, false)?;
        print_success("Created src/routes/mod.rs");
    }

    let mut contents = fs::read_to_string(&mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        write_file(&mod_path, &contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn generate_repository(
    project_dir: &Path,
    resource_name: &str,
    id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    profile: ResourceProfile,
    context: ResourceGenerationContext,
) -> Result<()> {
    let src_dir = project_dir.join("src");
    let repos_dir = src_dir.join("repositories");
    ensure_dir(&repos_dir).with_context(|| format!("Failed to create {}", repos_dir.display()))?;

    let repos_mod = repos_dir.join("mod.rs");
    if !repos_mod.exists() {
        let contents = "//! Repository layer.\n\n";
        write_file_with_force(&repos_mod, contents, false)?;
        print_success("Created src/repositories/mod.rs");
    }
    wire_repositories_mod(&repos_mod, resource_name)?;

    let repo_path = repos_dir.join(format!("{}.rs", resource_name));
    let repo_contents =
        render_repository(resource_name, id_type, paginate, search, profile, context);
    write_file_with_force(&repo_path, &repo_contents, false)?;
    print_success("Generated repository");
    Ok(())
}

fn wire_repositories_mod(mod_path: &Path, resource_name: &str) -> Result<()> {
    let mut contents = fs::read_to_string(mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        write_file(mod_path, &contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn render_repository(
    resource_name: &str,
    id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    profile: ResourceProfile,
    context: ResourceGenerationContext,
) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    let schema = resource_schema(profile);
    let current_timestamp_helper = render_timestamp_helper_if_needed(schema);
    let (id_type_str, uuid_import) = if matches!(id_type, ResourceIdType::Uuid) {
        ("uuid::Uuid", "use uuid::Uuid;\n")
    } else {
        ("i32", "")
    };
    let create_id_field = if matches!(id_type, ResourceIdType::Uuid) {
        "            id: Set(Uuid::new_v4()),\n"
    } else {
        ""
    };
    let list_signature = render_repository_list_signature(resource_name, schema, paginate, search);
    let list_params = render_repository_list_body(resource_name, schema, paginate, search);
    let create_signature_args = render_create_signature_args(schema, false);
    let update_signature_args = render_create_signature_args(schema, true);
    let create_assignments = render_param_create_assignments(schema, "            ");
    let update_assignments = render_param_update_assignments(schema, "active", "        ");
    let sea_orm_imports = if context.saas_owned_scope {
        if paginate {
            "use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};"
        } else {
            "use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};"
        }
    } else {
        match (paginate, search) {
            (true, true) => {
                "use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};"
            }
            (true, false) => "use sea_orm::{ActiveModelTrait, EntityTrait, QuerySelect, Set};",
            (false, true) => {
                "use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};"
            }
            (false, false) => "use sea_orm::{ActiveModelTrait, EntityTrait, Set};",
        }
    };
    let scoped_methods = if context.saas_owned_scope {
        let scoped_list_signature = if paginate {
            if search {
                format!(
                    "pub async fn list_owned(&self, organization_id: &str, owner_id: &str, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<{resource_name}::Model>> {{"
                )
            } else {
                format!(
                    "pub async fn list_owned(&self, organization_id: &str, owner_id: &str, limit: Option<u64>, offset: Option<u64>) -> Result<Vec<{resource_name}::Model>> {{"
                )
            }
        } else {
            format!(
                "pub async fn list_owned(&self, organization_id: &str, owner_id: &str) -> Result<Vec<{resource_name}::Model>> {{"
            )
        };
        let scoped_search_query = if search {
            render_search_query(resource_name, schema, "search")
        } else {
            String::new()
        };
        let scoped_list_body = if paginate {
            format!(
                "        let mut query = {resource_name}::Entity::find()\n            .filter({resource_name}::Column::OrganizationId.eq(organization_id.to_string()))\n            .filter({resource_name}::Column::OwnerId.eq(owner_id.to_string()));\n        query = query.limit(limit.unwrap_or(20).clamp(1, 100));\n        if let Some(offset) = offset {{ query = query.offset(offset); }}\n{scoped_search_query}        Ok(query.all(&self.db).await?)",
            )
        } else {
            format!(
                "        Ok({resource_name}::Entity::find()\n            .filter({resource_name}::Column::OrganizationId.eq(organization_id.to_string()))\n            .filter({resource_name}::Column::OwnerId.eq(owner_id.to_string()))\n            .all(&self.db)\n            .await?)"
            )
        };

        format!(
            r#"
    {scoped_list_signature}
{scoped_list_body}
    }}

    pub async fn get_owned(
        &self,
        id: {id_type},
        organization_id: &str,
        owner_id: &str,
    ) -> Result<Option<{resource_name}::Model>> {{
        Ok({resource_name}::Entity::find_by_id(id)
            .filter({resource_name}::Column::OrganizationId.eq(organization_id.to_string()))
            .filter({resource_name}::Column::OwnerId.eq(owner_id.to_string()))
            .one(&self.db)
            .await?)
    }}
"#,
            scoped_list_signature = scoped_list_signature,
            scoped_list_body = scoped_list_body,
            resource_name = resource_name,
            id_type = id_type_str,
        )
    } else {
        String::new()
    };
    format!(
        r#"{sea_orm_imports}
use tideway::Result;
{uuid_import}
{current_timestamp_helper}

use crate::entities::{resource_name};

pub struct {resource_pascal}Repository {{
    db: sea_orm::DatabaseConnection,
}}

impl {resource_pascal}Repository {{
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {{
        Self {{ db }}
    }}

    {list_signature}
{list_params}
    }}
{scoped_methods}

    pub async fn get(&self, id: {id_type}) -> Result<Option<{resource_name}::Model>> {{
        Ok({resource_name}::Entity::find_by_id(id).one(&self.db).await?)
    }}

    pub async fn create(&self, {create_signature_args}) -> Result<{resource_name}::Model> {{
        let active = {resource_name}::ActiveModel {{
{create_id_field}
{create_assignments}            ..Default::default()
        }};
        Ok(active.insert(&self.db).await?)
    }}

    pub async fn update(
        &self,
        id: {id_type},
        {update_signature_args},
    ) -> Result<{resource_name}::Model> {{
        let model = {resource_name}::Entity::find_by_id(id).one(&self.db).await?;
        let model =
            model.ok_or_else(|| tideway::TidewayError::not_found("{resource_pascal} not found"))?;
        let mut active: {resource_name}::ActiveModel = model.into();
{update_assignments}        Ok(active.update(&self.db).await?)
    }}

    pub async fn delete(&self, id: {id_type}) -> Result<()> {{
        {resource_name}::Entity::delete_by_id(id)
            .exec(&self.db)
            .await?;
        Ok(())
    }}
}}
"#,
        resource_name = resource_name,
        resource_pascal = resource_pascal,
        id_type = id_type_str,
        uuid_import = uuid_import,
        create_id_field = create_id_field,
        list_signature = list_signature,
        list_params = list_params,
        sea_orm_imports = sea_orm_imports,
        current_timestamp_helper = current_timestamp_helper,
        scoped_methods = scoped_methods,
        create_signature_args = create_signature_args,
        update_signature_args = update_signature_args,
        create_assignments = create_assignments,
        update_assignments = update_assignments,
    )
}

fn generate_service(
    project_dir: &Path,
    resource_name: &str,
    id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    profile: ResourceProfile,
    context: ResourceGenerationContext,
) -> Result<()> {
    let src_dir = project_dir.join("src");
    let services_dir = src_dir.join("services");
    ensure_dir(&services_dir)
        .with_context(|| format!("Failed to create {}", services_dir.display()))?;

    let services_mod = services_dir.join("mod.rs");
    if !services_mod.exists() {
        let contents = "//! Service layer.\n\n";
        write_file_with_force(&services_mod, contents, false)?;
        print_success("Created src/services/mod.rs");
    }
    wire_services_mod(&services_mod, resource_name)?;

    let service_path = services_dir.join(format!("{}.rs", resource_name));
    let service_contents =
        render_service(resource_name, id_type, paginate, search, profile, context);
    write_file_with_force(&service_path, &service_contents, false)?;
    print_success("Generated service");
    Ok(())
}

fn wire_services_mod(mod_path: &Path, resource_name: &str) -> Result<()> {
    let mut contents = fs::read_to_string(mod_path)
        .with_context(|| format!("Failed to read {}", mod_path.display()))?;
    let mod_line = format!("pub mod {};", resource_name);
    if !contents.contains(&mod_line) {
        contents.push_str(&format!("\n{}\n", mod_line));
        write_file(mod_path, &contents)
            .with_context(|| format!("Failed to write {}", mod_path.display()))?;
    }
    Ok(())
}

fn render_service(
    resource_name: &str,
    id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    profile: ResourceProfile,
    context: ResourceGenerationContext,
) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    let schema = resource_schema(profile);
    let uses_shared_saas_owned_actor = context.shared_saas_actor && context.saas_owned_scope;
    let uses_shared_saas_admin_actor = context.shared_saas_actor && context.saas_admin_guard;
    let route_create_fields = route_request_fields(schema, profile, context, false);
    let route_update_fields = route_request_fields(schema, profile, context, true);
    let create_signature_args = render_create_signature_args(schema, false);
    let update_signature_args = render_create_signature_args(schema, true);
    let create_call_args = render_param_names(schema, false);
    let update_call_args = render_param_names(schema, true);
    let create_normalization_lines = render_service_string_normalization_lines(schema, false);
    let update_normalization_lines = render_service_string_normalization_lines(schema, true);
    let validation_helpers = render_service_validation_helpers(schema);
    let id_type_str = if matches!(id_type, ResourceIdType::Uuid) {
        "uuid::Uuid"
    } else {
        "i32"
    };
    let uuid_import = if matches!(id_type, ResourceIdType::Uuid) {
        "use uuid::Uuid;\n"
    } else {
        ""
    };
    let actor_import = if uses_shared_saas_owned_actor || uses_shared_saas_admin_actor {
        "use crate::auth::RequestActor;\n"
    } else {
        ""
    };
    let audit_event_struct = if uses_shared_saas_owned_actor || uses_shared_saas_admin_actor {
        format!(
            r#"
#[derive(Debug, Clone)]
pub struct {resource_pascal}AuditEvent {{
    pub action: &'static str,
    pub actor_id: String,
    pub organization_id: Option<String>,
    pub resource: &'static str,
    pub resource_id: String,
}}
"#
        )
    } else {
        String::new()
    };
    let list_signature = if paginate {
        if search {
            format!(
                "pub async fn list(&self, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
            )
        } else {
            format!(
                "pub async fn list(&self, limit: Option<u64>, offset: Option<u64>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
            )
        }
    } else {
        format!(
            "pub async fn list(&self) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
        )
    };
    let list_body = if paginate {
        if search {
            "        self.repo.list(limit, offset, search).await"
        } else {
            "        self.repo.list(limit, offset).await"
        }
    } else {
        "        self.repo.list().await"
    };
    let owned_methods = if context.saas_owned_scope {
        let owned_list_signature = if paginate {
            if search {
                format!(
                    "pub async fn list_owned(&self, organization_id: &str, owner_id: &str, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
                )
            } else {
                format!(
                    "pub async fn list_owned(&self, organization_id: &str, owner_id: &str, limit: Option<u64>, offset: Option<u64>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
                )
            }
        } else {
            format!(
                "pub async fn list_owned(&self, organization_id: &str, owner_id: &str) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
            )
        };
        let owned_list_call = if paginate {
            if search {
                "        self.repo.list_owned(&organization_id, &owner_id, limit, offset, search).await"
            } else {
                "        self.repo.list_owned(&organization_id, &owner_id, limit, offset).await"
            }
        } else {
            "        self.repo.list_owned(&organization_id, &owner_id).await"
        };
        let owned_create_signature = render_signature_args_from_fields(&route_create_fields, false);
        let owned_update_signature = render_signature_args_from_fields(&route_update_fields, true);
        let owned_create_args = render_param_names_from_fields(&route_create_fields);
        let owned_update_args = render_param_names_from_fields(&route_update_fields);

        format!(
            r#"
    {owned_list_signature}
        let organization_id = Self::normalize_required_string("organization_id", organization_id.to_string())?;
        let owner_id = Self::normalize_required_string("owner_id", owner_id.to_string())?;
{owned_list_call}
    }}

    fn ensure_owned_access(
        model: crate::entities::{resource_name}::Model,
        organization_id: &str,
        owner_id: &str,
    ) -> Result<crate::entities::{resource_name}::Model> {{
        ensure!(
            model.organization_id == organization_id,
            TidewayError::not_found("{resource_pascal} not found")
        );
        ensure!(
            model.owner_id == owner_id,
            TidewayError::forbidden("{resource_pascal} belongs to another user")
        );
        Ok(model)
    }}

    pub async fn get_required_owned(
        &self,
        id: {id_type},
        organization_id: &str,
        owner_id: &str,
    ) -> Result<crate::entities::{resource_name}::Model> {{
        let organization_id = Self::normalize_required_string("organization_id", organization_id.to_string())?;
        let owner_id = Self::normalize_required_string("owner_id", owner_id.to_string())?;
        let model = self.repo
            .get(id)
            .await?
            .ok_or_else(|| TidewayError::not_found("{resource_pascal} not found"))?;
        Self::ensure_owned_access(model, &organization_id, &owner_id)
    }}

    pub async fn create_owned(
        &self,
        organization_id: &str,
        owner_id: &str,
        {owned_create_signature},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        self.create(
            organization_id.to_string(),
            owner_id.to_string(),
            {owned_create_args},
        )
        .await
    }}

    pub async fn update_owned(
        &self,
        id: {id_type},
        organization_id: &str,
        owner_id: &str,
        {owned_update_signature},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        let organization_id = Self::normalize_required_string("organization_id", organization_id.to_string())?;
        let owner_id = Self::normalize_required_string("owner_id", owner_id.to_string())?;
        self.get_required_owned(id, &organization_id, &owner_id).await?;
        self.update(id, Some(organization_id), Some(owner_id), {owned_update_args}).await
    }}

    pub async fn delete_owned(&self, id: {id_type}, organization_id: &str, owner_id: &str) -> Result<()> {{
        self.get_required_owned(id, organization_id, owner_id).await?;
        self.repo.delete(id).await
    }}
"#,
            owned_list_signature = owned_list_signature,
            owned_list_call = owned_list_call,
            id_type = id_type_str,
            resource_name = resource_name,
            resource_pascal = resource_pascal,
            owned_create_signature = owned_create_signature,
            owned_update_signature = owned_update_signature,
            owned_create_args = owned_create_args,
            owned_update_args = owned_update_args,
        )
    } else {
        String::new()
    };
    let owned_actor_methods = if uses_shared_saas_owned_actor {
        let actor_list_signature = if paginate {
            if search {
                format!(
                    "pub async fn list_for_actor(&self, actor: &RequestActor, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
                )
            } else {
                format!(
                    "pub async fn list_for_actor(&self, actor: &RequestActor, limit: Option<u64>, offset: Option<u64>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
                )
            }
        } else {
            format!(
                "pub async fn list_for_actor(&self, actor: &RequestActor) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
            )
        };
        let actor_list_call = if paginate {
            if search {
                "        self.list_owned(organization_id, &owner_id, limit, offset, search).await"
            } else {
                "        self.list_owned(organization_id, &owner_id, limit, offset).await"
            }
        } else {
            "        self.list_owned(organization_id, &owner_id).await"
        };
        let owned_create_signature = render_signature_args_from_fields(&route_create_fields, false);
        let owned_update_signature = render_signature_args_from_fields(&route_update_fields, true);
        let owned_create_args = render_param_names_from_fields(&route_create_fields);
        let owned_update_args = render_param_names_from_fields(&route_update_fields);

        format!(
            r#"
    {actor_list_signature}
        let organization_id = actor.organization_id()?;
        let owner_id = actor.owner_id();
{actor_list_call}
    }}

    fn build_owned_audit_event(
        actor: &RequestActor,
        action: &'static str,
        model: &crate::entities::{resource_name}::Model,
    ) -> Result<{resource_pascal}AuditEvent> {{
        Ok({resource_pascal}AuditEvent {{
            action,
            actor_id: actor.owner_id(),
            organization_id: Some(actor.organization_id()?.to_string()),
            resource: "{resource_name}",
            resource_id: model.id.to_string(),
        }})
    }}

    async fn audit_owned_write(
        &self,
        event: &{resource_pascal}AuditEvent,
        model: &crate::entities::{resource_name}::Model,
    ) -> Result<()> {{
        // Hook audit logging, events, or other side effects here.
        let _ = (event, model);
        Ok(())
    }}

    pub async fn get_required_for_actor(
        &self,
        actor: &RequestActor,
        id: {id_type},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        let organization_id = actor.organization_id()?;
        let owner_id = actor.owner_id();
        self.get_required_owned(id, organization_id, &owner_id).await
    }}

    pub async fn create_for_actor(
        &self,
        actor: &RequestActor,
        {owned_create_signature},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        let organization_id = actor.organization_id()?;
        let owner_id = actor.owner_id();
        let model = self
            .create_owned(organization_id, &owner_id, {owned_create_args})
            .await?;
        let event = Self::build_owned_audit_event(actor, "create", &model)?;
        self.audit_owned_write(&event, &model).await?;
        Ok(model)
    }}

    pub async fn update_for_actor(
        &self,
        actor: &RequestActor,
        id: {id_type},
        {owned_update_signature},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        let organization_id = actor.organization_id()?;
        let owner_id = actor.owner_id();
        let model = self
            .update_owned(id, organization_id, &owner_id, {owned_update_args})
            .await?;
        let event = Self::build_owned_audit_event(actor, "update", &model)?;
        self.audit_owned_write(&event, &model).await?;
        Ok(model)
    }}

    pub async fn delete_for_actor(&self, actor: &RequestActor, id: {id_type}) -> Result<()> {{
        let model = self.get_required_for_actor(actor, id).await?;
        let organization_id = actor.organization_id()?;
        let owner_id = actor.owner_id();
        let event = Self::build_owned_audit_event(actor, "delete", &model)?;
        self.delete_owned(id, organization_id, &owner_id).await?;
        self.audit_owned_write(&event, &model).await
    }}
"#,
            actor_list_signature = actor_list_signature,
            actor_list_call = actor_list_call,
            id_type = id_type_str,
            resource_name = resource_name,
            owned_create_signature = owned_create_signature,
            owned_update_signature = owned_update_signature,
            owned_create_args = owned_create_args,
            owned_update_args = owned_update_args,
        )
    } else {
        String::new()
    };
    let admin_actor_methods = if uses_shared_saas_admin_actor {
        let admin_list_signature = if paginate {
            if search {
                format!(
                    "pub async fn list_for_admin(&self, actor: &RequestActor, limit: Option<u64>, offset: Option<u64>, search: Option<String>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
                )
            } else {
                format!(
                    "pub async fn list_for_admin(&self, actor: &RequestActor, limit: Option<u64>, offset: Option<u64>) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
                )
            }
        } else {
            format!(
                "pub async fn list_for_admin(&self, actor: &RequestActor) -> Result<Vec<crate::entities::{resource_name}::Model>> {{"
            )
        };
        let admin_list_call = if paginate {
            if search {
                "        self.list(limit, offset, search).await"
            } else {
                "        self.list(limit, offset).await"
            }
        } else {
            "        self.list().await"
        };

        format!(
            r#"
    {admin_list_signature}
        actor.require_admin()?;
{admin_list_call}
    }}

    fn build_admin_audit_event(
        actor: &RequestActor,
        action: &'static str,
        model: &crate::entities::{resource_name}::Model,
    ) -> Result<{resource_pascal}AuditEvent> {{
        Ok({resource_pascal}AuditEvent {{
            action,
            actor_id: actor.user.id.to_string(),
            organization_id: None,
            resource: "{resource_name}",
            resource_id: model.id.to_string(),
        }})
    }}

    async fn audit_admin_write(
        &self,
        event: &{resource_pascal}AuditEvent,
        model: &crate::entities::{resource_name}::Model,
    ) -> Result<()> {{
        // Hook audit logging, events, or other side effects here.
        let _ = (event, model);
        Ok(())
    }}

    pub async fn get_required_for_admin(
        &self,
        actor: &RequestActor,
        id: {id_type},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        actor.require_admin()?;
        self.get_required(id).await
    }}

    pub async fn create_for_admin(
        &self,
        actor: &RequestActor,
        {create_signature_args},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        actor.require_admin()?;
        let model = self.create({create_call_args}).await?;
        let event = Self::build_admin_audit_event(actor, "create", &model)?;
        self.audit_admin_write(&event, &model).await?;
        Ok(model)
    }}

    pub async fn update_for_admin(
        &self,
        actor: &RequestActor,
        id: {id_type},
        {update_signature_args},
    ) -> Result<crate::entities::{resource_name}::Model> {{
        actor.require_admin()?;
        let model = self.update(id, {update_call_args}).await?;
        let event = Self::build_admin_audit_event(actor, "update", &model)?;
        self.audit_admin_write(&event, &model).await?;
        Ok(model)
    }}

    pub async fn delete_for_admin(&self, actor: &RequestActor, id: {id_type}) -> Result<()> {{
        actor.require_admin()?;
        let model = self.get_required(id).await?;
        let event = Self::build_admin_audit_event(actor, "delete", &model)?;
        self.delete(id).await?;
        self.audit_admin_write(&event, &model).await
    }}
"#,
            admin_list_signature = admin_list_signature,
            admin_list_call = admin_list_call,
            id_type = id_type_str,
            resource_name = resource_name,
            create_signature_args = create_signature_args,
            create_call_args = create_call_args,
            update_signature_args = update_signature_args,
            update_call_args = update_call_args,
        )
    } else {
        String::new()
    };
    format!(
        r#"use tideway::{{ensure, Result, TidewayError}};
{uuid_import}
{actor_import}

use crate::repositories::{resource_name}::{resource_pascal}Repository;
{audit_event_struct}

pub struct {resource_pascal}Service {{
    repo: {resource_pascal}Repository,
}}

impl {resource_pascal}Service {{
    pub fn new(repo: {resource_pascal}Repository) -> Self {{
        Self {{ repo }}
    }}

    {list_signature}
{list_body}
    }}
{owned_methods}
{owned_actor_methods}
{admin_actor_methods}

    pub async fn get(&self, id: {id_type}) -> Result<Option<crate::entities::{resource_name}::Model>> {{
        self.repo.get(id).await
    }}

    pub async fn get_required(&self, id: {id_type}) -> Result<crate::entities::{resource_name}::Model> {{
        self.repo
            .get(id)
            .await?
            .ok_or_else(|| TidewayError::not_found("{resource_pascal} not found"))
    }}

    pub async fn create(&self, {create_signature_args}) -> Result<crate::entities::{resource_name}::Model> {{
{create_normalization_lines}        self.repo.create({create_call_args}).await
    }}

    pub async fn update(
        &self,
        id: {id_type},
        {update_signature_args},
    ) -> Result<crate::entities::{resource_name}::Model> {{
{update_normalization_lines}        self.repo.update(id, {update_call_args}).await
    }}

    pub async fn delete(&self, id: {id_type}) -> Result<()> {{
        self.get_required(id).await?;
        self.repo.delete(id).await
    }}
{validation_helpers}}}
"#,
        resource_name = resource_name,
        resource_pascal = resource_pascal,
        id_type = id_type_str,
        uuid_import = uuid_import,
        actor_import = actor_import,
        audit_event_struct = audit_event_struct,
        list_signature = list_signature,
        list_body = list_body,
        create_signature_args = create_signature_args,
        update_signature_args = update_signature_args,
        create_call_args = create_call_args,
        update_call_args = update_call_args,
        create_normalization_lines = create_normalization_lines,
        update_normalization_lines = update_normalization_lines,
        validation_helpers = validation_helpers,
        owned_methods = owned_methods,
        owned_actor_methods = owned_actor_methods,
        admin_actor_methods = admin_actor_methods,
    )
}

fn generate_repository_tests(
    project_dir: &Path,
    project_name: &str,
    resource_name: &str,
    id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    profile: ResourceProfile,
) -> Result<()> {
    let tests_dir = project_dir.join("tests");
    ensure_dir(&tests_dir).with_context(|| format!("Failed to create {}", tests_dir.display()))?;

    let file_path = tests_dir.join(format!("repository_{}.rs", resource_name));
    let contents = render_repository_tests(
        project_name,
        resource_name,
        id_type,
        paginate,
        search,
        profile,
    );
    write_file_with_force(&file_path, &contents, false)?;
    print_success("Generated repository tests");
    Ok(())
}

fn render_repository_tests(
    project_name: &str,
    resource_name: &str,
    _id_type: ResourceIdType,
    paginate: bool,
    search: bool,
    profile: ResourceProfile,
) -> String {
    let resource_pascal = to_pascal_case(resource_name);
    let schema = resource_schema(profile);
    let create_call_args = render_stub_call_args(schema, false);
    let list_call = if paginate {
        if search {
            format!(
                "repo.list(Some(20), Some(0), Some({})).await?",
                render_search_stub_value(schema)
            )
        } else {
            "repo.list(Some(20), Some(0)).await?".to_string()
        }
    } else {
        "repo.list().await?".to_string()
    };
    r#"use tideway::testing::{TestDb, TestDbBackend, TestDbConfig};
use tideway::Result;

use {project_name}::repositories::{resource_name}::{resource_pascal}Repository;

async fn build_test_db() -> Result<TestDb> {
    let backend = std::env::var("TIDEWAY_TEST_DB_BACKEND")
        .unwrap_or_else(|_| "postgres".to_string());

    match backend.as_str() {
        "sqlite" => TestDb::new_with_config(TestDbConfig {
            backend: TestDbBackend::SqliteMemory,
            database_url: None,
        })
        .await,
        "postgres_container" => {
            #[cfg(feature = "test-containers")]
            {
                TestDb::new_with_config(TestDbConfig {
                    backend: TestDbBackend::PostgresContainer,
                    database_url: None,
                })
                .await
            }
            #[cfg(not(feature = "test-containers"))]
            {
                panic!("Enable the tideway `test-containers` feature to run postgres_container profile");
            }
        }
        "postgres" => {
            let database_url = match std::env::var("TIDEWAY_TEST_DATABASE_URL") {
                Ok(url) => Some(url),
                Err(_) => std::env::var("TEST_DATABASE_URL").ok(),
            };

            TestDb::new_with_config(TestDbConfig {
                backend: TestDbBackend::Postgres,
                database_url,
            })
            .await
        }
        _ => TestDb::new_postgres().await,
    }
}

#[tokio::test]
#[ignore = "Configure a DB-backed profile: TIDEWAY_TEST_DB_BACKEND=postgres (default) or postgres_container (requires tideway test-containers). Set TIDEWAY_TEST_DATABASE_URL or TEST_DATABASE_URL if needed."]
async fn repository_crud_smoke() -> Result<()> {
    let db = build_test_db().await?;
    let repo = {resource_pascal}Repository::new(db.connection);

    let created = repo.create({create_call_args}).await?;
    let _ = {list_call};
    repo.delete(created.id).await?;
        Ok(())
}
"#
    .replace("{project_name}", project_name)
    .replace("{resource_name}", resource_name)
    .replace("{resource_pascal}", &resource_pascal)
    .replace("{create_call_args}", &create_call_args)
    .replace("{list_call}", &list_call)
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

    if let Some((start, end)) = find_app_builder_marker_range(&contents) {
        let block = contents[start..end].to_string();
        if let Some(updated_block) = insert_register_into_builder_block(&block, &register_line) {
            contents.replace_range(start..end, &updated_block);
        } else {
            print_warning(
                "Could not locate app-builder statement inside markers; trying fallback wiring",
            );
            wire_register_fallback(&mut contents, &register_line);
        }
    } else {
        wire_register_fallback(&mut contents, &register_line);
    }

    write_file(&main_path, &contents)
        .with_context(|| format!("Failed to write {}", main_path.display()))?;
    Ok(())
}

fn insert_register_into_builder_block(block: &str, register_line: &str) -> Option<String> {
    let stmt_end = block.rfind(';')?;
    let line_start = block[..stmt_end]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let line = &block[line_start..stmt_end];
    let indent = line
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect::<String>();
    let indent = if indent.is_empty() {
        "        "
    } else {
        &indent
    };

    let mut updated = String::with_capacity(block.len() + register_line.len() + indent.len() + 2);
    updated.push_str(&block[..stmt_end]);
    updated.push('\n');
    updated.push_str(indent);
    updated.push_str(register_line);
    updated.push_str(&block[stmt_end..]);
    Some(updated)
}

fn wire_register_fallback(contents: &mut String, register_line: &str) {
    if let Some((start, end)) = find_unmarked_app_builder_statement_range(contents) {
        let statement = contents[start..=end].to_string();
        if let Some(updated_statement) =
            insert_register_into_builder_block(&statement, register_line)
        {
            contents.replace_range(start..=end, &updated_statement);
            return;
        }
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

fn add_uuid_dependency(cargo_path: &Path) -> Result<()> {
    let contents = fs::read_to_string(cargo_path)
        .with_context(|| format!("Failed to read {}", cargo_path.display()))?;
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;
    let deps = doc["dependencies"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let deps_table = deps
        .as_table_mut()
        .context("dependencies should be a table")?;

    let mut table = toml_edit::InlineTable::new();
    table.get_or_insert("version", "1");
    table.get_or_insert("features", array_value(&["v4"]));
    deps_table.insert(
        "uuid",
        toml_edit::Item::Value(toml_edit::Value::InlineTable(table)),
    );

    write_file(cargo_path, &doc.to_string())
        .with_context(|| format!("Failed to write {}", cargo_path.display()))?;
    Ok(())
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
