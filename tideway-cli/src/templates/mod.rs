//! Template engine for generating frontend and backend components.
//!
//! Uses Handlebars templates embedded at compile time.

use anyhow::{anyhow, Result};
use handlebars::Handlebars;
use include_dir::{include_dir, Dir};
use serde::Serialize;

use crate::cli::{BackendPreset, Style};

// Embed all templates at compile time
static TEMPLATES_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Context for template rendering
#[derive(Serialize, Clone)]
pub struct TemplateContext {
    pub api_base_url: String,
    pub style: Style,
}

/// Template engine using Handlebars
pub struct TemplateEngine {
    handlebars: Handlebars<'static>,
    context: TemplateContext,
}

impl TemplateEngine {
    /// Create a new template engine with the given context
    pub fn new(context: TemplateContext) -> Result<Self> {
        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);

        // Register all templates from embedded directory
        register_templates(&mut handlebars, &TEMPLATES_DIR, "")?;

        Ok(Self { handlebars, context })
    }

    /// Render a template by name
    pub fn render(&self, template_name: &str) -> Result<String> {
        // Build the full template path based on style
        let style_suffix = match self.context.style {
            Style::Shadcn => "shadcn",
            Style::Tailwind => "tailwind",
            Style::Unstyled => "unstyled",
        };

        // Try style-specific template first, fall back to default
        let styled_name = format!("vue/{}.{}", template_name, style_suffix);
        let default_name = format!("vue/{}", template_name);

        let template_key = if self.handlebars.has_template(&styled_name) {
            styled_name
        } else if self.handlebars.has_template(&default_name) {
            default_name
        } else {
            return Err(anyhow!("Template not found: {}", template_name));
        };

        self.handlebars
            .render(&template_key, &self.context)
            .map_err(|e| anyhow!("Failed to render template {}: {}", template_name, e))
    }
}

/// Recursively register templates from the embedded directory
fn register_templates(
    handlebars: &mut Handlebars<'static>,
    dir: &'static Dir<'static>,
    prefix: &str,
) -> Result<()> {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(subdir) => {
                let new_prefix = if prefix.is_empty() {
                    subdir.path().to_string_lossy().to_string()
                } else {
                    format!("{}/{}", prefix, subdir.path().file_name().unwrap().to_string_lossy())
                };
                register_templates(handlebars, subdir, &new_prefix)?;
            }
            include_dir::DirEntry::File(file) => {
                let path = file.path();
                if path.extension().map_or(false, |ext| ext == "hbs") {
                    // Remove .hbs extension for template name
                    let name = path.file_stem().unwrap().to_string_lossy();
                    let template_key = if prefix.is_empty() {
                        name.to_string()
                    } else {
                        format!("{}/{}", prefix, name)
                    };

                    let content = file
                        .contents_utf8()
                        .ok_or_else(|| anyhow!("Invalid UTF-8 in template: {}", path.display()))?;

                    handlebars.register_template_string(&template_key, content)?;
                }
            }
        }
    }
    Ok(())
}

// Make Style serializable for templates
impl Serialize for Style {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Context for backend template rendering
#[derive(Serialize, Clone)]
pub struct BackendTemplateContext {
    /// Project name in snake_case (e.g., "my_app")
    pub project_name: String,
    /// Project name in PascalCase (e.g., "MyApp")
    pub project_name_pascal: String,
    /// Whether the preset includes organizations (B2B)
    pub has_organizations: bool,
    /// Database type ("postgres" or "sqlite")
    pub database: String,
}

/// Template engine for backend scaffolding
pub struct BackendTemplateEngine {
    handlebars: Handlebars<'static>,
    context: BackendTemplateContext,
}

impl BackendTemplateEngine {
    /// Create a new backend template engine with the given context
    pub fn new(context: BackendTemplateContext) -> Result<Self> {
        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true);

        // Register all templates from embedded directory
        register_templates(&mut handlebars, &TEMPLATES_DIR, "")?;

        Ok(Self { handlebars, context })
    }

    /// Render a backend template by name
    pub fn render(&self, template_name: &str) -> Result<String> {
        let template_key = format!("backend/{}", template_name);

        if !self.handlebars.has_template(&template_key) {
            return Err(anyhow!("Backend template not found: {}", template_name));
        }

        self.handlebars
            .render(&template_key, &self.context)
            .map_err(|e| anyhow!("Failed to render template {}: {}", template_name, e))
    }

    /// Check if a template exists
    pub fn has_template(&self, template_name: &str) -> bool {
        let template_key = format!("backend/{}", template_name);
        self.handlebars.has_template(&template_key)
    }
}

// Make BackendPreset serializable for templates
impl Serialize for BackendPreset {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
