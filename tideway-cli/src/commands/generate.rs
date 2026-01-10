//! Generate command - creates frontend components from templates.

use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::cli::{GenerateArgs, Module, Style};
use crate::templates::{TemplateContext, TemplateEngine};
use crate::{print_info, print_success, print_warning};

/// Run the generate command
pub fn run(args: GenerateArgs) -> Result<()> {
    println!(
        "\n{} Generating {} components with {} style\n",
        "tideway".cyan().bold(),
        args.module.to_string().green(),
        args.style.to_string().yellow()
    );

    // Create output directory if it doesn't exist
    let output_path = Path::new(&args.output);
    if !output_path.exists() {
        fs::create_dir_all(output_path)
            .with_context(|| format!("Failed to create output directory: {}", args.output))?;
        print_info(&format!("Created directory: {}", args.output));
    }

    // Create template context
    let context = TemplateContext {
        api_base_url: args.api_base.clone(),
        style: args.style.clone(),
    };

    // Initialize template engine
    let engine = TemplateEngine::new(context)?;

    // Track which shadcn components are needed
    let mut shadcn_components: Vec<&str> = Vec::new();

    // Generate modules based on selection
    match args.module {
        Module::Auth => {
            generate_auth(&engine, output_path, &args, &mut shadcn_components)?;
        }
        Module::Billing => {
            generate_billing(&engine, output_path, &args, &mut shadcn_components)?;
        }
        Module::Organizations => {
            generate_organizations(&engine, output_path, &args, &mut shadcn_components)?;
        }
        Module::All => {
            generate_auth(&engine, output_path, &args, &mut shadcn_components)?;
            generate_billing(&engine, output_path, &args, &mut shadcn_components)?;
            generate_organizations(&engine, output_path, &args, &mut shadcn_components)?;
        }
    }

    // Generate shared files (types, composables)
    generate_shared(&engine, output_path, &args)?;

    // Print shadcn component requirements if using shadcn style
    if args.style == Style::Shadcn && !shadcn_components.is_empty() {
        shadcn_components.sort();
        shadcn_components.dedup();

        println!("\n{}", "Required shadcn-vue components:".yellow().bold());
        println!(
            "  npx shadcn-vue@latest add {}",
            shadcn_components.join(" ")
        );
    }

    println!(
        "\n{} Components generated in {}\n",
        "✓".green().bold(),
        args.output.cyan()
    );

    Ok(())
}

fn generate_auth(
    engine: &TemplateEngine,
    output_path: &Path,
    args: &GenerateArgs,
    shadcn_components: &mut Vec<&str>,
) -> Result<()> {
    let auth_path = output_path.join("auth");
    fs::create_dir_all(&auth_path)?;

    let composables_path = auth_path.join("composables");
    fs::create_dir_all(&composables_path)?;

    // Generate components
    let components = [
        ("LoginForm.vue", "auth/LoginForm"),
        ("RegisterForm.vue", "auth/RegisterForm"),
        ("ForgotPassword.vue", "auth/ForgotPassword"),
        ("ResetPassword.vue", "auth/ResetPassword"),
        ("MfaVerify.vue", "auth/MfaVerify"),
    ];

    for (filename, template_name) in components {
        let content = engine.render(template_name)?;
        let file_path = auth_path.join(filename);
        write_file(&file_path, &content, args.force)?;
        print_success(&format!("Generated auth/{}", filename));
    }

    // Generate composable
    let composable_content = engine.render("auth/composables/useAuth")?;
    let composable_path = composables_path.join("useAuth.ts");
    write_file(&composable_path, &composable_content, args.force)?;
    print_success("Generated auth/composables/useAuth.ts");

    // Track shadcn components needed for auth
    if args.style == Style::Shadcn {
        shadcn_components.extend(&[
            "button", "card", "input", "label", "form", "alert", "separator",
        ]);
    }

    Ok(())
}

fn generate_billing(
    engine: &TemplateEngine,
    output_path: &Path,
    args: &GenerateArgs,
    shadcn_components: &mut Vec<&str>,
) -> Result<()> {
    let billing_path = output_path.join("billing");
    fs::create_dir_all(&billing_path)?;

    let composables_path = billing_path.join("composables");
    fs::create_dir_all(&composables_path)?;

    // Generate components
    let components = [
        ("SubscriptionStatus.vue", "billing/SubscriptionStatus"),
        ("CheckoutButton.vue", "billing/CheckoutButton"),
        ("BillingPortalButton.vue", "billing/BillingPortalButton"),
        ("InvoiceHistory.vue", "billing/InvoiceHistory"),
        ("PlanSelector.vue", "billing/PlanSelector"),
    ];

    for (filename, template_name) in components {
        let content = engine.render(template_name)?;
        let file_path = billing_path.join(filename);
        write_file(&file_path, &content, args.force)?;
        print_success(&format!("Generated billing/{}", filename));
    }

    // Generate composable
    let composable_content = engine.render("billing/composables/useBilling")?;
    let composable_path = composables_path.join("useBilling.ts");
    write_file(&composable_path, &composable_content, args.force)?;
    print_success("Generated billing/composables/useBilling.ts");

    // Track shadcn components needed for billing
    if args.style == Style::Shadcn {
        shadcn_components.extend(&[
            "button", "card", "badge", "table", "skeleton", "alert", "separator",
        ]);
    }

    Ok(())
}

fn generate_organizations(
    engine: &TemplateEngine,
    output_path: &Path,
    args: &GenerateArgs,
    shadcn_components: &mut Vec<&str>,
) -> Result<()> {
    let orgs_path = output_path.join("organizations");
    fs::create_dir_all(&orgs_path)?;

    let composables_path = orgs_path.join("composables");
    fs::create_dir_all(&composables_path)?;

    // Generate components
    let components = [
        ("OrgSwitcher.vue", "organizations/OrgSwitcher"),
        ("OrgSettings.vue", "organizations/OrgSettings"),
        ("MemberList.vue", "organizations/MemberList"),
        ("InviteMember.vue", "organizations/InviteMember"),
    ];

    for (filename, template_name) in components {
        let content = engine.render(template_name)?;
        let file_path = orgs_path.join(filename);
        write_file(&file_path, &content, args.force)?;
        print_success(&format!("Generated organizations/{}", filename));
    }

    // Generate composable
    let composable_content = engine.render("organizations/composables/useOrganization")?;
    let composable_path = composables_path.join("useOrganization.ts");
    write_file(&composable_path, &composable_content, args.force)?;
    print_success("Generated organizations/composables/useOrganization.ts");

    // Track shadcn components needed for organizations
    if args.style == Style::Shadcn {
        shadcn_components.extend(&[
            "button",
            "card",
            "input",
            "label",
            "form",
            "avatar",
            "dropdown-menu",
            "table",
            "badge",
            "dialog",
            "alert",
        ]);
    }

    Ok(())
}

fn generate_shared(engine: &TemplateEngine, output_path: &Path, args: &GenerateArgs) -> Result<()> {
    // Generate shared types
    let types_path = output_path.join("types");
    fs::create_dir_all(&types_path)?;

    let types_content = engine.render("shared/types/index")?;
    let types_file = types_path.join("index.ts");
    write_file(&types_file, &types_content, args.force)?;
    print_success("Generated types/index.ts");

    // Generate shared API composable
    let composables_path = output_path.join("composables");
    fs::create_dir_all(&composables_path)?;

    let api_content = engine.render("shared/composables/useApi")?;
    let api_file = composables_path.join("useApi.ts");
    write_file(&api_file, &api_content, args.force)?;
    print_success("Generated composables/useApi.ts");

    Ok(())
}

fn write_file(path: &Path, content: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        print_warning(&format!(
            "Skipping {} (use --force to overwrite)",
            path.display()
        ));
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}
