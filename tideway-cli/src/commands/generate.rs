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
        Module::Admin => {
            generate_admin(&engine, output_path, &args, &mut shadcn_components)?;
        }
        Module::All => {
            generate_auth(&engine, output_path, &args, &mut shadcn_components)?;
            generate_billing(&engine, output_path, &args, &mut shadcn_components)?;
            generate_organizations(&engine, output_path, &args, &mut shadcn_components)?;
            generate_admin(&engine, output_path, &args, &mut shadcn_components)?;
        }
    }

    // Generate shared files (types, composables) unless --no-shared is set
    if !args.no_shared {
        generate_shared(&engine, output_path, &args)?;
    } else {
        print_info("Skipping shared files (--no-shared)");
    }

    // Generate view files if --with-views is set
    if args.with_views {
        let views_path = Path::new(&args.views_output);
        if !views_path.exists() {
            fs::create_dir_all(views_path)
                .with_context(|| format!("Failed to create views directory: {}", args.views_output))?;
        }

        match args.module {
            Module::Admin => {
                generate_admin_views(&engine, views_path, &args)?;
            }
            Module::All => {
                generate_admin_views(&engine, views_path, &args)?;
            }
            _ => {
                print_info("Views not yet available for this module");
            }
        }
    }

    // Print shadcn component requirements if using shadcn style
    if args.style == Style::Shadcn && !shadcn_components.is_empty() {
        shadcn_components.sort();
        shadcn_components.dedup();

        // Detect which components are already installed
        let installed = detect_installed_shadcn_components();
        let missing: Vec<&str> = shadcn_components
            .iter()
            .filter(|c| !installed.contains(&c.to_string()))
            .copied()
            .collect();

        if missing.is_empty() {
            println!(
                "\n{} All required shadcn-vue components are installed",
                "✓".green().bold()
            );
        } else {
            println!("\n{}", "Missing shadcn-vue components:".yellow().bold());
            println!(
                "  npx shadcn-vue@latest add {}",
                missing.join(" ")
            );
        }
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

fn generate_admin(
    engine: &TemplateEngine,
    output_path: &Path,
    args: &GenerateArgs,
    shadcn_components: &mut Vec<&str>,
) -> Result<()> {
    let admin_path = output_path.join("admin");
    fs::create_dir_all(&admin_path)?;

    let composables_path = admin_path.join("composables");
    fs::create_dir_all(&composables_path)?;

    // Generate components
    let components = [
        ("AdminDashboard.vue", "admin/AdminDashboard"),
        ("UserList.vue", "admin/UserList"),
        ("UserDetail.vue", "admin/UserDetail"),
        ("OrganizationList.vue", "admin/OrganizationList"),
        ("OrganizationDetail.vue", "admin/OrganizationDetail"),
        ("ImpersonationBanner.vue", "admin/ImpersonationBanner"),
    ];

    for (filename, template_name) in components {
        let content = engine.render(template_name)?;
        let file_path = admin_path.join(filename);
        write_file(&file_path, &content, args.force)?;
        print_success(&format!("Generated admin/{}", filename));
    }

    // Generate composable
    let composable_content = engine.render("admin/composables/useAdmin")?;
    let composable_path = composables_path.join("useAdmin.ts");
    write_file(&composable_path, &composable_content, args.force)?;
    print_success("Generated admin/composables/useAdmin.ts");

    // Track shadcn components needed for admin
    if args.style == Style::Shadcn {
        shadcn_components.extend(&[
            "button",
            "card",
            "input",
            "label",
            "table",
            "badge",
            "skeleton",
            "alert",
            "separator",
            "switch",
        ]);
    }

    Ok(())
}

fn generate_admin_views(
    engine: &TemplateEngine,
    views_path: &Path,
    args: &GenerateArgs,
) -> Result<()> {
    let admin_views_path = views_path.join("admin");
    fs::create_dir_all(&admin_views_path)?;

    // Generate view files
    let views = [
        ("AdminLayout.vue", "views/admin/AdminLayout"),
        ("AdminDashboardView.vue", "views/admin/AdminDashboardView"),
        ("AdminUsersView.vue", "views/admin/AdminUsersView"),
        ("AdminOrganizationsView.vue", "views/admin/AdminOrganizationsView"),
    ];

    for (filename, template_name) in views {
        let content = engine.render(template_name)?;
        let file_path = admin_views_path.join(filename);
        write_file(&file_path, &content, args.force)?;
        print_success(&format!("Generated views/admin/{}", filename));
    }

    // Print router config hint
    println!("\n{}", "Add to your router:".yellow().bold());
    println!(
        r#"  {{
    path: '/admin',
    component: () => import('@/views/admin/AdminLayout.vue'),
    meta: {{ requiresAuth: true }},
    children: [
      {{ path: '', name: 'admin-dashboard', component: () => import('@/views/admin/AdminDashboardView.vue') }},
      {{ path: 'users', name: 'admin-users', component: () => import('@/views/admin/AdminUsersView.vue') }},
      {{ path: 'organizations', name: 'admin-organizations', component: () => import('@/views/admin/AdminOrganizationsView.vue') }},
    ]
  }}"#
    );

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

/// Detect installed shadcn-vue components by checking ./src/components/ui/ subdirectories
fn detect_installed_shadcn_components() -> Vec<String> {
    let ui_path = Path::new("./src/components/ui");

    if !ui_path.exists() {
        return Vec::new();
    }

    let Ok(entries) = fs::read_dir(ui_path) else {
        return Vec::new();
    };

    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                entry.file_name().to_str().map(String::from)
            } else {
                None
            }
        })
        .collect()
}
