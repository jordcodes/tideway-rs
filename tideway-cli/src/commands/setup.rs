//! Setup command - installs frontend dependencies (Tailwind, shadcn, etc.)

use anyhow::{Context, Result};
use colored::Colorize;
use std::process::Command;

use crate::cli::{Framework, SetupArgs, Style};
use crate::{print_error, print_info, print_success, print_warning};

/// Components required for tideway frontend
const SHADCN_VUE_COMPONENTS: &[&str] = &[
    "button",
    "input",
    "label",
    "card",
    "tabs",
    "alert",
    "dialog",
    "dropdown-menu",
    "avatar",
    "badge",
    "table",
    "select",
    "checkbox",
    "separator",
    "toast",
    "sonner",
];

/// Run the setup command
pub fn run(args: SetupArgs) -> Result<()> {
    println!(
        "\n{} Setting up frontend dependencies...\n",
        "tideway".cyan().bold()
    );

    // Check for package.json
    if !std::path::Path::new("package.json").exists() {
        print_error("No package.json found. Please run this from a frontend project directory.");
        println!("\nTo create a new Vue project:");
        println!("  npm create vue@latest my-app");
        println!("  cd my-app");
        println!("  tideway setup");
        return Ok(());
    }

    match args.framework {
        Framework::Vue => setup_vue(&args)?,
    }

    println!(
        "\n{} Frontend setup complete!\n",
        "✓".green().bold()
    );

    println!("{}", "Next steps:".yellow().bold());
    println!("  1. Generate components:");
    println!("     tideway generate all --with-views");
    println!();
    println!("  2. Set up your router to use the generated views");
    println!();

    Ok(())
}

fn setup_vue(args: &SetupArgs) -> Result<()> {
    // Step 1: Install Tailwind if needed
    if !args.no_tailwind && args.style != Style::Unstyled {
        setup_tailwind()?;
    }

    // Step 2: Install shadcn-vue if using shadcn style
    if args.style == Style::Shadcn && !args.no_components {
        setup_shadcn_vue()?;
    }

    Ok(())
}

fn setup_tailwind() -> Result<()> {
    print_info("Checking Tailwind CSS...");

    // Check if tailwind.config already exists
    let has_tailwind = std::path::Path::new("tailwind.config.js").exists()
        || std::path::Path::new("tailwind.config.ts").exists();

    if has_tailwind {
        print_info("Tailwind CSS already configured, skipping");
        return Ok(());
    }

    print_info("Installing Tailwind CSS...");

    // Install tailwind
    let status = Command::new("npm")
        .args(["install", "-D", "tailwindcss", "postcss", "autoprefixer"])
        .status()
        .context("Failed to run npm install")?;

    if !status.success() {
        print_warning("Failed to install Tailwind CSS dependencies");
        return Ok(());
    }

    // Init tailwind
    let status = Command::new("npx")
        .args(["tailwindcss", "init", "-p"])
        .status()
        .context("Failed to run tailwindcss init")?;

    if !status.success() {
        print_warning("Failed to initialize Tailwind CSS");
        return Ok(());
    }

    print_success("Tailwind CSS installed");
    print_warning("Remember to configure tailwind.config.js content paths and add @tailwind directives to your CSS");

    Ok(())
}

fn setup_shadcn_vue() -> Result<()> {
    print_info("Setting up shadcn-vue...");

    // Check if shadcn is already initialized (components.json exists)
    let has_shadcn = std::path::Path::new("components.json").exists();

    if !has_shadcn {
        print_info("Initializing shadcn-vue (this may prompt for options)...");

        let status = Command::new("npx")
            .args(["shadcn-vue@latest", "init"])
            .status()
            .context("Failed to run shadcn-vue init")?;

        if !status.success() {
            print_error("Failed to initialize shadcn-vue");
            println!("You can try running manually: npx shadcn-vue@latest init");
            return Ok(());
        }

        print_success("shadcn-vue initialized");
    } else {
        print_info("shadcn-vue already initialized");
    }

    // Install required components
    print_info(&format!(
        "Installing {} shadcn components...",
        SHADCN_VUE_COMPONENTS.len()
    ));

    let components = SHADCN_VUE_COMPONENTS.join(" ");

    let status = Command::new("npx")
        .args(["shadcn-vue@latest", "add", "-y"])
        .args(SHADCN_VUE_COMPONENTS)
        .status()
        .context("Failed to install shadcn components")?;

    if !status.success() {
        print_warning("Some components may have failed to install");
        println!("You can try running manually: npx shadcn-vue@latest add {}", components);
        return Ok(());
    }

    print_success("shadcn components installed");

    Ok(())
}
