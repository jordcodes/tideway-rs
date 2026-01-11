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
    print_info("Setting up Tailwind CSS v4...");

    // Check if vite.config exists
    let vite_config_path = if std::path::Path::new("vite.config.ts").exists() {
        "vite.config.ts"
    } else if std::path::Path::new("vite.config.js").exists() {
        "vite.config.js"
    } else {
        print_warning("No vite.config found. Tailwind v4 setup requires Vite.");
        return Ok(());
    };

    // Install Tailwind v4 with Vite plugin
    print_info("Installing @tailwindcss/vite...");
    let status = Command::new("npm")
        .args(["install", "-D", "tailwindcss", "@tailwindcss/vite"])
        .status()
        .context("Failed to run npm install")?;

    if !status.success() {
        print_warning("Failed to install Tailwind CSS");
        return Ok(());
    }

    print_success("Tailwind CSS v4 installed");

    // Update vite.config to add tailwindcss plugin
    print_info("Configuring vite.config...");
    let vite_config = std::fs::read_to_string(vite_config_path)?;

    if !vite_config.contains("@tailwindcss/vite") {
        let updated = vite_config
            .replace(
                "import vue from '@vitejs/plugin-vue'",
                "import vue from '@vitejs/plugin-vue'\nimport tailwindcss from '@tailwindcss/vite'"
            )
            .replace(
                "plugins: [vue()]",
                "plugins: [vue(), tailwindcss()]"
            )
            .replace(
                "plugins: [\n    vue()",
                "plugins: [\n    vue(),\n    tailwindcss()"
            );

        std::fs::write(vite_config_path, updated)?;
        print_success("Updated vite.config with tailwindcss plugin");
    } else {
        print_info("Tailwind already in vite.config");
    }

    // Update main CSS file
    let css_paths = ["src/assets/main.css", "src/style.css", "src/index.css"];
    for css_path in css_paths {
        if std::path::Path::new(css_path).exists() {
            let css_content = std::fs::read_to_string(css_path)?;
            if !css_content.contains("@import \"tailwindcss\"") && !css_content.contains("@import 'tailwindcss'") {
                let updated = format!("@import \"tailwindcss\";\n\n{}", css_content);
                std::fs::write(css_path, updated)?;
                print_success(&format!("Added Tailwind import to {}", css_path));
            }
            break;
        }
    }

    Ok(())
}

fn setup_shadcn_vue() -> Result<()> {
    print_info("Setting up shadcn-vue...");

    // First, ensure tsconfig has the @ alias
    setup_tsconfig_alias()?;

    // Check if shadcn is already initialized (components.json exists)
    let has_shadcn = std::path::Path::new("components.json").exists();

    if !has_shadcn {
        print_info("Initializing shadcn-vue...");

        let status = Command::new("npx")
            .args(["shadcn-vue@latest", "init", "-y", "-d"])
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

fn setup_tsconfig_alias() -> Result<()> {
    // Check for tsconfig.json or tsconfig.app.json
    let tsconfig_path = if std::path::Path::new("tsconfig.app.json").exists() {
        "tsconfig.app.json"
    } else if std::path::Path::new("tsconfig.json").exists() {
        "tsconfig.json"
    } else {
        print_warning("No tsconfig.json found, skipping alias setup");
        return Ok(());
    };

    print_info(&format!("Checking {} for import alias...", tsconfig_path));

    let content = std::fs::read_to_string(tsconfig_path)?;

    // Check if paths already configured
    if content.contains("\"@/*\"") || content.contains("'@/*'") {
        print_info("Import alias already configured");
        return Ok(());
    }

    // Add paths to compilerOptions
    let updated = if content.contains("\"compilerOptions\"") {
        content.replace(
            "\"compilerOptions\": {",
            "\"compilerOptions\": {\n    \"baseUrl\": \".\",\n    \"paths\": {\n      \"@/*\": [\"./src/*\"]\n    },"
        )
    } else {
        content
    };

    std::fs::write(tsconfig_path, updated)?;
    print_success(&format!("Added @ import alias to {}", tsconfig_path));

    Ok(())
}
