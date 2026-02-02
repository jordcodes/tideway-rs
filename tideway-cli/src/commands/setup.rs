//! Setup command - installs frontend dependencies (Tailwind, shadcn, etc.)

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;
use std::process::Command;

use crate::cli::{Framework, SetupArgs, Style};
use crate::{
    is_json_output, is_plan_mode, print_error, print_info, print_success, print_warning,
    remove_dir, remove_file, write_file,
};

/// Components required for tideway frontend
const SHADCN_VUE_COMPONENTS: &[&str] = &[
    "alert",
    "avatar",
    "badge",
    "button",
    "card",
    "checkbox",
    "dialog",
    "dropdown-menu",
    "form",
    "input",
    "label",
    "select",
    "separator",
    "skeleton",
    "sonner",
    "switch",
    "table",
    "tabs",
];

/// Run the setup command
pub fn run(args: SetupArgs) -> Result<()> {
    if !is_json_output() {
        println!(
            "\n{} Setting up frontend dependencies...\n",
            "tideway".cyan().bold()
        );
    }

    // Check for package.json
    if !std::path::Path::new("package.json").exists() {
        print_error("No package.json found. Please run this from a frontend project directory.");
        if !is_json_output() {
            println!("\nTo create a new Vue project:");
            println!("  npm create vue@latest my-app");
            println!("  cd my-app");
            println!("  tideway setup");
        }
        return Ok(());
    }

    match args.framework {
        Framework::Vue => setup_vue(&args)?,
    }

    if !is_json_output() {
        println!("\n{} Frontend setup complete!\n", "✓".green().bold());

        println!("{}", "Next steps:".yellow().bold());
        println!("  1. Generate components:");
        println!("     tideway generate all --with-views");
        println!();
        println!("  2. Set up your router to use the generated views");
        println!();
    }

    Ok(())
}

fn setup_vue(args: &SetupArgs) -> Result<()> {
    // Step 1: Clean up default Vue starter files
    cleanup_vue_starter()?;

    // Step 2: Install Tailwind if needed
    if !args.no_tailwind && args.style != Style::Unstyled {
        setup_tailwind()?;
    }

    // Step 3: Install shadcn-vue if using shadcn style
    if args.style == Style::Shadcn && !args.no_components {
        setup_shadcn_vue()?;
    }

    Ok(())
}

fn cleanup_vue_starter() -> Result<()> {
    print_info("Cleaning up default Vue starter files...");

    // Remove default components
    let default_files = [
        "src/components/HelloWorld.vue",
        "src/components/TheWelcome.vue",
        "src/components/WelcomeItem.vue",
        "src/components/icons/IconCommunity.vue",
        "src/components/icons/IconDocumentation.vue",
        "src/components/icons/IconEcosystem.vue",
        "src/components/icons/IconSupport.vue",
        "src/components/icons/IconTooling.vue",
    ];

    for file in default_files {
        if Path::new(file).exists() {
            let _ = remove_file(Path::new(file));
        }
    }

    // Remove icons directory if empty
    if Path::new("src/components/icons").exists() {
        let _ = remove_dir(Path::new("src/components/icons"));
    }

    // Replace HomeView with a simple redirect
    if Path::new("src/views/HomeView.vue").exists() {
        write_file(
            Path::new("src/views/HomeView.vue"),
            r#"<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

onMounted(() => {
  router.push('/login')
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center">
    <p class="text-muted-foreground">Redirecting...</p>
  </div>
</template>
"#,
        )?;
        print_success("Replaced HomeView.vue with login redirect");
    }

    // Remove AboutView if it exists
    if Path::new("src/views/AboutView.vue").exists() {
        let _ = remove_file(Path::new("src/views/AboutView.vue"));
    }

    // Clean up App.vue
    if Path::new("src/App.vue").exists() {
        write_file(
            Path::new("src/App.vue"),
            r#"<script setup lang="ts">
import { RouterView } from 'vue-router'
</script>

<template>
  <RouterView />
</template>
"#,
        )?;
        print_success("Cleaned up App.vue");
    }

    // Clean up main.css - remove default styles and base.css import
    if Path::new("src/assets/main.css").exists() {
        let content = std::fs::read_to_string("src/assets/main.css")?;
        // Keep only @import lines that are NOT base.css
        let imports: Vec<&str> = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("@import") && !trimmed.contains("base.css")
            })
            .collect();

        if !imports.is_empty() {
            write_file(
                Path::new("src/assets/main.css"),
                &(imports.join("\n") + "\n"),
            )?;
            print_success("Cleaned up main.css");
        }
    }

    // Remove base.css if it exists (default Vue styles)
    if Path::new("src/assets/base.css").exists() {
        let _ = remove_file(Path::new("src/assets/base.css"));
        print_success("Removed base.css");
    }

    // Clean up router - remove default Home and About routes
    cleanup_router()?;

    Ok(())
}

fn cleanup_router() -> Result<()> {
    let router_path = Path::new("src/router/index.ts");
    if !router_path.exists() {
        return Ok(());
    }

    // Replace with a clean router template - tideway generate will add routes
    write_file(
        router_path,
        r#"import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [],
})

export default router
"#,
    )?;
    print_success("Cleaned up router (removed default routes)");

    Ok(())
}

fn setup_tailwind() -> Result<()> {
    print_info("Setting up Tailwind CSS v4...");

    // Check if vite.config exists
    let vite_config_path = if Path::new("vite.config.ts").exists() {
        "vite.config.ts"
    } else if Path::new("vite.config.js").exists() {
        "vite.config.js"
    } else {
        print_warning("No vite.config found. Tailwind v4 setup requires Vite.");
        return Ok(());
    };

    // Install Tailwind v4 with Vite plugin
    print_info("Installing @tailwindcss/vite...");
    if !run_external_command(
        "npm",
        &["install", "-D", "tailwindcss", "@tailwindcss/vite"],
        "install tailwind dependencies",
    )? {
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
                "import vue from '@vitejs/plugin-vue'\nimport tailwindcss from '@tailwindcss/vite'",
            )
            .replace("plugins: [vue()]", "plugins: [vue(), tailwindcss()]")
            .replace(
                "plugins: [\n    vue()",
                "plugins: [\n    vue(),\n    tailwindcss()",
            );

        write_file(Path::new(vite_config_path), &updated)?;
        print_success("Updated vite.config with tailwindcss plugin");
    } else {
        print_info("Tailwind already in vite.config");
    }

    // Update main CSS file
    let css_paths = ["src/assets/main.css", "src/style.css", "src/index.css"];
    for css_path in css_paths {
        if Path::new(css_path).exists() {
            let css_content = std::fs::read_to_string(css_path)?;
            if !css_content.contains("@import \"tailwindcss\"")
                && !css_content.contains("@import 'tailwindcss'")
            {
                let updated = format!("@import \"tailwindcss\";\n\n{}", css_content);
                write_file(Path::new(css_path), &updated)?;
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
    let has_shadcn = Path::new("components.json").exists();

    if !has_shadcn {
        print_info("Initializing shadcn-vue...");

        if !run_external_command(
            "npx",
            &["shadcn-vue@latest", "init", "-y", "-d"],
            "initialize shadcn-vue",
        )? {
            print_error("Failed to initialize shadcn-vue");
            if !is_json_output() {
                println!("You can try running manually: npx shadcn-vue@latest init");
            }
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

    let mut add_args = vec!["shadcn-vue@latest", "add", "-y"];
    add_args.extend(SHADCN_VUE_COMPONENTS);

    if !run_external_command("npx", &add_args, "install shadcn components")? {
        print_warning("Some components may have failed to install");
        if !is_json_output() {
            println!(
                "You can try running manually: npx shadcn-vue@latest add {}",
                components
            );
        }
        return Ok(());
    }

    print_success("shadcn components installed");

    // Install tw-animate-css (required by shadcn-vue animations)
    print_info("Installing tw-animate-css...");
    if run_external_command(
        "npm",
        &["install", "tw-animate-css"],
        "install tw-animate-css",
    )? {
        print_success("tw-animate-css installed");
    }

    Ok(())
}

fn setup_tsconfig_alias() -> Result<()> {
    // Need to update BOTH tsconfig.json and tsconfig.app.json for shadcn-vue
    let configs = ["tsconfig.json", "tsconfig.app.json"];

    for tsconfig_path in configs {
        if !Path::new(tsconfig_path).exists() {
            continue;
        }

        print_info(&format!("Checking {} for import alias...", tsconfig_path));

        let content = std::fs::read_to_string(tsconfig_path)?;

        // Check if paths already configured
        if content.contains("\"@/*\"") || content.contains("'@/*'") {
            print_info(&format!("{} already has import alias", tsconfig_path));
            continue;
        }

        // Add paths to compilerOptions - handle both regular and references-style tsconfig
        let updated = if content.contains("\"compilerOptions\": {") {
            // Regular tsconfig with existing compilerOptions
            content.replace(
                "\"compilerOptions\": {",
                "\"compilerOptions\": {\n    \"baseUrl\": \".\",\n    \"paths\": {\n      \"@/*\": [\"./src/*\"]\n    },"
            )
        } else if content.contains("\"files\":") || content.contains("\"references\":") {
            // References-style tsconfig without compilerOptions - add it
            content.replace(
                "{",
                "{\n  \"compilerOptions\": {\n    \"baseUrl\": \".\",\n    \"paths\": {\n      \"@/*\": [\"./src/*\"]\n    }\n  },"
            )
        } else {
            content
        };

        write_file(Path::new(tsconfig_path), &updated)?;
        print_success(&format!("Added @ import alias to {}", tsconfig_path));
    }

    // Also update vite.config for path resolution
    setup_vite_path_resolution()?;

    // Create tailwind.config.ts stub for shadcn-vue compatibility
    setup_tailwind_config_stub()?;

    Ok(())
}

fn setup_tailwind_config_stub() -> Result<()> {
    // shadcn-vue requires a tailwind.config file even though Tailwind v4 doesn't need one
    let config_exists =
        Path::new("tailwind.config.ts").exists() || Path::new("tailwind.config.js").exists();

    if config_exists {
        return Ok(());
    }

    print_info("Creating tailwind.config.ts for shadcn-vue compatibility...");
    write_file(
        Path::new("tailwind.config.ts"),
        "// Tailwind v4 uses CSS-based configuration, but shadcn-vue needs this file\nexport default {}\n",
    )?;
    print_success("Created tailwind.config.ts");

    Ok(())
}

fn setup_vite_path_resolution() -> Result<()> {
    // Install @types/node if needed
    print_info("Installing @types/node for path resolution...");
    let _ = run_external_command(
        "npm",
        &["install", "-D", "@types/node"],
        "install @types/node",
    );

    // Update vite.config to add resolve.alias
    let vite_config_path = if Path::new("vite.config.ts").exists() {
        "vite.config.ts"
    } else if Path::new("vite.config.js").exists() {
        "vite.config.js"
    } else {
        return Ok(());
    };

    let content = std::fs::read_to_string(vite_config_path)?;

    // Check if already has path import and resolve.alias
    if content.contains("fileURLToPath") && content.contains("resolve:") {
        print_info("Vite path resolution already configured");
        return Ok(());
    }

    // Add the import and resolve config
    let mut updated = content;

    // Add import if not present
    if !updated.contains("fileURLToPath") {
        updated = format!(
            "import {{ fileURLToPath, URL }} from 'node:url'\n{}",
            updated
        );
    }

    // Add resolve.alias if not present
    if !updated.contains("resolve:") {
        updated = updated.replace(
            "plugins: [",
            "resolve: {\n    alias: {\n      '@': fileURLToPath(new URL('./src', import.meta.url))\n    }\n  },\n  plugins: ["
        );
    }

    write_file(Path::new(vite_config_path), &updated)?;
    print_success("Added path resolution to vite.config");

    Ok(())
}

fn run_external_command(program: &str, args: &[&str], context: &str) -> Result<bool> {
    if is_plan_mode() {
        print_info(&format!(
            "Plan: run command `{}`",
            format_command(program, args)
        ));
        return Ok(true);
    }

    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("Failed to {}", context))?;

    Ok(status.success())
}

fn format_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}
