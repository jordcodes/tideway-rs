//! Tideway CLI - Scaffold Tideway apps and advanced helpers.
//!
//! Usage:
//!   tideway new my_app
//!   tideway dev
//!   tideway resource user
//!   tideway generate auth --framework vue --style shadcn

use anyhow::Result;
use clap::Parser;
use tideway_cli::cli::{Cli, Commands};
use tideway_cli::{CommandRuntime, print_structured_error};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = CommandRuntime::new(cli.json, cli.plan);
    runtime.install();

    let result = match cli.command {
        Commands::New(args) => tideway_cli::commands::new::run_with_runtime(args, runtime),
        Commands::Doctor(args) => tideway_cli::commands::doctor::run_with_runtime(args, runtime),
        Commands::Generate(args) => {
            tideway_cli::commands::generate::run_with_runtime(args, runtime)
        }
        Commands::Backend(args) => tideway_cli::commands::backend::run_with_runtime(args, runtime),
        Commands::Add(args) => tideway_cli::commands::add::run_with_runtime(args, runtime),
        Commands::Init(args) => tideway_cli::commands::init::run_with_runtime(args, runtime),
        Commands::Resource(args) => {
            tideway_cli::commands::resource::run_with_runtime(args, runtime)
        }
        Commands::Setup(args) => tideway_cli::commands::setup::run_with_runtime(args, runtime),
        Commands::Dev(args) => tideway_cli::commands::dev::run_with_runtime(args, runtime),
        Commands::Migrate(args) => tideway_cli::commands::migrate::run_with_runtime(args, runtime),
        Commands::Templates => tideway_cli::commands::templates::run_with_runtime(runtime),
    };

    if let Err(err) = result {
        print_structured_error(&err.to_string());
        std::process::exit(1);
    }

    Ok(())
}
