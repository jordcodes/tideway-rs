//! Tideway CLI - Scaffold Tideway apps and advanced helpers.
//!
//! Usage:
//!   tideway new my_app
//!   tideway dev
//!   tideway resource user --wire --db --repo --service --paginate --search
//!   tideway generate auth --framework vue --style shadcn

use anyhow::Result;
use clap::Parser;
use tideway_cli::cli::{Cli, Commands};
use tideway_cli::{print_structured_error, set_json_output, set_plan_mode};

fn main() -> Result<()> {
    let cli = Cli::parse();
    set_json_output(cli.json);
    set_plan_mode(cli.plan);

    let result = match cli.command {
        Commands::New(args) => tideway_cli::commands::new::run(args),
        Commands::Doctor(args) => tideway_cli::commands::doctor::run(args),
        Commands::Generate(args) => tideway_cli::commands::generate::run(args),
        Commands::Backend(args) => tideway_cli::commands::backend::run(args),
        Commands::Add(args) => tideway_cli::commands::add::run(args),
        Commands::Init(args) => tideway_cli::commands::init::run(args),
        Commands::Resource(args) => tideway_cli::commands::resource::run(args),
        Commands::Setup(args) => tideway_cli::commands::setup::run(args),
        Commands::Dev(args) => tideway_cli::commands::dev::run(args),
        Commands::Migrate(args) => tideway_cli::commands::migrate::run(args),
        Commands::Templates => tideway_cli::commands::templates::run(),
    };

    if let Err(err) = result {
        print_structured_error(&err.to_string());
        std::process::exit(1);
    }

    Ok(())
}
