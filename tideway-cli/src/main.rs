//! Tideway CLI - Generate frontend components for tideway applications.
//!
//! Usage:
//!   tideway generate auth --framework vue --style shadcn
//!   tideway generate billing --framework vue
//!   tideway generate organizations --framework vue
//!   tideway generate all --framework vue --output ./src/components

use anyhow::Result;
use clap::Parser;
use tideway_cli::cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New(args) => tideway_cli::commands::new::run(args)?,
        Commands::Generate(args) => tideway_cli::commands::generate::run(args)?,
        Commands::Backend(args) => tideway_cli::commands::backend::run(args)?,
        Commands::Init(args) => tideway_cli::commands::init::run(args)?,
        Commands::Setup(args) => tideway_cli::commands::setup::run(args)?,
        Commands::Templates => tideway_cli::commands::templates::run()?,
    }

    Ok(())
}
