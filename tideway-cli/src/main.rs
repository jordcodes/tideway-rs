//! Tideway CLI - Generate frontend components for tideway applications.
//!
//! Usage:
//!   tideway generate auth --framework vue --style shadcn
//!   tideway generate billing --framework vue
//!   tideway generate organizations --framework vue
//!   tideway generate all --framework vue --output ./src/components

mod cli;
mod commands;
mod templates;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate(args) => commands::generate::run(args)?,
        Commands::Backend(args) => commands::backend::run(args)?,
        Commands::Init(args) => commands::init::run(args)?,
        Commands::Setup(args) => commands::setup::run(args)?,
        Commands::Templates => commands::templates::run()?,
    }

    Ok(())
}

/// Print a success message
pub fn print_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Print an info message
pub fn print_info(message: &str) {
    println!("{} {}", "→".blue(), message);
}

/// Print a warning message
pub fn print_warning(message: &str) {
    println!("{} {}", "!".yellow().bold(), message);
}

/// Print an error message
pub fn print_error(message: &str) {
    println!("{} {}", "✗".red().bold(), message);
}
