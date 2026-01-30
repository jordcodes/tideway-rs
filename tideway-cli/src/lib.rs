//! Tideway CLI library exports.

pub mod cli;
pub mod commands;
pub mod env;
pub mod templates;

use colored::Colorize;

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
