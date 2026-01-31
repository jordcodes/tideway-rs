//! Tideway CLI library exports.

pub mod cli;
pub mod commands;
pub mod env;
pub mod templates;

use colored::Colorize;
use std::sync::atomic::{AtomicBool, Ordering};

pub const TIDEWAY_VERSION: &str = env!("TIDEWAY_VERSION");

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);

pub fn set_json_output(enabled: bool) {
    JSON_OUTPUT.store(enabled, Ordering::Relaxed);
}

pub fn is_json_output() -> bool {
    JSON_OUTPUT.load(Ordering::Relaxed)
}

fn print_json(level: &str, message: &str) {
    let payload = serde_json::json!({
        "level": level,
        "message": message,
    });
    println!("{}", payload);
}

/// Print a success message
pub fn print_success(message: &str) {
    if is_json_output() {
        print_json("success", message);
    } else {
        println!("{} {}", "✓".green().bold(), message);
    }
}

/// Print an info message
pub fn print_info(message: &str) {
    if is_json_output() {
        print_json("info", message);
    } else {
        println!("{} {}", "→".blue(), message);
    }
}

/// Print a warning message
pub fn print_warning(message: &str) {
    if is_json_output() {
        print_json("warning", message);
    } else {
        println!("{} {}", "!".yellow().bold(), message);
    }
}

/// Print an error message
pub fn print_error(message: &str) {
    if is_json_output() {
        print_json("error", message);
    } else {
        println!("{} {}", "✗".red().bold(), message);
    }
}
