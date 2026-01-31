//! Tideway CLI library exports.

pub mod cli;
pub mod commands;
pub mod env;
pub mod templates;

use colored::Colorize;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

pub const TIDEWAY_VERSION: &str = env!("TIDEWAY_VERSION");

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
static PLAN_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_json_output(enabled: bool) {
    JSON_OUTPUT.store(enabled, Ordering::Relaxed);
}

pub fn is_json_output() -> bool {
    JSON_OUTPUT.load(Ordering::Relaxed)
}

pub fn set_plan_mode(enabled: bool) {
    PLAN_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_plan_mode() -> bool {
    PLAN_MODE.load(Ordering::Relaxed)
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

pub fn ensure_dir(path: &Path) -> std::io::Result<()> {
    if is_plan_mode() {
        print_info(&format!("Plan: create directory {}", path.display()));
        Ok(())
    } else {
        fs::create_dir_all(path)
    }
}

pub fn write_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if is_plan_mode() {
        print_info(&format!("Plan: write file {}", path.display()));
        Ok(())
    } else {
        fs::write(path, contents)
    }
}

pub fn remove_file(path: &Path) -> std::io::Result<()> {
    if is_plan_mode() {
        print_info(&format!("Plan: remove file {}", path.display()));
        Ok(())
    } else {
        fs::remove_file(path)
    }
}

pub fn remove_dir(path: &Path) -> std::io::Result<()> {
    if is_plan_mode() {
        print_info(&format!("Plan: remove directory {}", path.display()));
        Ok(())
    } else {
        fs::remove_dir(path)
    }
}
