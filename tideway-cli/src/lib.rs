//! Tideway CLI library exports.

pub mod cli;
pub mod commands;
pub mod database;
pub mod env;
pub mod templates;

use colored::Colorize;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

pub const TIDEWAY_VERSION: &str = env!("TIDEWAY_VERSION");

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
static PLAN_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommandRuntime {
    json_output: bool,
    plan_mode: bool,
}

impl CommandRuntime {
    pub const fn new(json_output: bool, plan_mode: bool) -> Self {
        Self {
            json_output,
            plan_mode,
        }
    }

    pub fn from_process_state() -> Self {
        Self::new(is_json_output(), is_plan_mode())
    }

    pub const fn json_output(self) -> bool {
        self.json_output
    }

    pub const fn plan_mode(self) -> bool {
        self.plan_mode
    }

    pub fn install(self) {
        set_json_output(self.json_output);
        set_plan_mode(self.plan_mode);
    }
}

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
    let payload = json!({
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

pub fn error_contract(problem: &str, primary_fix: &str, advanced_fix: &str) -> String {
    format!("Problem: {problem}\nPrimary fix: {primary_fix}\nAdvanced fix: {advanced_fix}")
}

pub fn parse_error_contract(message: &str) -> Option<(String, String, String)> {
    let mut problem = None;
    let mut primary_fix = None;
    let mut advanced_fix = None;

    for line in message.lines() {
        if let Some(value) = line.strip_prefix("Problem: ") {
            problem = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Primary fix: ") {
            primary_fix = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Advanced fix: ") {
            advanced_fix = Some(value.trim().to_string());
        }
    }

    match (problem, primary_fix, advanced_fix) {
        (Some(problem), Some(primary_fix), Some(advanced_fix)) => {
            Some((problem, primary_fix, advanced_fix))
        }
        _ => None,
    }
}

pub fn print_structured_error(message: &str) {
    if is_json_output() {
        if let Some((problem, primary_fix, advanced_fix)) = parse_error_contract(message) {
            let payload = json!({
                "level": "error",
                "message": message,
                "problem": problem,
                "primary_fix": primary_fix,
                "advanced_fix": advanced_fix,
            });
            println!("{}", payload);
        } else {
            print_json("error", message);
        }
    } else {
        print_error(message);
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
