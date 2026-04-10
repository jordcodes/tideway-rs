use crate::{CommandRuntime, print_info, print_warning};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    summary: String,
    steps: Vec<PlanStep>,
}

impl ExecutionPlan {
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            steps: Vec::new(),
        }
    }

    pub fn step(mut self, step: PlanStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn command(self, command: PlannedCommand) -> Self {
        self.step(PlanStep::run_command(command))
    }

    pub fn info(self, message: impl Into<String>) -> Self {
        self.step(PlanStep::info(message))
    }

    pub fn warning(self, message: impl Into<String>) -> Self {
        self.step(PlanStep::warning(message))
    }

    pub fn emit(&self, runtime: CommandRuntime) {
        runtime.install();
        print_info(&format!("Plan: {}", self.summary));
        for step in &self.steps {
            step.emit();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStep {
    CreateDirectory(String),
    WriteFile(String),
    RemoveFile(String),
    RemoveDirectory(String),
    RunCommand(PlannedCommand),
    Info(String),
    Warning(String),
}

impl PlanStep {
    pub fn create_directory(path: impl Into<String>) -> Self {
        Self::CreateDirectory(path.into())
    }

    pub fn write_file(path: impl Into<String>) -> Self {
        Self::WriteFile(path.into())
    }

    pub fn remove_file(path: impl Into<String>) -> Self {
        Self::RemoveFile(path.into())
    }

    pub fn remove_directory(path: impl Into<String>) -> Self {
        Self::RemoveDirectory(path.into())
    }

    pub fn run_command(command: PlannedCommand) -> Self {
        Self::RunCommand(command)
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::Info(message.into())
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::Warning(message.into())
    }

    pub fn emit(&self) {
        match self {
            Self::Warning(_) => print_warning(&self.message()),
            _ => print_info(&self.message()),
        }
    }

    fn message(&self) -> String {
        match self {
            Self::CreateDirectory(path) => format!("Plan: create directory {}", path),
            Self::WriteFile(path) => format!("Plan: write file {}", path),
            Self::RemoveFile(path) => format!("Plan: remove file {}", path),
            Self::RemoveDirectory(path) => format!("Plan: remove directory {}", path),
            Self::RunCommand(command) => command.plan_message(),
            Self::Info(message) | Self::Warning(message) => message.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCommand {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
}

impl PlannedCommand {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    fn plan_message(&self) -> String {
        let command = self.render();
        match &self.cwd {
            Some(cwd) => format!("Plan: run command `{command}` (cwd: {cwd})"),
            None => format!("Plan: run command `{command}`"),
        }
    }

    fn render(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_escape)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn shell_escape(part: &str) -> String {
    if part
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        part.to_string()
    } else {
        format!("'{}'", part.replace('\'', "'\"'\"'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_step_file_messages_match_existing_output() {
        assert_eq!(
            PlanStep::create_directory("src/generated").message(),
            "Plan: create directory src/generated"
        );
        assert_eq!(
            PlanStep::write_file("src/main.rs").message(),
            "Plan: write file src/main.rs"
        );
        assert_eq!(
            PlanStep::remove_file("src/old.rs").message(),
            "Plan: remove file src/old.rs"
        );
        assert_eq!(
            PlanStep::remove_directory("src/old").message(),
            "Plan: remove directory src/old"
        );
    }

    #[test]
    fn planned_command_renders_args_and_cwd() {
        let command = PlannedCommand::new("cargo")
            .arg("run")
            .arg("--release")
            .cwd("/tmp/project");

        assert_eq!(
            PlanStep::run_command(command).message(),
            "Plan: run command `cargo run --release` (cwd: /tmp/project)"
        );
    }

    #[test]
    fn planned_command_quotes_args_with_spaces() {
        let command = PlannedCommand::new("cargo")
            .arg("run")
            .arg("--features")
            .arg("jobs redis");

        assert_eq!(
            PlanStep::run_command(command).message(),
            "Plan: run command `cargo run --features 'jobs redis'`"
        );
    }
}
