use anyhow::{Context, Result, bail};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::env::read_env_map;
use crate::{print_info, print_success, print_warning};

const DEBOUNCE: Duration = Duration::from_millis(200);
const BUILD_POLL: Duration = Duration::from_millis(50);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

pub(super) struct WatchConfig {
    pub project_dir: PathBuf,
    pub cargo_args: Vec<String>,
    pub load_env: bool,
    pub forced_env: BTreeMap<String, String>,
}

pub(super) fn run(mut config: WatchConfig) -> Result<()> {
    let (cargo_args, app_args) = split_args(std::mem::take(&mut config.cargo_args));
    // Let setup writes (notably first-run `.env` creation) settle before registering
    // the native watcher, otherwise macOS can report them as a new user edit.
    thread::sleep(DEBOUNCE);
    let (events_tx, events_rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |event| {
            let _ = events_tx.send(event);
        },
        notify::Config::default(),
    )
    .context("Failed to initialize the file watcher")?;
    watcher
        .watch(&config.project_dir, RecursiveMode::Recursive)
        .with_context(|| format!("Failed to watch {}", config.project_dir.display()))?;

    let stopping = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&stopping);
    ctrlc::set_handler(move || signal_flag.store(true, Ordering::SeqCst))
        .context("Failed to install Ctrl-C handler")?;

    print_info("Watching Rust sources, migrations, Cargo manifests, and .env");
    let mut app: Option<Child> = None;
    let mut pending_build = true;

    while !stopping.load(Ordering::SeqCst) {
        if pending_build {
            pending_build = false;
            match build(&config, &cargo_args, &events_rx, &stopping)? {
                BuildOutcome::Success(executable) => {
                    stop_child(&mut app, false);
                    app = Some(start_app(&config, &executable, &app_args)?);
                    print_success("Build succeeded; Tideway app restarted");
                }
                BuildOutcome::Failed => {
                    if app.is_some() {
                        print_warning("Build failed; the previous server is still running");
                    } else {
                        print_warning("Build failed; watching for the next change");
                    }
                }
                BuildOutcome::Superseded(paths) => {
                    print_changes(&config.project_dir, &paths);
                    pending_build = true;
                    continue;
                }
                BuildOutcome::Stopping => break,
            }
        }

        if let Some(child) = app.as_mut()
            && let Some(status) = child.try_wait().context("Failed to inspect Tideway app")?
        {
            if !status.success() {
                print_warning(&format!(
                    "Tideway app exited with status {status}; still watching"
                ));
            }
            app = None;
        }

        match events_rx.recv_timeout(BUILD_POLL) {
            Ok(event) => {
                let paths = collect_changes(&config.project_dir, event, &events_rx);
                if !paths.is_empty() {
                    print_changes(&config.project_dir, &paths);
                    pending_build = true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("File watcher stopped unexpectedly")
            }
        }
    }

    stop_child(&mut app, false);
    print_info("Development server stopped");
    Ok(())
}

enum BuildOutcome {
    Success(PathBuf),
    Failed,
    Superseded(BTreeSet<PathBuf>),
    Stopping,
}

fn build(
    config: &WatchConfig,
    cargo_args: &[String],
    events: &mpsc::Receiver<notify::Result<Event>>,
    stopping: &AtomicBool,
) -> Result<BuildOutcome> {
    print_info("Compiling Tideway app...");
    let started = Instant::now();
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .args(cargo_args)
        .arg("--message-format=json-render-diagnostics")
        .current_dir(&config.project_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    configure_process_group(&mut command);

    let mut child = command.spawn().context("Failed to run cargo build")?;
    let stdout = child
        .stdout
        .take()
        .context("Failed to capture cargo output")?;
    let (artifacts_tx, artifacts_rx) = mpsc::channel();
    let reader = thread::spawn(move || read_cargo_output(stdout, artifacts_tx));
    let mut changed = BTreeSet::new();

    let status = loop {
        if stopping.load(Ordering::SeqCst) {
            terminate(&mut child, true);
            let _ = reader.join();
            return Ok(BuildOutcome::Stopping);
        }
        drain_changes(&config.project_dir, events, &mut changed);
        if !changed.is_empty() {
            thread::sleep(DEBOUNCE);
            drain_changes(&config.project_dir, events, &mut changed);
            terminate(&mut child, true);
            let _ = reader.join();
            return Ok(BuildOutcome::Superseded(changed));
        }
        if let Some(status) = child.try_wait().context("Failed to inspect cargo build")? {
            break status;
        }
        thread::sleep(BUILD_POLL);
    };

    reader
        .join()
        .map_err(|_| anyhow::anyhow!("Cargo output reader panicked"))?;
    let executables: BTreeSet<_> = artifacts_rx.try_iter().collect();
    if !status.success() {
        return Ok(BuildOutcome::Failed);
    }
    let executable = select_executable(executables)?;
    print_info(&format!(
        "Compiled in {:.1}s",
        started.elapsed().as_secs_f32()
    ));
    Ok(BuildOutcome::Success(executable))
}

fn read_cargo_output(stdout: impl std::io::Read, artifacts: mpsc::Sender<PathBuf>) {
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            println!("{line}");
            continue;
        };
        match message.get("reason").and_then(Value::as_str) {
            Some("compiler-message") => {
                if let Some(rendered) = message.pointer("/message/rendered").and_then(Value::as_str)
                {
                    eprint!("{rendered}");
                }
            }
            Some("compiler-artifact") => {
                let runnable = message
                    .pointer("/target/kind")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| {
                        kinds
                            .iter()
                            .any(|kind| matches!(kind.as_str(), Some("bin") | Some("example")))
                    });
                if runnable && let Some(path) = message.get("executable").and_then(Value::as_str) {
                    let _ = artifacts.send(PathBuf::from(path));
                }
            }
            _ => {}
        }
    }
}

fn select_executable(executables: BTreeSet<PathBuf>) -> Result<PathBuf> {
    match executables.len() {
        0 => bail!(
            "Cargo built successfully but produced no runnable binary. Add a binary target or pass `--bin <name>`."
        ),
        1 => Ok(executables.into_iter().next().expect("one executable")),
        _ => bail!(
            "Cargo produced multiple runnable binaries. Select one with `tideway dev -- --bin <name>`."
        ),
    }
}

fn start_app(config: &WatchConfig, executable: &Path, args: &[String]) -> Result<Child> {
    let child_env = resolve_child_env(config);

    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(&config.project_dir)
        .envs(&child_env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    configure_process_group(&mut command);
    command
        .spawn()
        .with_context(|| format!("Failed to start {}", executable.display()))
}

fn resolve_child_env(config: &WatchConfig) -> BTreeMap<String, String> {
    let mut child_env = BTreeMap::new();
    if config.load_env
        && let Some(env) = read_env_map(&config.project_dir.join(".env"))
    {
        child_env.extend(
            env.into_iter()
                .filter(|(key, _)| std::env::var_os(key).is_none()),
        );
    }
    child_env.extend(config.forced_env.clone());
    child_env
}

pub(super) fn split_args(args: Vec<String>) -> (Vec<String>, Vec<String>) {
    if let Some(separator) = args.iter().position(|arg| arg == "--") {
        (args[..separator].to_vec(), args[separator + 1..].to_vec())
    } else {
        (args, Vec::new())
    }
}

fn collect_changes(
    root: &Path,
    first: notify::Result<Event>,
    events: &mpsc::Receiver<notify::Result<Event>>,
) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    add_event_paths(root, first, &mut paths);
    while let Ok(event) = events.recv_timeout(DEBOUNCE) {
        add_event_paths(root, event, &mut paths);
    }
    paths
}

fn drain_changes(
    root: &Path,
    events: &mpsc::Receiver<notify::Result<Event>>,
    paths: &mut BTreeSet<PathBuf>,
) {
    while let Ok(event) = events.try_recv() {
        add_event_paths(root, event, paths);
    }
}

fn add_event_paths(root: &Path, event: notify::Result<Event>, paths: &mut BTreeSet<PathBuf>) {
    let Ok(event) = event else {
        return;
    };
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return;
    }
    paths.extend(
        event
            .paths
            .into_iter()
            .filter(|path| is_relevant(root, path)),
    );
}

fn is_relevant(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    if relative.components().any(|component| {
        matches!(component, Component::Normal(name) if name == "target" || name == ".git")
    }) {
        return false;
    }
    let first = relative.components().next();
    if matches!(first, Some(Component::Normal(name)) if name == "migration" || name == "migrations")
    {
        return true;
    }
    matches!(
        relative.file_name().and_then(|name| name.to_str()),
        Some("Cargo.toml" | "build.rs" | ".env")
    ) || relative.extension().and_then(|ext| ext.to_str()) == Some("rs")
}

fn print_changes(root: &Path, paths: &BTreeSet<PathBuf>) {
    let names = paths
        .iter()
        .take(3)
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect::<Vec<_>>();
    let suffix = if paths.len() > names.len() {
        format!(" and {} more", paths.len() - names.len())
    } else {
        String::new()
    };
    print_info(&format!("Change detected: {}{suffix}", names.join(", ")));
}

fn stop_child(child: &mut Option<Child>, force: bool) {
    if let Some(mut running) = child.take() {
        terminate(&mut running, force);
    }
}

fn terminate(child: &mut Child, force: bool) {
    send_termination(child, force);
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(BUILD_POLL);
    }
    send_termination(child, true);
    let _ = child.wait();
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn send_termination(child: &mut Child, force: bool) {
    let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
    // Each child is placed in its own process group, so a negative PID safely targets its tree.
    unsafe {
        libc::kill(-(child.id() as i32), signal);
    }
}

#[cfg(windows)]
fn send_termination(child: &mut Child, force: bool) {
    let mut command = Command::new("taskkill");
    command.args(["/PID", &child.id().to_string(), "/T"]);
    if force {
        command.arg("/F");
    }
    let _ = command.status();
}

#[cfg(all(not(unix), not(windows)))]
fn send_termination(child: &mut Child, _force: bool) {
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_cargo_and_application_arguments() {
        let (cargo, app) = split_args(vec!["--release".into(), "--".into(), "--seed".into()]);
        assert_eq!(cargo, ["--release"]);
        assert_eq!(app, ["--seed"]);
    }

    #[test]
    fn filters_watched_paths() {
        let root = Path::new("/project");
        assert!(is_relevant(root, Path::new("/project/src/main.rs")));
        assert!(is_relevant(
            root,
            Path::new("/project/migration/src/lib.rs")
        ));
        assert!(is_relevant(root, Path::new("/project/Cargo.toml")));
        assert!(is_relevant(root, Path::new("/project/.env")));
        assert!(!is_relevant(root, Path::new("/project/Cargo.lock")));
        assert!(!is_relevant(root, Path::new("/project/target/debug/app")));
        assert!(!is_relevant(root, Path::new("/project/README.md")));
    }

    #[test]
    fn reloads_dotenv_and_preserves_forced_values() {
        let temp = tempfile::tempdir().expect("temp dir");
        let env_path = temp.path().join(".env");
        crate::write_file(
            &env_path,
            "TIDEWAY_WATCH_RELOAD_TEST=first\nDATABASE_AUTO_MIGRATE=true\n",
        )
        .expect("write dotenv");
        let config = WatchConfig {
            project_dir: temp.path().to_path_buf(),
            cargo_args: Vec::new(),
            load_env: true,
            forced_env: BTreeMap::from([("DATABASE_AUTO_MIGRATE".into(), "false".into())]),
        };

        assert_eq!(
            resolve_child_env(&config).get("TIDEWAY_WATCH_RELOAD_TEST"),
            Some(&"first".to_string())
        );
        crate::write_file(&env_path, "TIDEWAY_WATCH_RELOAD_TEST=second\n").expect("update dotenv");
        let reloaded = resolve_child_env(&config);
        assert_eq!(
            reloaded.get("TIDEWAY_WATCH_RELOAD_TEST"),
            Some(&"second".to_string())
        );
        assert_eq!(
            reloaded.get("DATABASE_AUTO_MIGRATE"),
            Some(&"false".to_string())
        );
    }
}
