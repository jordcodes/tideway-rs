//! Helpers shared by the integration test modules.

use std::process::Command;

/// Set in a child process to the full name of the one test it runs.
/// Deliberately not `TIDEWAY_`-prefixed, so scrubbing Tideway config from the child's
/// environment leaves it alone.
const CHILD_ENV: &str = "IT_CHILD_TEST";

/// Re-runs `test` alone in a child process of this test binary, so it can change
/// process-global state without racing the other tests sharing this process.
///
/// `module` is the caller's `module_path!()`. `configure` adjusts the child's command,
/// typically its environment. Returns `true` in the parent once the child has passed, and
/// `false` in the child, which should go on to run the test body:
///
/// ```ignore
/// if support::isolated(module_path!(), "my_test", |_| {}) {
///     return;
/// }
/// ```
pub fn isolated(module: &str, test: &str, configure: impl FnOnce(&mut Command)) -> bool {
    // libtest names omit the crate (`it::`) segment of the module path.
    let name = match module.split_once("::") {
        Some((_, module)) => format!("{module}::{test}"),
        None => test.to_string(),
    };
    if std::env::var(CHILD_ENV).as_deref() == Ok(name.as_str()) {
        return false;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD_ENV, &name);
    configure(&mut command);
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child run of {name} failed\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
