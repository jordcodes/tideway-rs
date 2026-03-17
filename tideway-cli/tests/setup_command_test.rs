use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn test_setup_fails_without_package_json() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("setup")
        .current_dir(temp_dir.path())
        .output()
        .expect("run tideway setup");

    assert!(
        !output.status.success(),
        "expected setup to fail without package.json.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No package.json found."),
        "expected missing package.json error, got:\n{}",
        combined
    );
}

#[test]
fn test_setup_plan_mode_is_non_mutating() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_fixture(&project_dir);

    let tracked_files = fixture_files(&project_dir);
    let before = snapshot_files(&tracked_files);

    let output = Command::new(env!("CARGO_BIN_EXE_tideway"))
        .arg("--plan")
        .arg("setup")
        .current_dir(&project_dir)
        .output()
        .expect("run tideway setup --plan");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let after = snapshot_files(&tracked_files);
    assert_eq!(before, after, "expected setup --plan to be non-mutating");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Plan: run command `npm install -D tailwindcss @tailwindcss/vite`"),
        "expected command plan output, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Plan: write file src/App.vue"),
        "expected file plan output, got:\n{}",
        stdout
    );

    assert!(project_dir.join("src/components/icons").exists());
}

#[test]
fn test_setup_fails_when_shadcn_init_fails() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let project_dir = temp_dir.path().join("my_app");
    create_fixture(&project_dir);

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_fake_npm(&fake_bin_dir);
    write_fake_npx_failing_init(&fake_bin_dir);

    let output = run_tideway_with_path_in_dir(&["setup"], &project_dir, &fake_bin_dir);
    assert!(
        !output.status.success(),
        "expected setup to fail when shadcn init fails.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Failed to initialize shadcn-vue."),
        "expected shadcn init failure message, got:\n{}",
        combined
    );
}

fn run_tideway_with_path_in_dir(
    args: &[&str],
    current_dir: &Path,
    fake_bin_dir: &Path,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    for arg in args {
        command.arg(arg);
    }
    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", fake_bin_dir.display(), current_path);
    command
        .current_dir(current_dir)
        .env("PATH", new_path)
        .output()
        .expect("run tideway")
}

fn create_fixture(project_dir: &Path) {
    fs::create_dir_all(project_dir.join("src/components/icons")).expect("create components/icons");
    fs::create_dir_all(project_dir.join("src/views")).expect("create views");
    fs::create_dir_all(project_dir.join("src/assets")).expect("create assets");
    fs::create_dir_all(project_dir.join("src/router")).expect("create router");

    fs::write(
        project_dir.join("package.json"),
        "{\n  \"name\": \"my_app\"\n}\n",
    )
    .expect("write package.json");
    fs::write(
        project_dir.join("src/components/HelloWorld.vue"),
        "<template>Hello</template>\n",
    )
    .expect("write HelloWorld.vue");
    fs::write(
        project_dir.join("src/components/icons/IconCommunity.vue"),
        "<template>Icon</template>\n",
    )
    .expect("write icon");
    fs::write(
        project_dir.join("src/views/HomeView.vue"),
        "<template>Home</template>\n",
    )
    .expect("write HomeView.vue");
    fs::write(
        project_dir.join("src/views/AboutView.vue"),
        "<template>About</template>\n",
    )
    .expect("write AboutView.vue");
    fs::write(
        project_dir.join("src/App.vue"),
        "<template>App</template>\n",
    )
    .expect("write App.vue");
    fs::write(
        project_dir.join("src/assets/main.css"),
        "@import './base.css';\nbody { color: red; }\n",
    )
    .expect("write main.css");
    fs::write(
        project_dir.join("src/assets/base.css"),
        "html, body { margin: 0; }\n",
    )
    .expect("write base.css");
    fs::write(
        project_dir.join("src/router/index.ts"),
        "export default [];\n",
    )
    .expect("write router");
    fs::write(
        project_dir.join("vite.config.ts"),
        "import vue from '@vitejs/plugin-vue'\nexport default { plugins: [vue()] }\n",
    )
    .expect("write vite config");
    fs::write(
        project_dir.join("tsconfig.json"),
        "{\n  \"compilerOptions\": {}\n}\n",
    )
    .expect("write tsconfig.json");
    fs::write(
        project_dir.join("tsconfig.app.json"),
        "{\n  \"compilerOptions\": {}\n}\n",
    )
    .expect("write tsconfig.app.json");
}

fn fixture_files(project_dir: &Path) -> Vec<PathBuf> {
    vec![
        project_dir.join("package.json"),
        project_dir.join("src/components/HelloWorld.vue"),
        project_dir.join("src/components/icons/IconCommunity.vue"),
        project_dir.join("src/views/HomeView.vue"),
        project_dir.join("src/views/AboutView.vue"),
        project_dir.join("src/App.vue"),
        project_dir.join("src/assets/main.css"),
        project_dir.join("src/assets/base.css"),
        project_dir.join("src/router/index.ts"),
        project_dir.join("vite.config.ts"),
        project_dir.join("tsconfig.json"),
        project_dir.join("tsconfig.app.json"),
    ]
}

fn write_fake_npm(fake_bin_dir: &Path) {
    let fake_npm = fake_bin_dir.join("npm");
    fs::write(&fake_npm, "#!/usr/bin/env bash\nexit 0\n").expect("write fake npm");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&fake_npm).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake_npm, perms).expect("set executable bit");
    }
}

fn write_fake_npx_failing_init(fake_bin_dir: &Path) {
    let fake_npx = fake_bin_dir.join("npx");
    fs::write(
        &fake_npx,
        "#!/usr/bin/env bash\nif [ \"${2:-}\" = \"init\" ]; then exit 1; fi\nexit 0\n",
    )
    .expect("write fake npx");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&fake_npx).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake_npx, perms).expect("set executable bit");
    }
}

fn snapshot_files(files: &[PathBuf]) -> BTreeMap<PathBuf, String> {
    files
        .iter()
        .map(|path| {
            let content = fs::read_to_string(path).expect("read tracked file");
            (path.clone(), content)
        })
        .collect()
}
