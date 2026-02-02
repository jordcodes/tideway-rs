use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn snapshot_files(files: &[PathBuf]) -> BTreeMap<PathBuf, String> {
    files
        .iter()
        .map(|path| {
            let content = fs::read_to_string(path).expect("read tracked file");
            (path.clone(), content)
        })
        .collect()
}
