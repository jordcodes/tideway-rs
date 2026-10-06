//! `tideway generate client` and React/Next frontend template tests.
//!
//! The client tests build a real OpenAPI document with utoipa (the same library a
//! Tideway app uses) from a small sample todo app shaped like `tideway resource`
//! output, generate the TypeScript client from it, and — when a TypeScript compiler
//! is available (`TIDEWAY_TSC=/path/to/tsc` or `tsc` on PATH) — type-check a sample
//! frontend against it (including `@ts-expect-error` misuse cases) and run it under
//! Node with a mock `fetch`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

mod sample_app {
    use super::*;

    #[derive(Serialize, Deserialize, ToSchema)]
    #[serde(rename_all = "snake_case")]
    pub enum TodoStatus {
        Open,
        Done,
    }

    /// A todo item.
    #[derive(Serialize, Deserialize, ToSchema)]
    pub struct Todo {
        pub id: i64,
        pub title: String,
        pub completed: bool,
        pub status: TodoStatus,
        /// Optional free-form notes.
        pub notes: Option<String>,
        pub tags: Vec<String>,
    }

    #[derive(Serialize, Deserialize, ToSchema)]
    pub struct CreateTodoRequest {
        pub title: String,
        pub notes: Option<String>,
    }

    #[derive(Serialize, Deserialize, ToSchema)]
    pub struct UpdateTodoRequest {
        pub title: Option<String>,
        pub completed: Option<bool>,
    }

    #[derive(Serialize, Deserialize, ToSchema)]
    pub struct MessageResponse {
        pub message: String,
    }

    #[derive(Deserialize, IntoParams)]
    #[into_params(parameter_in = Query)]
    #[allow(dead_code)]
    pub struct PaginationParams {
        pub limit: Option<u64>,
        pub offset: Option<u64>,
        /// Search term
        pub q: Option<String>,
    }

    /// List todos
    #[utoipa::path(
        get,
        path = "/api/todos",
        params(PaginationParams),
        responses((status = 200, body = [Todo]))
    )]
    #[allow(dead_code)]
    pub fn list_todos() {}

    /// Get a todo
    #[utoipa::path(
        get,
        path = "/api/todos/{id}",
        params(("id" = i64, Path, description = "Todo id")),
        responses((status = 200, body = Todo), (status = 404, description = "Not found"))
    )]
    #[allow(dead_code)]
    pub fn get_todo() {}

    /// Create a todo
    #[utoipa::path(
        post,
        path = "/api/todos",
        request_body = CreateTodoRequest,
        responses((status = 201, body = Todo)),
        security(("bearer_auth" = []))
    )]
    #[allow(dead_code)]
    pub fn create_todo() {}

    #[utoipa::path(
        put,
        path = "/api/todos/{id}",
        params(("id" = i64, Path)),
        request_body = UpdateTodoRequest,
        responses((status = 200, body = MessageResponse))
    )]
    #[allow(dead_code)]
    pub fn update_todo() {}

    #[utoipa::path(
        delete,
        path = "/api/todos/{id}",
        params(("id" = i64, Path)),
        responses((status = 204, description = "Deleted"))
    )]
    #[allow(dead_code)]
    pub fn delete_todo() {}

    #[derive(OpenApi)]
    #[openapi(
        info(title = "Sample Todo API", version = "1.0.0"),
        paths(list_todos, get_todo, create_todo, update_todo, delete_todo),
        components(schemas(
            Todo,
            TodoStatus,
            CreateTodoRequest,
            UpdateTodoRequest,
            MessageResponse
        ))
    )]
    pub struct ApiDoc;
}

const SAMPLE_FRONTEND: &str = r#"import { ApiError, createClient, type CreateTodoRequest, type Todo, type TodoStatus } from './client';

type Call = { url: string; method: string; headers: Record<string, string>; body?: string };
const calls: Call[] = [];

const sampleTodo: Todo = { id: 7, title: 'Ship it', completed: false, status: 'open', notes: null, tags: ['a'] };

async function mockFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = String(input);
  const method = init?.method ?? 'GET';
  calls.push({ url, method, headers: init?.headers as Record<string, string>, body: init?.body as string | undefined });
  if (url.endsWith('/api/todos/404')) {
    return new Response(JSON.stringify({ error: 'Not found: Todo' }), { status: 404 });
  }
  if (method === 'DELETE') return new Response(null, { status: 204 });
  if (method === 'PUT') return new Response(JSON.stringify({ message: 'updated' }), { status: 200 });
  if (method === 'POST') return new Response(JSON.stringify(sampleTodo), { status: 201 });
  if (url.includes('/api/todos/')) return new Response(JSON.stringify(sampleTodo), { status: 200 });
  return new Response(JSON.stringify([sampleTodo]), { status: 200 });
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

async function main() {
  const api = createClient({ baseUrl: 'http://api.test/', fetch: mockFetch, getToken: () => 'tok' });

  const todos: Todo[] = await api.listTodos({ limit: 10, q: 'ship it' });
  assert(todos[0].title === 'Ship it', 'list returns parsed todos');
  assert(calls[0].url === 'http://api.test/api/todos?limit=10&q=ship+it', `list url: ${calls[0].url}`);
  assert(calls[0].headers.Authorization === 'Bearer tok', 'bearer token header');

  await api.listTodos();
  assert(calls[1].url === 'http://api.test/api/todos', `query is optional: ${calls[1].url}`);

  const todo = await api.getTodo(7);
  const status: TodoStatus = todo.status;
  assert(status === 'open' && todo.id === 7, 'get returns typed todo');
  assert(calls[2].url === 'http://api.test/api/todos/7', `get url: ${calls[2].url}`);

  const input: CreateTodoRequest = { title: 'New' };
  const created = await api.createTodo(input);
  assert(created.id === 7, 'create returns todo');
  assert(calls[3].method === 'POST' && calls[3].body === '{"title":"New"}', 'create sends JSON body');
  assert(calls[3].headers['Content-Type'] === 'application/json', 'create sets content type');

  const updated = await api.updateTodo(7, { completed: true });
  assert(updated.message === 'updated', 'update returns message');
  assert(calls[4].method === 'PUT' && calls[4].url === 'http://api.test/api/todos/7', 'update url');

  const deleted: void = await api.deleteTodo(7);
  assert(deleted === undefined, 'delete resolves to void');

  try {
    await api.getTodo(404);
    throw new Error('expected ApiError');
  } catch (error) {
    assert(error instanceof ApiError, 'non-2xx throws ApiError');
    assert(error.status === 404 && error.message === 'Not found: Todo', `error mapping: ${error.message}`);
  }

  console.log('sample frontend OK');
}

// Compile-time contract: misuse must not type-check.
async function typeErrors(api: ReturnType<typeof createClient>) {
  // @ts-expect-error path id is an integer
  await api.getTodo('7');
  // @ts-expect-error title must be a string
  await api.createTodo({ title: 123 });
  // @ts-expect-error create requires a body
  await api.createTodo();
  // @ts-expect-error unknown query parameter
  await api.listTodos({ page: 1 });
  // @ts-expect-error limit is numeric
  await api.listTodos({ limit: 'ten' });
  const todo = await api.getTodo(1);
  // @ts-expect-error unknown property
  todo.nope;
  // @ts-expect-error status is a closed enum
  const status: TodoStatus = 'archived';
  void status;
}
void typeErrors;

main().catch((error) => {
  console.error(error);
  throw error;
});
"#;

#[test]
fn test_generate_client_from_sample_app_openapi() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let spec_path = temp_dir.path().join("openapi.json");
    let spec = sample_app::ApiDoc::openapi()
        .to_pretty_json()
        .expect("serialize spec");
    fs::write(&spec_path, spec).expect("write spec");
    let client_path = temp_dir.path().join("web/src/api/client.ts");

    let output = run_tideway(&[
        "generate",
        "client",
        "--spec",
        path_str(&spec_path),
        "--output",
        path_str(&client_path),
    ]);
    assert_success(&output, "tideway generate client");

    let client = fs::read_to_string(&client_path).expect("read generated client");
    for expected in [
        "// Generated by `tideway generate client` from the OpenAPI document for Sample Todo API 1.0.0.",
        "export interface Todo {",
        "  id: number;",
        "  title: string;",
        "  status: TodoStatus;",
        "  notes?: string | null;",
        "  tags: Array<string>;",
        "export type TodoStatus = \"open\" | \"done\";",
        "listTodos: (query?: { limit?: number; offset?: number; q?: string }, options?: RequestOptions): Promise<Array<Todo>> =>",
        "getTodo: (id: number, options?: RequestOptions): Promise<Todo> =>",
        "createTodo: (body: CreateTodoRequest, options?: RequestOptions): Promise<Todo> =>",
        "updateTodo: (id: number, body: UpdateTodoRequest, options?: RequestOptions): Promise<MessageResponse> =>",
        "deleteTodo: (id: number, options?: RequestOptions): Promise<void> =>",
        "export class ApiError extends Error {",
        "export type TidewayClient = ReturnType<typeof createClient>;",
    ] {
        assert!(
            client.contains(expected),
            "expected `{}` in generated client:\n{}",
            expected,
            client
        );
    }

    typecheck_and_run_sample_frontend(temp_dir.path(), &client_path);
}

#[test]
fn test_generate_client_regenerates_without_force_but_protects_hand_written_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let spec_path = temp_dir.path().join("openapi.json");
    fs::write(
        &spec_path,
        sample_app::ApiDoc::openapi().to_json().expect("spec json"),
    )
    .expect("write spec");

    let client_path = temp_dir.path().join("client.ts");
    fs::write(
        &client_path,
        "// Generated by `tideway generate client` (old)\n",
    )
    .expect("seed");
    let output = run_tideway(&[
        "generate",
        "client",
        "--spec",
        path_str(&spec_path),
        "--output",
        path_str(&client_path),
    ]);
    assert_success(&output, "regenerate client");
    assert!(
        fs::read_to_string(&client_path)
            .unwrap()
            .contains("getTodo"),
        "previously generated client should be regenerated in place"
    );

    let custom_path = temp_dir.path().join("custom.ts");
    fs::write(&custom_path, "export const mine = 1;\n").expect("seed custom");
    let output = run_tideway(&[
        "generate",
        "client",
        "--spec",
        path_str(&spec_path),
        "--output",
        path_str(&custom_path),
    ]);
    assert_success(&output, "skip hand-written file");
    assert_eq!(
        fs::read_to_string(&custom_path).unwrap(),
        "export const mine = 1;\n"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("use --force to overwrite"));
}

#[test]
fn test_generate_client_missing_spec_explains_how_to_export_it() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let missing = temp_dir.path().join("missing.json");
    let output = run_tideway(&["generate", "client", "--spec", path_str(&missing)]);
    assert!(!output.status.success(), "missing spec should fail");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Could not read OpenAPI document"),
        "{stdout}"
    );
    assert!(stdout.contains("/api-docs/openapi.json"), "{stdout}");
}

#[test]
fn test_generate_auth_for_react_and_next() {
    for (framework, env_expr, use_client) in [
        ("react", "import.meta.env.VITE_API_URL", false),
        ("next", "process.env.NEXT_PUBLIC_API_URL", true),
    ] {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let output_dir = temp_dir.path().join("components");
        let output = run_tideway(&[
            "generate",
            "auth",
            "--framework",
            framework,
            "--output",
            path_str(&output_dir),
        ]);
        assert_success(
            &output,
            &format!("tideway generate auth --framework {framework}"),
        );

        for file in [
            "auth/LoginForm.tsx",
            "auth/RegisterForm.tsx",
            "auth/ForgotPassword.tsx",
            "auth/ResetPassword.tsx",
            "auth/MfaVerify.tsx",
            "auth/useAuth.ts",
            "lib/api.ts",
            "types/index.ts",
        ] {
            assert!(
                output_dir.join(file).exists(),
                "{framework}: expected {file} to be generated"
            );
        }
        assert!(!output_dir.join("auth/LoginForm.vue").exists());

        let login = fs::read_to_string(output_dir.join("auth/LoginForm.tsx")).unwrap();
        assert!(login.contains("export function LoginForm("));
        assert!(login.contains("from 'react'"));
        assert_eq!(
            login.starts_with("'use client'"),
            use_client,
            "{framework}: unexpected 'use client' directive state"
        );
        assert!(!login.contains("{{"), "unrendered handlebars in LoginForm");

        let api = fs::read_to_string(output_dir.join("lib/api.ts")).unwrap();
        assert!(api.contains(env_expr), "{framework}: expected {env_expr}");
        assert!(api.contains("'http://localhost:3000'"));

        let use_auth = fs::read_to_string(output_dir.join("auth/useAuth.ts")).unwrap();
        assert!(use_auth.contains("useSyncExternalStore"));
        assert!(use_auth.contains("'/auth/login'"));
        assert!(use_auth.contains("'/auth/mfa/verify'"));

        let types = fs::read_to_string(output_dir.join("types/index.ts")).unwrap();
        assert!(types.contains("export interface LoginResponse"));
    }
}

#[test]
fn test_generate_react_rejects_unported_modules_with_guidance() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output = run_tideway(&[
        "generate",
        "billing",
        "--framework",
        "react",
        "--output",
        path_str(&temp_dir.path().join("components")),
    ]);
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tideway generate client"), "{stdout}");
    assert!(!temp_dir.path().join("components").exists());
}

#[test]
fn test_generate_vue_shared_types_still_rendered() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("components");
    let output = run_tideway(&["generate", "auth", "--output", path_str(&output_dir)]);
    assert_success(&output, "tideway generate auth (vue)");
    assert!(output_dir.join("auth/LoginForm.vue").exists());
    let types = fs::read_to_string(output_dir.join("types/index.ts")).unwrap();
    assert!(types.contains("export interface LoginRequest"));
}

/// Type-check the sample frontend against the generated client and execute it.
fn typecheck_and_run_sample_frontend(root: &Path, client_path: &Path) {
    let Some(tsc) = find_tsc() else {
        eprintln!(
            "skipping TypeScript type-check of the generated client: set TIDEWAY_TSC or put `tsc` on PATH"
        );
        return;
    };
    let app_dir = root.join("sample-frontend");
    fs::create_dir_all(&app_dir).unwrap();
    fs::copy(client_path, app_dir.join("client.ts")).unwrap();
    fs::write(app_dir.join("main.ts"), SAMPLE_FRONTEND).unwrap();

    fs::write(
        app_dir.join("tsconfig.json"),
        r#"{
  "compilerOptions": {
    "strict": true,
    "noUnusedLocals": true,
    "target": "es2022",
    "lib": ["es2022", "dom"],
    "module": "commonjs",
    "types": [],
    "outDir": "dist"
  },
  "files": ["client.ts", "main.ts"]
}
"#,
    )
    .unwrap();

    let out_dir = app_dir.join("dist");
    let output = Command::new(&tsc)
        .args(["-p"])
        .arg(&app_dir)
        .output()
        .expect("run tsc");
    assert!(
        output.status.success(),
        "generated client failed to type-check:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let Ok(node) = which("node") else {
        eprintln!("skipping sample frontend run: `node` not on PATH");
        return;
    };
    let output = Command::new(node)
        .arg(out_dir.join("main.js"))
        .output()
        .expect("run node");
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("sample frontend OK"),
        "sample frontend failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn find_tsc() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TIDEWAY_TSC") {
        return Some(PathBuf::from(path));
    }
    which("tsc").ok()
}

fn which(binary: &str) -> Result<PathBuf, ()> {
    let paths = std::env::var_os("PATH").ok_or(())?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
        .ok_or(())
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

fn run_tideway(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tideway"))
        .args(args)
        .output()
        .expect("run tideway")
}

fn assert_success(output: &std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{} failed.\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
