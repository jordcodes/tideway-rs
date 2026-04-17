use axum::{Json, Router, extract::Path, routing::get};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
/// Testing example demonstrating Tideway's testing utilities
///
/// This example shows:
/// - Alba-style HTTP testing
/// - Database testing with TestDb
/// - Testing with authentication
/// - Testing error cases
///
/// Run tests with: cargo test --example testing_example
use tideway::{ApiResponse, App, AppContext, CreatedResponse, Result, RouteModule, TidewayError};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Clone)]
struct Todo {
    id: u64,
    title: String,
    completed: bool,
}

#[derive(Deserialize)]
struct CreateTodoRequest {
    title: String,
}

// Mock storage (unused in simplified example)
#[allow(dead_code)]
struct TodoStore {
    todos: Vec<Todo>,
    next_id: u64,
}

#[allow(dead_code)]
impl TodoStore {
    fn new() -> Self {
        Self {
            todos: Vec::new(),
            next_id: 1,
        }
    }

    fn create(&mut self, title: String) -> Todo {
        let todo = Todo {
            id: self.next_id,
            title,
            completed: false,
        };
        self.next_id += 1;
        self.todos.push(todo.clone());
        todo
    }

    fn find(&self, id: u64) -> Option<Todo> {
        self.todos.iter().find(|t| t.id == id).cloned()
    }

    fn list(&self) -> Vec<Todo> {
        self.todos.clone()
    }
}

static TODO_STORE: LazyLock<Mutex<TodoStore>> = LazyLock::new(|| Mutex::new(TodoStore::new()));

async fn reset_store() {
    *TODO_STORE.lock().await = TodoStore::new();
}

async fn create_todo(Json(req): Json<CreateTodoRequest>) -> Result<CreatedResponse<Todo>> {
    let mut store = TODO_STORE.lock().await;
    let todo = store.create(req.title);
    Ok(ApiResponse::created(
        todo.clone(),
        format!("/api/todos/{}", todo.id),
    ))
}

async fn get_todo(Path(id): Path<u64>) -> Result<Json<Todo>> {
    let store = TODO_STORE.lock().await;
    let todo = store
        .find(id)
        .ok_or_else(|| TidewayError::not_found("Todo not found"))?;
    Ok(Json(todo))
}

async fn list_todos() -> Result<Json<Vec<Todo>>> {
    let store = TODO_STORE.lock().await;
    Ok(Json(store.list()))
}

struct TodosModule;

impl RouteModule for TodosModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/todos", get(list_todos).post(create_todo))
            .route("/todos/{id}", get(get_todo))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

#[cfg(test)]
fn create_app() -> Router {
    Router::new()
        .route("/api/todos", get(list_todos).post(create_todo))
        .route("/api/todos/{id}", get(get_todo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tideway::testing::{get, post};

    static TEST_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[tokio::test]
    async fn test_create_todo() {
        let _guard = TEST_GUARD.lock().await;
        reset_store().await;
        let app = create_app();

        let todo_data = json!({
            "title": "Test todo"
        });

        let response = post(app, "/api/todos")
            .json_body(&todo_data)
            .execute()
            .await
            .assert_created()
            .assert_json();

        let todo: Todo = response.json().await;
        assert_eq!(todo.title, "Test todo");
        assert!(!todo.completed);
    }

    #[tokio::test]
    async fn test_get_todo() {
        let _guard = TEST_GUARD.lock().await;
        reset_store().await;
        let app = create_app();

        // First create a todo
        let todo_data = json!({"title": "Get me"});
        let create_response = post(app.clone(), "/api/todos")
            .json_body(&todo_data)
            .execute()
            .await
            .assert_created();

        let created: Todo = create_response.json().await;
        let todo_id = created.id;

        // Then get it
        get(app, &format!("/api/todos/{}", todo_id))
            .execute()
            .await
            .assert_ok()
            .assert_json_field("title", json!("Get me"))
            .await;
    }

    #[tokio::test]
    async fn test_todo_not_found() {
        let _guard = TEST_GUARD.lock().await;
        reset_store().await;
        let app = create_app();

        get(app, "/api/todos/99999")
            .execute()
            .await
            .assert_not_found();
    }

    #[tokio::test]
    async fn test_list_todos() {
        let _guard = TEST_GUARD.lock().await;
        reset_store().await;
        let app = create_app();

        // Create a few todos
        for i in 1..=3 {
            let todo_data = json!({"title": format!("Todo {}", i)});
            post(app.clone(), "/api/todos")
                .json_body(&todo_data)
                .execute()
                .await
                .assert_created();
        }

        // List all todos
        let response = get(app, "/api/todos")
            .execute()
            .await
            .assert_ok()
            .assert_json();

        let todos: Vec<Todo> = response.json().await;
        assert_eq!(todos.len(), 3);
    }
}

#[tokio::main]
async fn main() {
    tideway::init_tracing();
    let app = App::new().register_module(TodosModule);
    tracing::info!("Testing example server starting on http://0.0.0.0:8000");
    app.serve().await.unwrap();
}
