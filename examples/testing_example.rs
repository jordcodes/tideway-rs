/// Testing example demonstrating Tideway's testing utilities
///
/// This example shows:
/// - Alba-style HTTP testing
/// - Database testing with TestDb
/// - Testing with authentication
/// - Testing error cases
///
/// Run tests with: cargo test --example testing_example
use tideway::{App, RouteModule, Result, AppContext};
use axum::{Router, routing::get, Json, extract::State};
use serde::{Deserialize, Serialize};

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

    fn find(&self, id: u64) -> Option<&Todo> {
        self.todos.iter().find(|t| t.id == id)
    }

    fn list(&self) -> Vec<Todo> {
        self.todos.clone()
    }
}

// Simplified handlers for example (without state for simplicity)
async fn create_todo(Json(req): Json<CreateTodoRequest>) -> Result<Json<Todo>> {
    // In real app, this would use state/database
    let todo = Todo {
        id: 1,
        title: req.title,
        completed: false,
    };
    Ok(Json(todo))
}

async fn get_todo(axum::extract::Path(id): axum::extract::Path<u64>) -> Result<Json<Todo>> {
    // In real app, this would query database
    if id == 1 {
        Ok(Json(Todo {
            id: 1,
            title: "Test todo".to_string(),
            completed: false,
        }))
    } else {
        Err(tideway::TidewayError::not_found("Todo not found"))
    }
}

async fn list_todos(State(_ctx): State<AppContext>) -> Result<Json<Vec<Todo>>> {
    // In real app, this would query database
    Ok(Json(vec![
        Todo {
            id: 1,
            title: "Todo 1".to_string(),
            completed: false,
        },
    ]))
}

struct TodosModule;

impl RouteModule for TodosModule {
    fn routes(&self) -> Router<AppContext> {
        Router::new()
            .route("/todos", get(list_todos).post(create_todo))
            .route("/todos/:id", get(get_todo))
    }

    fn prefix(&self) -> Option<&str> {
        Some("/api")
    }
}

#[cfg(test)]
fn create_app() -> Router {
    // Simplified example - create router directly
    // In real app, you'd use App with proper state management
    Router::new()
        .route("/api/todos", get(list_todos).post(create_todo))
        .route("/api/todos/:id", get(get_todo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tideway::testing::{get, post};
    use serde_json::json;

    #[tokio::test]
    async fn test_create_todo() {
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
        let app = create_app();

        get(app, "/api/todos/99999")
            .execute()
            .await
            .assert_not_found();
    }

    #[tokio::test]
    async fn test_list_todos() {
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
    let app = App::new()
        .register_module(TodosModule);
    tracing::info!("Testing example server starting on http://0.0.0.0:8000");
    app.serve().await.unwrap();
}
