//! Proc macros for the Tideway web framework.
//!
//! This crate provides the `#[api]` attribute macro for defining HTTP handlers
//! with automatic OpenAPI documentation generation via utoipa.
//!
//! # Usage
//!
//! ```ignore
//! use tideway::api;
//!
//! #[tideway::api(get, "/users/:id")]
//! async fn get_user(Path(id): Path<Uuid>) -> Result<Json<User>> {
//!     // handler implementation
//! }
//! ```
//!
//! # Inference
//!
//! The macro automatically infers OpenAPI metadata from the handler signature:
//!
//! - **Path parameters**: Extracted from `Path<T>` and the route path
//! - **Query parameters**: Extracted from `Query<T>` or `ValidatedQuery<T>`
//! - **Request body**: Extracted from `Json<T>`, `ValidatedJson<T>`, `Form<T>`
//! - **Response type**: Extracted from the return type (e.g., `Result<Json<T>>`)
//! - **Security**: Inferred from `AuthUser<P>` or `Claims<P>` extractors
//!
//! # Override Options
//!
//! You can override any inferred value:
//!
//! ```ignore
//! #[tideway::api(
//!     post,
//!     "/users",
//!     tag = "users",
//!     summary = "Create a new user",
//!     responses((status = 201, description = "User created", body = User))
//! )]
//! async fn create_user(Json(req): Json<CreateRequest>) -> Result<Json<User>> {
//!     // handler implementation
//! }
//! ```

mod codegen;
mod inference;
mod parse;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use syn::{parse_macro_input, ItemFn};

use codegen::generate_api_macro;
use inference::analyze_handler;
use parse::ApiArgs;

/// Define an HTTP handler with automatic OpenAPI documentation.
///
/// # Arguments
///
/// Required:
/// - HTTP method (`get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `trace`)
/// - Route path (e.g., `"/users/:id"`)
///
/// Optional (key = value):
/// - `tag` - OpenAPI tag (default: "default")
/// - `summary` - Short description (default: first line of doc comment)
/// - `description` - Full description (default: doc comment)
/// - `operation_id` - Operation ID (default: function name)
/// - `request_body` - Request body type override
/// - `response` - Response type override
/// - `responses` - Additional response definitions
/// - `security` - Security scheme ("bearer", "none", or custom)
/// - `deprecated` - Mark endpoint as deprecated (default: false)
/// - `internal` - Add "internal" tag (default: false)
/// - `skip_openapi` - Skip OpenAPI generation (default: false)
///
/// # Example
///
/// ```ignore
/// #[tideway::api(get, "/users/:id", tag = "users")]
/// async fn get_user(
///     State(ctx): State<AppContext>,
///     Path(id): Path<Uuid>,
/// ) -> Result<Json<UserResponse>> {
///     let user = ctx.user_service.get(id).await?;
///     Ok(Json(UserResponse::from(user)))
/// }
/// ```
///
/// This expands to:
///
/// ```ignore
/// #[cfg_attr(feature = "openapi", utoipa::path(
///     get,
///     path = "/users/{id}",
///     tag = "users",
///     operation_id = "get_user",
///     params(("id" = Uuid, Path, description = "")),
///     responses(
///         (status = 200, description = "Success", body = UserResponse),
///         (status = 400, description = "Bad request", body = ErrorResponse),
///         (status = 401, description = "Unauthorized", body = ErrorResponse),
///         (status = 404, description = "Not found", body = ErrorResponse),
///         (status = 500, description = "Internal server error", body = ErrorResponse),
///     )
/// ))]
/// async fn get_user(
///     State(ctx): State<AppContext>,
///     Path(id): Path<Uuid>,
/// ) -> Result<Json<UserResponse>> {
///     let user = ctx.user_service.get(id).await?;
///     Ok(Json(UserResponse::from(user)))
/// }
/// ```
#[proc_macro_attribute]
pub fn api(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as ApiArgs);
    let func = parse_macro_input!(input as ItemFn);

    expand_api(args, func)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn expand_api(args: ApiArgs, func: ItemFn) -> syn::Result<TokenStream2> {
    // Analyze the handler function for type inference
    let inference = analyze_handler(&func);

    // Generate the output with utoipa attribute
    Ok(generate_api_macro(&args, &func, &inference))
}
