# OpenAPI Documentation

Tideway provides built-in OpenAPI 3.0 documentation support using the `utoipa` crate. This allows you to generate type-safe API documentation and client SDKs automatically.

## Features

- **Automatic documentation generation** from code annotations
- **Swagger UI** for interactive API exploration
- **OpenAPI 3.0 specification** endpoint for client generation
- **Flexible visibility control** for different environments
- **JWT Bearer authentication** support

## Configuration

OpenAPI support is controlled via environment variables:

### Environment Variables

```bash
# Enable/disable OpenAPI documentation (default: true)
OPENAPI_ENABLED=true

# Enable/disable Swagger UI (default: true)
OPENAPI_SWAGGER_UI=true

# Serve OpenAPI spec JSON endpoint (default: true)
OPENAPI_SERVE_SPEC=true

# Control visibility of endpoints (default: all)
# Options: all, public, internal
OPENAPI_VISIBILITY=all
```

### Custom Paths

You can customize the Swagger UI and spec paths:

```bash
# Swagger UI path (default: /swagger-ui)
OPENAPI_SWAGGER_UI_PATH=/swagger-ui

# OpenAPI spec path (default: /api-docs/openapi.json)
OPENAPI_SPEC_PATH=/api-docs/openapi.json
```

## Accessing the Documentation

Once your application is running with OpenAPI enabled:

1. **Swagger UI**: Visit `http://localhost:8080/swagger-ui` to explore the API interactively
2. **OpenAPI Spec**: Download the spec from `http://localhost:8080/api-docs/openapi.json`

## Usage Scenarios

### Development - Private API

For private APIs where you only need type generation locally:

```bash
OPENAPI_ENABLED=true
OPENAPI_SWAGGER_UI=false
OPENAPI_SERVE_SPEC=false
```

This allows you to generate the OpenAPI spec during development without exposing it in production.

### Production - Public API

For public APIs where you want full documentation:

```bash
OPENAPI_ENABLED=true
OPENAPI_SWAGGER_UI=true
OPENAPI_SERVE_SPEC=true
OPENAPI_VISIBILITY=public
```

### Mixed - Public and Internal Endpoints

For APIs with both public and internal endpoints:

```bash
OPENAPI_ENABLED=true
OPENAPI_SWAGGER_UI=true
OPENAPI_SERVE_SPEC=true
OPENAPI_VISIBILITY=public  # Only show public endpoints
```

Tag your internal endpoints with `tag = "internal"` and public ones with appropriate tags like `"customers"`, `"orders"`, etc.

## Adding Documentation to Your Endpoints

### 1. Add Schema Derives to Your Types

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateCustomerRequest {
    pub name: String,
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CustomerResponse {
    pub id: i64,
    pub name: String,
    pub email: Option<String>,
}
```

**Note**: Use `utoipa::IntoParams` for query parameters:

```rust
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationParams {
    pub page: u64,
    pub per_page: u64,
}
```

### 2. Annotate Your Handler Functions

**Recommended: Using the `#[api]` macro** (requires `macros` feature):

```rust
use tideway::api;

/// Create a new customer
#[api(post, "/api/customers", tag = "customers")]
async fn create_customer(
    AuthUser(user): AuthUser<MyAuthProvider>,
    Json(req): Json<CreateCustomerRequest>,
) -> Result<Json<ApiResponse<CustomerResponse>>> {
    // Implementation
}

/// Get a customer by ID
#[api(get, "/api/customers/:id", tag = "customers")]
async fn get_customer(
    AuthUser(user): AuthUser<MyAuthProvider>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<CustomerResponse>>> {
    // Implementation
}
```

The `#[api]` macro automatically infers:
- Path parameters from `:param` syntax (converted to `{param}` for OpenAPI)
- Request body from `Json<T>` extractors
- Query parameters from `Query<T>` extractors (if T implements `IntoParams`)
- Security requirement from `AuthUser<T>` extractors
- Response type from return type

**Override options:**
- `security = "none"` - disable authentication requirement for public endpoints
- `tag = "custom_tag"` - override the default tag

**Alternative: Manual utoipa annotations** (for edge cases):

```rust
/// Create a new customer
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/customers",
    tag = "customers",
    request_body = CreateCustomerRequest,
    responses(
        (status = 200, description = "Customer created", body = ApiResponse<CustomerResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
))]
async fn create_customer(
    Json(req): Json<CreateCustomerRequest>,
) -> Result<Json<ApiResponse<CustomerResponse>>> {
    // Implementation
}
```

Use manual annotations for:
- Handlers returning `()` or `impl IntoResponse`
- Handlers returning `StatusCode` or `Response` directly
- Query types that don't implement `IntoParams`

### 3. Register Paths in main.rs

Add your endpoints to the `ApiDoc` struct:

```rust
#[cfg(feature = "openapi")]
#[derive(OpenApi)]
#[openapi(
    paths(
        // Add your handlers here
        sh_api::routes::customers::create_customer,
        sh_api::routes::customers::list_customers,
    ),
    components(
        schemas(
            // Add your request/response types here
            sh_api::routes::customers::CreateCustomerRequest,
            sh_api::routes::customers::CustomerResponse,
        )
    ),
    tags(
        (name = "customers", description = "Customer management endpoints")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;
```

## Generating Client SDKs

You can use the OpenAPI spec to generate type-safe client libraries:

### TypeScript/Vue

```bash
# Install openapi-typescript
npm install -D openapi-typescript

# Generate TypeScript types
npx openapi-typescript http://localhost:8080/api-docs/openapi.json -o src/api/types.ts
```

### Other Languages

Use [openapi-generator](https://openapi-generator.tech/):

```bash
# Install openapi-generator-cli
npm install -g @openapitools/openapi-generator-cli

# Generate Python client
openapi-generator-cli generate \
  -i http://localhost:8080/api-docs/openapi.json \
  -g python \
  -o ./client/python

# Generate Go client
openapi-generator-cli generate \
  -i http://localhost:8080/api-docs/openapi.json \
  -g go \
  -o ./client/go
```

## Best Practices

1. **Always use `cfg_attr`**: Wrap OpenAPI derives and macros with `#[cfg_attr(feature = "openapi", ...)]` to keep them optional
2. **Document your endpoints**: Use the doc comments (`///`) - they appear in Swagger UI
3. **Use appropriate tags**: Group related endpoints with meaningful tags
4. **Specify all response codes**: Document success and error responses
5. **Keep schemas simple**: Complex nested generics can be difficult for OpenAPI to represent

## Disabling OpenAPI

To completely disable OpenAPI support, either:

1. Remove the `openapi` feature from `default` features in `Cargo.toml`
2. Set `OPENAPI_ENABLED=false` in your environment

## Troubleshooting

### Swagger UI not appearing

- Check that `OPENAPI_ENABLED=true` and `OPENAPI_SWAGGER_UI=true`
- Verify the path: default is `/swagger-ui`
- Check logs for "OpenAPI documentation enabled"

### Endpoints missing from documentation

- Ensure the handler function has `#[cfg_attr(feature = "openapi", utoipa::path(...))]`
- Verify the path is registered in the `ApiDoc` struct in `main.rs`
- Check that request/response types have `ToSchema` or `IntoParams` derives

### Generic type errors

For complex generic types like `ApiResponse<PaginatedResponse<CustomerResponse>>`, you may need to explicitly list them in the `components.schemas` section.

## Resources

- [utoipa documentation](https://docs.rs/utoipa/latest/utoipa/)
- [utoipa-swagger-ui documentation](https://docs.rs/utoipa-swagger-ui/latest/utoipa_swagger_ui/)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
- [Swagger UI](https://swagger.io/tools/swagger-ui/)
