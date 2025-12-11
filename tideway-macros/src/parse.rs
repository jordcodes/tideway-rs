//! Argument parsing for the `#[api]` macro.

use darling::FromMeta;
use proc_macro2::Span;
use syn::{Ident, Meta, Type, parse::Parse, parse::ParseStream, Token, LitStr, LitInt};

/// HTTP methods supported by the API macro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
}

impl HttpMethod {
    /// Parse HTTP method from identifier.
    pub fn from_ident(ident: &Ident) -> syn::Result<Self> {
        let method_str = ident.to_string().to_lowercase();
        match method_str.as_str() {
            "get" => Ok(HttpMethod::Get),
            "post" => Ok(HttpMethod::Post),
            "put" => Ok(HttpMethod::Put),
            "delete" => Ok(HttpMethod::Delete),
            "patch" => Ok(HttpMethod::Patch),
            "head" => Ok(HttpMethod::Head),
            "options" => Ok(HttpMethod::Options),
            "trace" => Ok(HttpMethod::Trace),
            _ => Err(syn::Error::new(
                ident.span(),
                format!(
                    "unknown HTTP method '{}'. Expected one of: get, post, put, delete, patch, head, options, trace",
                    method_str
                ),
            )),
        }
    }

    /// Get the method name as a lowercase string for utoipa.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Delete => "delete",
            HttpMethod::Patch => "patch",
            HttpMethod::Head => "head",
            HttpMethod::Options => "options",
            HttpMethod::Trace => "trace",
        }
    }
}

/// A single response definition for OpenAPI.
#[derive(Debug, Clone)]
pub struct ResponseDef {
    pub status: u16,
    pub description: String,
    pub body: Option<Type>,
}

impl FromMeta for ResponseDef {
    fn from_meta(meta: &Meta) -> darling::Result<Self> {
        match meta {
            Meta::List(list) => {
                let mut status: Option<u16> = None;
                let mut description: Option<String> = None;
                let mut body: Option<Type> = None;

                list.parse_nested_meta(|nested| {
                    let ident = nested.path.get_ident().ok_or_else(|| {
                        nested.error("expected identifier")
                    })?;

                    match ident.to_string().as_str() {
                        "status" => {
                            nested.input.parse::<Token![=]>()?;
                            let lit: LitInt = nested.input.parse()?;
                            status = Some(lit.base10_parse()?);
                        }
                        "description" => {
                            nested.input.parse::<Token![=]>()?;
                            let lit: LitStr = nested.input.parse()?;
                            description = Some(lit.value());
                        }
                        "body" => {
                            nested.input.parse::<Token![=]>()?;
                            let ty: Type = nested.input.parse()?;
                            body = Some(ty);
                        }
                        other => {
                            return Err(nested.error(format!("unknown response field '{}'", other)));
                        }
                    }
                    Ok(())
                })?;

                let status = status.ok_or_else(|| darling::Error::missing_field("status"))?;
                let description = description.ok_or_else(|| darling::Error::missing_field("description"))?;

                Ok(ResponseDef { status, description, body })
            }
            _ => Err(darling::Error::unexpected_type("list")),
        }
    }
}

/// Parsed arguments for the `#[api]` macro.
#[derive(Debug)]
pub struct ApiArgs {
    /// HTTP method (required).
    pub method: HttpMethod,
    /// Route path (required), e.g., "/users/:id".
    pub path: String,
    /// OpenAPI tag (optional, defaults to module name).
    pub tag: Option<String>,
    /// Summary for the endpoint (optional, defaults to doc comment).
    pub summary: Option<String>,
    /// Description for the endpoint (optional, defaults to doc comment).
    pub description: Option<String>,
    /// Operation ID (optional, defaults to function name).
    pub operation_id: Option<String>,
    /// Request body type override (optional, inferred from Json<T>).
    pub request_body: Option<Type>,
    /// Response type override (optional, inferred from return type).
    pub response: Option<Type>,
    /// Additional response definitions.
    pub responses: Vec<ResponseDef>,
    /// Security scheme (optional, inferred from AuthUser).
    /// Use "none" to disable security, "bearer" for bearer_auth, or custom scheme name.
    pub security: Option<String>,
    /// Whether the endpoint is deprecated.
    pub deprecated: bool,
    /// Whether this is an internal endpoint (adds "internal" tag).
    pub internal: bool,
    /// Skip OpenAPI generation entirely.
    pub skip_openapi: bool,
}

impl Parse for ApiArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Parse method (required)
        let method_ident: Ident = input.parse()?;
        let method = HttpMethod::from_ident(&method_ident)?;

        // Parse comma
        input.parse::<Token![,]>()?;

        // Parse path (required)
        let path_lit: LitStr = input.parse()?;
        let path = path_lit.value();

        // Parse optional named arguments
        let mut tag = None;
        let mut summary = None;
        let mut description = None;
        let mut operation_id = None;
        let mut request_body = None;
        let mut response = None;
        let mut responses = Vec::new();
        let mut security = None;
        let mut deprecated = false;
        let mut internal = false;
        let mut skip_openapi = false;

        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;

            // Check if we've reached the end
            if input.is_empty() {
                break;
            }

            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match key.to_string().as_str() {
                "tag" => {
                    let value: LitStr = input.parse()?;
                    tag = Some(value.value());
                }
                "summary" => {
                    let value: LitStr = input.parse()?;
                    summary = Some(value.value());
                }
                "description" => {
                    let value: LitStr = input.parse()?;
                    description = Some(value.value());
                }
                "operation_id" => {
                    let value: LitStr = input.parse()?;
                    operation_id = Some(value.value());
                }
                "request_body" => {
                    let ty: Type = input.parse()?;
                    request_body = Some(ty);
                }
                "response" => {
                    let ty: Type = input.parse()?;
                    response = Some(ty);
                }
                "responses" => {
                    // Parse responses as a parenthesized list of tuples
                    let content;
                    syn::parenthesized!(content in input);

                    while !content.is_empty() {
                        let inner;
                        syn::parenthesized!(inner in content);

                        let mut status: Option<u16> = None;
                        let mut desc: Option<String> = None;
                        let mut body: Option<Type> = None;

                        while !inner.is_empty() {
                            let field_name: Ident = inner.parse()?;
                            inner.parse::<Token![=]>()?;

                            match field_name.to_string().as_str() {
                                "status" => {
                                    let lit: LitInt = inner.parse()?;
                                    status = Some(lit.base10_parse()?);
                                }
                                "description" => {
                                    let lit: LitStr = inner.parse()?;
                                    desc = Some(lit.value());
                                }
                                "body" => {
                                    let ty: Type = inner.parse()?;
                                    body = Some(ty);
                                }
                                other => {
                                    return Err(syn::Error::new(
                                        field_name.span(),
                                        format!("unknown response field '{}'", other),
                                    ));
                                }
                            }

                            if inner.peek(Token![,]) {
                                inner.parse::<Token![,]>()?;
                            }
                        }

                        let status = status.ok_or_else(|| {
                            syn::Error::new(Span::call_site(), "response missing 'status' field")
                        })?;
                        let description = desc.ok_or_else(|| {
                            syn::Error::new(Span::call_site(), "response missing 'description' field")
                        })?;

                        responses.push(ResponseDef { status, description, body });

                        if content.peek(Token![,]) {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                "security" => {
                    let value: LitStr = input.parse()?;
                    security = Some(value.value());
                }
                "deprecated" => {
                    let value: syn::LitBool = input.parse()?;
                    deprecated = value.value();
                }
                "internal" => {
                    let value: syn::LitBool = input.parse()?;
                    internal = value.value();
                }
                "skip_openapi" => {
                    let value: syn::LitBool = input.parse()?;
                    skip_openapi = value.value();
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown argument '{}'. Expected one of: tag, summary, description, operation_id, request_body, response, responses, security, deprecated, internal, skip_openapi",
                            other
                        ),
                    ));
                }
            }
        }

        Ok(ApiArgs {
            method,
            path,
            tag,
            summary,
            description,
            operation_id,
            request_body,
            response,
            responses,
            security,
            deprecated,
            internal,
            skip_openapi,
        })
    }
}

/// Convert Axum-style path to OpenAPI-style.
/// - `:id` becomes `{id}`
/// - `*rest` becomes `{rest}`
pub fn convert_path_to_openapi(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            ':' => {
                // Collect the parameter name
                result.push('{');
                while let Some(&next) = chars.peek() {
                    if next.is_alphanumeric() || next == '_' {
                        result.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                result.push('}');
            }
            '*' => {
                // Wildcard parameter
                result.push('{');
                while let Some(&next) = chars.peek() {
                    if next.is_alphanumeric() || next == '_' {
                        result.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                result.push('}');
            }
            _ => result.push(ch),
        }
    }

    result
}

/// Extract path parameter names from an Axum-style path.
pub fn extract_path_params(path: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == ':' || ch == '*' {
            let mut param = String::new();
            while let Some(&next) = chars.peek() {
                if next.is_alphanumeric() || next == '_' {
                    param.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
            if !param.is_empty() {
                params.push(param);
            }
        }
    }

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_path_to_openapi() {
        assert_eq!(convert_path_to_openapi("/users/:id"), "/users/{id}");
        assert_eq!(convert_path_to_openapi("/users/:user_id/posts/:post_id"), "/users/{user_id}/posts/{post_id}");
        assert_eq!(convert_path_to_openapi("/files/*path"), "/files/{path}");
        assert_eq!(convert_path_to_openapi("/health"), "/health");
    }

    #[test]
    fn test_extract_path_params() {
        assert_eq!(extract_path_params("/users/:id"), vec!["id"]);
        assert_eq!(extract_path_params("/users/:user_id/posts/:post_id"), vec!["user_id", "post_id"]);
        assert_eq!(extract_path_params("/files/*path"), vec!["path"]);
        assert_eq!(extract_path_params("/health"), Vec::<String>::new());
    }
}
