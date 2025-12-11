//! Type inference from handler function signatures.
//!
//! This module analyzes handler function parameters and return types to infer:
//! - Path parameters (from Path<T> extractors)
//! - Query parameters (from Query<T> extractors)
//! - Request body type (from Json<T> extractors)
//! - Response type (from return type)
//! - Security requirements (from AuthUser extractors)

use syn::{FnArg, GenericArgument, ItemFn, PathArguments, ReturnType, Type};

/// Information about a path parameter.
#[derive(Debug, Clone)]
pub struct PathParamInfo {
    /// Parameter name (from the path, e.g., "id" from ":id").
    #[allow(dead_code)]
    pub name: String,
    /// The inferred type (from Path<T>), if available.
    pub ty: Option<Type>,
}

/// Information about query parameters.
#[derive(Debug, Clone)]
pub struct QueryParamInfo {
    /// The type T from Query<T> or ValidatedQuery<T>.
    pub ty: Type,
    /// Whether it uses validation (ValidatedQuery).
    #[allow(dead_code)]
    pub validated: bool,
}

/// Information about the request body.
#[derive(Debug, Clone)]
pub struct RequestBodyInfo {
    /// The type T from Json<T>, ValidatedJson<T>, Form<T>, etc.
    pub ty: Type,
    /// Content type for the request body.
    pub content_type: ContentType,
    /// Whether it uses validation.
    #[allow(dead_code)]
    pub validated: bool,
}

/// Content type for request/response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Json,
    Form,
    Multipart,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::Json => "application/json",
            ContentType::Form => "application/x-www-form-urlencoded",
            ContentType::Multipart => "multipart/form-data",
        }
    }
}

/// Information about security requirements.
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    /// Whether authentication is required.
    pub required: bool,
    /// The security scheme name (default: "bearer_auth").
    pub scheme: String,
}

/// Information about the response type.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// The response body type (T from Json<T>, ApiResponse<T>, etc.).
    pub body_type: Option<Type>,
    /// The default status code.
    pub status: u16,
    /// Whether errors are possible (wrapped in Result).
    pub can_fail: bool,
}

/// Complete inference result from analyzing a handler function.
#[derive(Debug)]
pub struct InferenceResult {
    /// Path parameter info (from Path<T> extractors).
    pub path_params: Vec<PathParamInfo>,
    /// Query parameter info (from Query<T> extractors).
    pub query_params: Option<QueryParamInfo>,
    /// Request body info (from Json<T>, Form<T>, etc.).
    pub request_body: Option<RequestBodyInfo>,
    /// Response info (from return type).
    pub response: ResponseInfo,
    /// Security requirements (from AuthUser, Claims extractors).
    pub security: Option<SecurityInfo>,
    /// Doc comment from the function (for summary/description).
    pub doc_comment: Option<String>,
}

/// Analyze a handler function and infer OpenAPI metadata.
pub fn analyze_handler(func: &ItemFn) -> InferenceResult {
    let mut path_params = Vec::new();
    let mut query_params = None;
    let mut request_body = None;
    let mut security = None;

    // Extract doc comments
    let doc_comment = extract_doc_comment(func);

    // Analyze each parameter
    for arg in &func.sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            let ty = &*pat_type.ty;
            analyze_extractor(ty, &mut path_params, &mut query_params, &mut request_body, &mut security);
        }
    }

    // Analyze return type
    let response = analyze_return_type(&func.sig.output);

    InferenceResult {
        path_params,
        query_params,
        request_body,
        response,
        security,
        doc_comment,
    }
}

/// Extract doc comments from function attributes.
fn extract_doc_comment(func: &ItemFn) -> Option<String> {
    let mut doc_lines = Vec::new();

    for attr in &func.attrs {
        if attr.path().is_ident("doc") {
            if let syn::Meta::NameValue(meta) = &attr.meta {
                if let syn::Expr::Lit(expr_lit) = &meta.value {
                    if let syn::Lit::Str(lit_str) = &expr_lit.lit {
                        doc_lines.push(lit_str.value().trim().to_string());
                    }
                }
            }
        }
    }

    if doc_lines.is_empty() {
        None
    } else {
        Some(doc_lines.join("\n"))
    }
}

/// Analyze an extractor type and update inference state.
fn analyze_extractor(
    ty: &Type,
    path_params: &mut Vec<PathParamInfo>,
    query_params: &mut Option<QueryParamInfo>,
    request_body: &mut Option<RequestBodyInfo>,
    security: &mut Option<SecurityInfo>,
) {
    // Try to get the type as a path (e.g., Path<T>, Json<T>, etc.)
    let Type::Path(type_path) = ty else {
        return;
    };

    let Some(last_segment) = type_path.path.segments.last() else {
        return;
    };

    let type_name = last_segment.ident.to_string();
    let inner_type = extract_generic_arg(&last_segment.arguments);

    match type_name.as_str() {
        // Path parameters
        "Path" | "PathParams" => {
            if let Some(inner) = inner_type {
                // For simple types like Path<Uuid>, use a single param
                // For struct types like Path<UserParams>, we'd need to look at the struct fields
                // For now, we'll just store the type and handle it at codegen time
                path_params.push(PathParamInfo {
                    name: String::new(), // Will be filled from the route path
                    ty: Some(inner),
                });
            }
        }

        // Query parameters
        "Query" => {
            if let Some(inner) = inner_type {
                *query_params = Some(QueryParamInfo {
                    ty: inner,
                    validated: false,
                });
            }
        }
        "ValidatedQuery" => {
            if let Some(inner) = inner_type {
                *query_params = Some(QueryParamInfo {
                    ty: inner,
                    validated: true,
                });
            }
        }

        // Request body - JSON
        "Json" => {
            if let Some(inner) = inner_type {
                *request_body = Some(RequestBodyInfo {
                    ty: inner,
                    content_type: ContentType::Json,
                    validated: false,
                });
            }
        }
        "ValidatedJson" => {
            if let Some(inner) = inner_type {
                *request_body = Some(RequestBodyInfo {
                    ty: inner,
                    content_type: ContentType::Json,
                    validated: true,
                });
            }
        }

        // Request body - Form
        "Form" => {
            if let Some(inner) = inner_type {
                *request_body = Some(RequestBodyInfo {
                    ty: inner,
                    content_type: ContentType::Form,
                    validated: false,
                });
            }
        }
        "ValidatedForm" => {
            if let Some(inner) = inner_type {
                *request_body = Some(RequestBodyInfo {
                    ty: inner,
                    content_type: ContentType::Form,
                    validated: true,
                });
            }
        }

        // Request body - Multipart
        "Multipart" => {
            *request_body = Some(RequestBodyInfo {
                ty: syn::parse_quote!(Vec<u8>), // Placeholder type for multipart
                content_type: ContentType::Multipart,
                validated: false,
            });
        }

        // Authentication extractors
        "AuthUser" | "Claims" => {
            *security = Some(SecurityInfo {
                required: true,
                scheme: "bearer_auth".to_string(),
            });
        }
        "OptionalAuth" => {
            *security = Some(SecurityInfo {
                required: false,
                scheme: "bearer_auth".to_string(),
            });
        }

        // State and other extractors - ignored
        "State" | "Extension" | "Request" | "Headers" | "HeaderMap" | "ConnectInfo" | "MatchedPath" | "OriginalUri" => {
            // These don't affect OpenAPI spec
        }

        _ => {
            // Unknown extractor - ignore
        }
    }
}

/// Extract the first generic argument from a type's arguments.
fn extract_generic_arg(args: &PathArguments) -> Option<Type> {
    match args {
        PathArguments::AngleBracketed(angle) => {
            for arg in &angle.args {
                if let GenericArgument::Type(ty) = arg {
                    return Some(ty.clone());
                }
            }
            None
        }
        _ => None,
    }
}

/// Analyze the return type to determine response information.
fn analyze_return_type(output: &ReturnType) -> ResponseInfo {
    let ReturnType::Type(_, ty) = output else {
        // No return type -> 200 OK with no body
        return ResponseInfo {
            body_type: None,
            status: 200,
            can_fail: false,
        };
    };

    // Check if it's wrapped in Result
    let (inner_ty, can_fail) = unwrap_result_type(ty);

    // Now analyze the inner response type
    analyze_response_type(&inner_ty, can_fail)
}

/// Unwrap Result<T, E> and return the inner type T and whether it was Result.
fn unwrap_result_type(ty: &Type) -> (Type, bool) {
    let Type::Path(type_path) = ty else {
        return (ty.clone(), false);
    };

    let Some(last_segment) = type_path.path.segments.last() else {
        return (ty.clone(), false);
    };

    if last_segment.ident == "Result" {
        if let Some(inner) = extract_generic_arg(&last_segment.arguments) {
            return (inner, true);
        }
    }

    (ty.clone(), false)
}

/// Analyze a response type (after unwrapping Result) to get body type and status.
fn analyze_response_type(ty: &Type, can_fail: bool) -> ResponseInfo {
    let Type::Path(type_path) = ty else {
        return ResponseInfo {
            body_type: Some(ty.clone()),
            status: 200,
            can_fail,
        };
    };

    let Some(last_segment) = type_path.path.segments.last() else {
        return ResponseInfo {
            body_type: Some(ty.clone()),
            status: 200,
            can_fail,
        };
    };

    let type_name = last_segment.ident.to_string();
    let inner_type = extract_generic_arg(&last_segment.arguments);

    match type_name.as_str() {
        "Json" => ResponseInfo {
            body_type: inner_type,
            status: 200,
            can_fail,
        },
        "ApiResponse" => {
            // ApiResponse<T> wraps T in a standard envelope
            ResponseInfo {
                body_type: inner_type,
                status: 200,
                can_fail,
            }
        }
        "CreatedResponse" => ResponseInfo {
            body_type: inner_type,
            status: 201,
            can_fail,
        },
        "NoContentResponse" => ResponseInfo {
            body_type: None,
            status: 204,
            can_fail,
        },
        "AcceptedResponse" => ResponseInfo {
            body_type: inner_type,
            status: 202,
            can_fail,
        },
        // Tuple types like (StatusCode, Json<T>)
        _ => ResponseInfo {
            body_type: Some(ty.clone()),
            status: 200,
            can_fail,
        },
    }
}
