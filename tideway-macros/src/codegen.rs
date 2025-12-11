//! Code generation for utoipa OpenAPI attributes.
//!
//! This module generates `#[utoipa::path(...)]` attributes based on
//! parsed arguments and inferred types.

use proc_macro2::{TokenStream, Literal};
use quote::{quote, format_ident};
use syn::ItemFn;

use crate::inference::InferenceResult;
use crate::parse::{ApiArgs, HttpMethod, convert_path_to_openapi, extract_path_params};

/// Generate the complete output for the API macro.
pub fn generate_api_macro(args: &ApiArgs, func: &ItemFn, inference: &InferenceResult) -> TokenStream {
    // If skip_openapi is set, just return the original function
    if args.skip_openapi {
        return quote! { #func };
    }

    // Generate the utoipa::path attribute
    let utoipa_attr = generate_utoipa_path(args, func, inference);

    // Combine the utoipa attribute with the original function
    // Use cfg_attr to conditionally apply when openapi feature is enabled
    let func_attrs = &func.attrs;
    let func_vis = &func.vis;
    let func_sig = &func.sig;
    let func_block = &func.block;

    quote! {
        #[cfg_attr(feature = "openapi", #utoipa_attr)]
        #(#func_attrs)*
        #func_vis #func_sig #func_block
    }
}

/// Generate the `utoipa::path(...)` attribute.
fn generate_utoipa_path(args: &ApiArgs, func: &ItemFn, inference: &InferenceResult) -> TokenStream {
    let method = generate_method(args.method);
    let path = convert_path_to_openapi(&args.path);
    let path_params_from_route = extract_path_params(&args.path);

    // Tag - use explicit, or default to "default"
    let tag = args.tag.as_deref().unwrap_or("default");

    // Operation ID - use explicit, or function name
    let operation_id = args.operation_id
        .clone()
        .unwrap_or_else(|| func.sig.ident.to_string());

    // Summary/description from explicit args or doc comments
    let inferred_summary: Option<String> = inference.doc_comment.as_ref().map(|s| {
        // Use first line as summary
        s.lines().next().unwrap_or(s).to_string()
    });
    let summary = args.summary.as_ref().or(inferred_summary.as_ref());

    let description = args.description.as_ref()
        .or(inference.doc_comment.as_ref());

    // Generate params
    let params = generate_params(args, inference, &path_params_from_route);

    // Generate request body
    let request_body = generate_request_body(args, inference);

    // Generate responses
    let responses = generate_responses(args, inference);

    // Generate security
    let security = generate_security(args, inference);

    // Generate deprecated flag
    let deprecated = if args.deprecated {
        quote! { deprecated = true, }
    } else {
        quote! {}
    };

    // Build tags list
    let tags = if args.internal {
        quote! { tag = #tag, tag = "internal", }
    } else {
        quote! { tag = #tag, }
    };

    // Build summary/description if present
    let summary_attr = summary.map(|s| quote! { summary = #s, }).unwrap_or_default();
    let description_attr = description.map(|d| quote! { description = #d, }).unwrap_or_default();

    quote! {
        utoipa::path(
            #method,
            path = #path,
            operation_id = #operation_id,
            #tags
            #summary_attr
            #description_attr
            #deprecated
            #params
            #request_body
            #responses
            #security
        )
    }
}

/// Generate the HTTP method token.
fn generate_method(method: HttpMethod) -> TokenStream {
    let method_ident = format_ident!("{}", method.as_str());
    quote! { #method_ident }
}

/// Generate the params section.
fn generate_params(
    _args: &ApiArgs,
    inference: &InferenceResult,
    path_params_from_route: &[String],
) -> TokenStream {
    let mut param_tokens = Vec::new();

    // Generate path parameters from the route
    for param_name in path_params_from_route {
        // Try to find a matching type from inference
        let param_type = inference.path_params.first()
            .and_then(|p| p.ty.as_ref())
            .map(|ty| quote! { #ty })
            .unwrap_or_else(|| quote! { String });

        param_tokens.push(quote! {
            (#param_name = #param_type, Path, description = "")
        });
    }

    // Add query parameters if present
    if let Some(query_info) = &inference.query_params {
        let query_type = &query_info.ty;
        // For query params, we reference the type which should implement IntoParams
        param_tokens.push(quote! {
            #query_type
        });
    }

    if param_tokens.is_empty() {
        quote! {}
    } else {
        quote! {
            params(#(#param_tokens),*),
        }
    }
}

/// Generate the request_body section.
fn generate_request_body(args: &ApiArgs, inference: &InferenceResult) -> TokenStream {
    // Use explicit request_body if provided
    if let Some(explicit_type) = &args.request_body {
        return quote! {
            request_body = #explicit_type,
        };
    }

    // Otherwise use inferred type
    if let Some(body_info) = &inference.request_body {
        let body_type = &body_info.ty;
        let content_type = body_info.content_type.as_str();

        // For JSON, we can use the simple form
        if content_type == "application/json" {
            return quote! {
                request_body = #body_type,
            };
        }

        // For other content types, use the expanded form
        return quote! {
            request_body(content = #body_type, content_type = #content_type),
        };
    }

    quote! {}
}

/// Generate the responses section.
fn generate_responses(args: &ApiArgs, inference: &InferenceResult) -> TokenStream {
    let mut response_tokens = Vec::new();

    // Start with explicit responses from args
    for resp in &args.responses {
        let status = Literal::u16_unsuffixed(resp.status);
        let description = &resp.description;

        if let Some(body) = &resp.body {
            response_tokens.push(quote! {
                (status = #status, description = #description, body = #body)
            });
        } else {
            response_tokens.push(quote! {
                (status = #status, description = #description)
            });
        }
    }

    // Add success response from explicit override or inference
    let success_response = if let Some(explicit_type) = &args.response {
        let status = Literal::u16_unsuffixed(inference.response.status);
        quote! {
            (status = #status, description = "Success", body = #explicit_type)
        }
    } else if let Some(body_type) = &inference.response.body_type {
        let status = Literal::u16_unsuffixed(inference.response.status);
        quote! {
            (status = #status, description = "Success", body = #body_type)
        }
    } else {
        let status = Literal::u16_unsuffixed(inference.response.status);
        quote! {
            (status = #status, description = "Success")
        }
    };

    // Only add success response if not already defined in explicit responses
    let has_success_status = args.responses.iter()
        .any(|r| r.status == inference.response.status);

    if !has_success_status {
        response_tokens.insert(0, success_response);
    }

    // Add error responses if the handler can fail
    if inference.response.can_fail {
        // Check which error responses are already defined
        let defined_statuses: Vec<u16> = args.responses.iter().map(|r| r.status).collect();

        // Add default error responses
        let default_errors: [(u16, &str); 4] = [
            (400, "Bad request"),
            (401, "Unauthorized"),
            (404, "Not found"),
            (500, "Internal server error"),
        ];

        for (status, description) in default_errors {
            if !defined_statuses.contains(&status) {
                let status_lit = Literal::u16_unsuffixed(status);
                response_tokens.push(quote! {
                    (status = #status_lit, description = #description, body = tideway::ErrorResponse)
                });
            }
        }
    }

    if response_tokens.is_empty() {
        quote! {}
    } else {
        quote! {
            responses(#(#response_tokens),*),
        }
    }
}

/// Generate the security section.
fn generate_security(args: &ApiArgs, inference: &InferenceResult) -> TokenStream {
    // Check for explicit security override
    if let Some(security) = &args.security {
        if security == "none" {
            return quote! {};
        }
        // Use string literal for security scheme name
        return quote! {
            security(
                (#security = [])
            ),
        };
    }

    // Use inferred security
    if let Some(sec_info) = &inference.security {
        if sec_info.required {
            let scheme = &sec_info.scheme;
            return quote! {
                security(
                    (#scheme = [])
                ),
            };
        }
    }

    quote! {}
}
