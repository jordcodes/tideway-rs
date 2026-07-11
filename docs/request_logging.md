# Request Logging

Request logging is enabled by default, while header logging and body previews are disabled by
default. If body previews are enabled, Tideway only previews JSON, URL-encoded forms, and—when
redaction is explicitly disabled—plain text.

Structured previews redact common password, token, MFA, API-key, and payment fields recursively.
Unknown or binary content types are never logged. Authorization, cookie, and API-key headers are
also redacted when header logging is enabled.

```rust
use tideway::request_logging::RequestLoggingConfig;

let logging = RequestLoggingConfig::builder()
    .body_preview_size(4096)
    .body_preview_redaction(true)
    .exclude_path("/api/auth")
    .exclude_path("/api/billing/webhooks")
    .build();
```

Environment equivalents:

- `TIDEWAY_REQUEST_LOGGING_BODY_PREVIEW_SIZE`
- `TIDEWAY_REQUEST_LOGGING_BODY_PREVIEW_REDACTION`
- `TIDEWAY_REQUEST_LOGGING_SENSITIVE_BODY_FIELDS` (comma-separated fields added to secure defaults)
- `TIDEWAY_REQUEST_LOGGING_EXCLUDED_PATHS` (comma-separated path prefixes)

Disabling body redaction is an explicit unsafe option. Avoid it in production because request
bodies commonly contain credentials and personal data.
