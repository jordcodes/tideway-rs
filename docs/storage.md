# File Storage

Tideway provides a `FileStorage` trait for avatars, organization logos, attachments, and
generated exports. It is a small layer over [`object_store`](https://docs.rs/object_store) with
presigned uploads, so clients upload directly to storage instead of streaming files through your
API.

| Backend | Constructor | Feature | Presigned URLs |
| --- | --- | --- | --- |
| Local filesystem | `LocalStorage::new(root, base_url, secret)` | `storage` | HMAC-signed, served by `LocalStorage::router()` |
| In-memory (tests) | `ObjectStorage::in_memory()` | `storage` | Not supported |
| AWS S3 / MinIO | `ObjectStorage::s3(S3Config)` / `ObjectStorage::s3_from_env()` | `storage-s3` | SigV4 |
| Cloudflare R2 | `ObjectStorage::r2(R2Config)` | `storage-s3` | SigV4 |

```toml
[dependencies]
tideway = { version = "0.9.0", features = ["storage"] }      # local + in-memory
# tideway = { version = "0.9.0", features = ["storage-s3"] } # adds S3 and R2
```

## Configure a backend

```rust,ignore
use std::sync::Arc;
use tideway::storage::{LocalStorage, ObjectStorage, R2Config};
use tideway::AppContext;

// Development / single node. Mount the router so that base_url points at it.
let local = LocalStorage::new("./uploads", "http://localhost:8000/files", std::env::var("STORAGE_SECRET")?)?;
let files_router = axum::Router::new().nest("/files", local.router());
let storage: Arc<dyn tideway::FileStorage> = Arc::new(local);

// Production on Cloudflare R2 (R2_ACCOUNT_ID, R2_BUCKET, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY).
let storage: Arc<dyn tideway::FileStorage> = Arc::new(ObjectStorage::r2(R2Config::from_env()?)?);

let ctx = AppContext::builder().with_storage(storage).build();
```

The local signing secret must be at least 32 bytes. `LocalStorage::router()` accepts uploads up to
25 MiB by default; change it with `.max_upload_bytes(n)`.

## Presigned uploads

`UploadPolicy` covers the common cases:

| Preset | Prefix | Max size | Allowed types |
| --- | --- | --- | --- |
| `UploadPolicy::avatar()` | `avatars/` | 5 MiB | PNG, JPEG, WebP, GIF |
| `UploadPolicy::logo()` | `logos/` | 5 MiB | PNG, JPEG, WebP, GIF |
| `UploadPolicy::attachment()` | `attachments/` | 25 MiB | Any |

Adjust them with `.prefix()`, `.max_bytes()`, `.allow_content_types()`, and `.expires_in()`.
SVG is excluded from the image presets because it can carry scripts.

The upload is a three-step flow:

```rust,ignore
use tideway::storage::UploadPolicy;

// 1. Client declares the file; the API validates it and returns a presigned PUT.
async fn start_avatar_upload(ctx: AppContext, body: StartUpload) -> tideway::Result<Json<PresignedRequest>> {
    let storage = ctx.storage()?;
    let upload = UploadPolicy::avatar()
        .prefix(format!("avatars/{}", user.id))
        .presign(storage.as_ref(), &body.filename, &body.content_type, body.size)
        .await?;
    Ok(Json(upload)) // { key, method: "PUT", url, headers, expires_in }
}

// 2. Client: fetch(upload.url, { method: "PUT", headers: upload.headers, body: file })

// 3. Client reports the key; the API verifies it before saving it on the user.
async fn finish_avatar_upload(ctx: AppContext, body: FinishUpload) -> tideway::Result<()> {
    let storage = ctx.storage()?;
    let object = UploadPolicy::avatar()
        .prefix(format!("avatars/{}", user.id))
        .confirm(storage.as_ref(), &body.key)
        .await?;
    users.set_avatar_key(user.id, &object.key).await?;
    Ok(())
}
```

The content type is always bound into the signature. `LocalStorage` also enforces the exact
length. S3-compatible services cannot bind a size limit into a presigned `PUT` (SigV4 does not sign
`Content-Length`), so step 3 is required: `confirm` checks that the key is under the policy prefix
and that the stored size is within limits, and deletes oversized objects. Scope the prefix per user
or organization so one tenant cannot confirm another's key.

## Exports and server-side files

```rust,ignore
use std::time::Duration;
use tideway::storage::object_key;

let key = object_key("exports", "users.csv")?;
storage.put(&key, csv.into(), Some("text/csv")).await?;
let download = storage.presign_download(&key, Duration::from_secs(60 * 60)).await?;
// Email or return download.url
```

`FileStorage` also provides `get`, `head`, `exists`, and `delete`. Deleting a missing key succeeds.

## Keys

Keys are `/`-separated paths of ASCII letters, digits, `-`, `_`, `.`, and `=`. Empty, `.` and `..`
segments are rejected, so keys cannot escape the storage root. Use `object_key(prefix, filename)`
to turn a user-supplied filename into a unique, safe key that keeps a sanitized extension.

Presigned URLs default to 15 minutes and are capped at 7 days.

## Serving local files

`LocalStorage::router()` serves downloads with `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: sandbox`. It only sends a specific `Content-Type` for inert formats
(images, PDF, CSV, text, JSON); everything else is served as `application/octet-stream`.

## Testing

Use `ObjectStorage::in_memory()` for handlers that only read and write files. Use a `LocalStorage`
in a temporary directory to exercise the full presigned upload flow in-process, as
`tests/it/storage_test.rs` does.

## Custom backends

Wrap any `object_store` backend with `ObjectStorage::new(Arc::new(store))`, or with
`ObjectStorage::with_signer` if it implements `object_store::signer::Signer` (requires
`storage-s3`). For anything else, implement `FileStorage` directly.
