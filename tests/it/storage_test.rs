//! Tests for file storage and presigned uploads

#[cfg(feature = "storage")]
mod storage_tests {
    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::http::{Request, StatusCode};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tideway::storage::{
        FileStorage, LocalStorage, ObjectStorage, PresignOptions, PresignedRequest, UploadPolicy,
        object_key,
    };
    use tideway::{AppContext, TidewayError};
    use tower::ServiceExt;

    const SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";
    const BASE_URL: &str = "http://localhost:8000/files";

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("tideway-storage-{}", uuid::Uuid::new_v4())))
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn local(root: &TempRoot) -> (LocalStorage, Router) {
        let storage = LocalStorage::new(&root.0, BASE_URL, SECRET).unwrap();
        let router = Router::new().nest("/files", storage.router());
        (storage, router)
    }

    /// Turn a presigned URL into a request path the in-process router understands.
    fn request_path(presigned: &PresignedRequest) -> String {
        presigned
            .url
            .strip_prefix("http://localhost:8000")
            .unwrap()
            .to_string()
    }

    fn put_request(presigned: &PresignedRequest, body: impl Into<Body>) -> Request<Body> {
        let mut builder = Request::put(request_path(presigned));
        for (name, value) in &presigned.headers {
            builder = builder.header(name, value);
        }
        builder.body(body.into()).unwrap()
    }

    async fn send(
        router: &Router,
        request: Request<Body>,
    ) -> (StatusCode, Bytes, axum::http::HeaderMap) {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body, headers)
    }

    #[tokio::test]
    async fn local_presigned_upload_and_download_round_trip() {
        let root = TempRoot::new();
        let (storage, router) = local(&root);
        let png = Bytes::from_static(b"\x89PNG\r\n\x1a\nfake-image");

        let upload = UploadPolicy::avatar()
            .presign(&storage, "Me.PNG", "image/png", png.len() as u64)
            .await
            .unwrap();
        assert_eq!(upload.method, "PUT");
        assert!(upload.key.starts_with("avatars/") && upload.key.ends_with(".png"));
        assert_eq!(upload.headers["content-type"], "image/png");
        assert_eq!(upload.headers["content-length"], png.len().to_string());
        assert_eq!(upload.expires_in, 15 * 60);

        let (status, _, _) = send(&router, put_request(&upload, png.clone())).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(storage.get(&upload.key).await.unwrap(), png);
        let meta = storage.head(&upload.key).await.unwrap().unwrap();
        assert_eq!(meta.size, png.len() as u64);
        assert!(root.0.join(&upload.key).is_file());

        let download = storage
            .presign_download(&upload.key, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(download.method, "GET");
        let (status, body, headers) = send(
            &router,
            Request::get(request_path(&download))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, png);
        assert_eq!(headers["content-type"], "image/png");
        assert_eq!(headers["x-content-type-options"], "nosniff");
    }

    #[tokio::test]
    async fn local_router_rejects_tampered_or_mismatched_uploads() {
        let root = TempRoot::new();
        let (storage, router) = local(&root);
        let key = object_key("attachments", "doc.pdf").unwrap();
        let upload = storage
            .presign_upload(
                &key,
                PresignOptions::new()
                    .content_type("application/pdf")
                    .content_length(4),
            )
            .await
            .unwrap();

        // Signature tampered.
        let mut tampered = upload.clone();
        tampered.url = tampered.url.replace("sig=", "sig=x");
        let (status, _, _) = send(&router, put_request(&tampered, "%PDF")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Key swapped for another one under the same signature.
        let mut other_key = upload.clone();
        other_key.url = other_key.url.replace(&key, "attachments/other.pdf");
        let (status, _, _) = send(&router, put_request(&other_key, "%PDF")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Signed size loosened in the query string.
        let mut bigger = upload.clone();
        bigger.url = bigger.url.replace("len=4", "len=4000");
        let (status, _, _) = send(&router, put_request(&bigger, "%PDF")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Different content type than signed.
        let request = Request::put(request_path(&upload))
            .header("content-type", "text/html")
            .body(Body::from("%PDF"))
            .unwrap();
        let (status, _, _) = send(&router, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Body larger than the signed length.
        let (status, _, _) = send(&router, put_request(&upload, "%PDF-1.7 and more")).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        // Body shorter than the signed length.
        let (status, _, _) = send(&router, put_request(&upload, "%P")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // An upload URL cannot be used to download.
        let (status, _, _) = send(
            &router,
            Request::get(request_path(&upload))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        assert!(!storage.exists(&key).await.unwrap());

        // The untouched request still works.
        let (status, _, _) = send(&router, put_request(&upload, "%PDF")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(storage.exists(&key).await.unwrap());
    }

    #[tokio::test]
    async fn local_router_rejects_expired_urls() {
        let root = TempRoot::new();
        let (storage, router) = local(&root);
        let upload = storage
            .presign_upload(
                "exports/report.csv",
                PresignOptions::new().expires_in(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;

        let (status, _, _) = send(&router, put_request(&upload, "a,b\n")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn local_router_enforces_max_upload_size_without_signed_length() {
        let root = TempRoot::new();
        let storage = LocalStorage::new(&root.0, BASE_URL, SECRET)
            .unwrap()
            .max_upload_bytes(8);
        let router = Router::new().nest("/files", storage.router());
        let upload = storage
            .presign_upload("attachments/big.bin", PresignOptions::new())
            .await
            .unwrap();

        let (status, _, _) = send(&router, put_request(&upload, vec![0u8; 9])).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _, _) = send(&router, put_request(&upload, vec![0u8; 8])).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn local_storage_rejects_weak_secrets_and_unsafe_keys() {
        let root = TempRoot::new();
        assert!(LocalStorage::new(&root.0, BASE_URL, "short").is_err());

        let (storage, _) = local(&root);
        for key in ["../escape.txt", "a/../../b", "/etc/passwd", "a b"] {
            let err = storage
                .put(key, Bytes::from_static(b"x"), None)
                .await
                .unwrap_err();
            assert!(matches!(err, TidewayError::BadRequest(_)), "{key}: {err:?}");
            assert!(
                storage
                    .presign_upload(key, PresignOptions::new())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn in_memory_backend_supports_server_side_exports() {
        let storage: Arc<dyn FileStorage> = Arc::new(ObjectStorage::in_memory());
        let ctx = AppContext::builder().with_storage(storage).build();
        let storage = ctx.storage().unwrap();

        let key = object_key("exports", "users.csv").unwrap();
        let stored = storage
            .put(&key, Bytes::from_static(b"id,email\n"), Some("text/csv"))
            .await
            .unwrap();
        assert_eq!(stored.size, 9);
        assert_eq!(storage.get(&key).await.unwrap(), "id,email\n");
        assert!(storage.exists(&key).await.unwrap());

        storage.delete(&key).await.unwrap();
        storage.delete(&key).await.unwrap();
        assert!(storage.head(&key).await.unwrap().is_none());
        assert!(matches!(
            storage.get(&key).await.unwrap_err(),
            TidewayError::NotFound(_)
        ));

        // In-memory has no signer, so presigning reports a clear error.
        let err = storage
            .presign_download(&key, Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not support presigned URLs"));
    }

    #[tokio::test]
    async fn upload_policy_confirm_rejects_oversized_and_foreign_keys() {
        let storage = ObjectStorage::in_memory();
        let policy = UploadPolicy::avatar().max_bytes(4);

        // Simulates a client that ignored the declared size (S3 cannot enforce it).
        let key = object_key("avatars", "me.png").unwrap();
        storage
            .put(&key, Bytes::from_static(b"too large"), Some("image/png"))
            .await
            .unwrap();
        assert!(matches!(
            policy.confirm(&storage, &key).await.unwrap_err(),
            TidewayError::BadRequest(_)
        ));
        assert!(
            !storage.exists(&key).await.unwrap(),
            "oversized upload is deleted"
        );

        storage
            .put(&key, Bytes::from_static(b"ok!"), Some("image/png"))
            .await
            .unwrap();
        assert_eq!(policy.confirm(&storage, &key).await.unwrap().size, 3);

        // Keys outside the policy prefix are rejected without touching them.
        let foreign = "attachments/secret.pdf";
        storage
            .put(foreign, Bytes::from_static(b"%PDF"), None)
            .await
            .unwrap();
        for bad in [foreign, "avatarsX/a.png"] {
            assert!(policy.confirm(&storage, bad).await.is_err(), "{bad}");
        }
        assert!(storage.exists(foreign).await.unwrap());

        assert!(matches!(
            policy
                .confirm(&storage, "avatars/missing.png")
                .await
                .unwrap_err(),
            TidewayError::NotFound(_)
        ));
    }

    #[test]
    fn default_policies_reject_browser_active_content_types() {
        for policy in [UploadPolicy::attachment(), UploadPolicy::new("files", 1024)] {
            for active in [
                "text/html",
                "text/html; charset=utf-8",
                "IMAGE/SVG+XML",
                "application/xhtml+xml",
                "text/javascript",
            ] {
                assert!(policy.validate(active, 10).is_err(), "{active}");
            }
            for inert in ["application/pdf", "text/plain", "image/png"] {
                assert!(policy.validate(inert, 10).is_ok(), "{inert}");
            }
        }
        // An explicit allowlist can still accept them.
        let html = UploadPolicy::new("pages", 1024).allow_content_types(["text/html"]);
        assert!(html.validate("text/html", 10).is_ok());
    }

    #[tokio::test]
    async fn upload_policy_finalize_moves_object_out_of_presigned_key() {
        let storage = ObjectStorage::in_memory();
        let policy = UploadPolicy::avatar().max_bytes(8);
        let upload_key = object_key("avatars", "me.png").unwrap();
        storage
            .put(&upload_key, Bytes::from_static(b"small"), Some("image/png"))
            .await
            .unwrap();

        let recorded = policy
            .finalize(&storage, &upload_key, "image/png")
            .await
            .unwrap();
        assert_ne!(recorded.key, upload_key);
        assert!(recorded.key.starts_with("avatars/") && recorded.key.ends_with(".png"));
        assert!(!storage.exists(&upload_key).await.unwrap());

        // Replaying the presigned URL with a larger body only rewrites the abandoned key.
        storage
            .put(&upload_key, Bytes::from(vec![0u8; 64]), Some("image/png"))
            .await
            .unwrap();
        let stored = storage.head(&recorded.key).await.unwrap().unwrap();
        assert_eq!(stored.size, 5);
        assert_eq!(storage.get(&recorded.key).await.unwrap(), "small");
    }

    #[test]
    fn storage_is_optional_on_app_context() {
        let ctx = AppContext::new();
        assert!(ctx.storage_opt().is_none());
        assert!(ctx.storage().is_err());
    }

    #[cfg(feature = "storage-s3")]
    #[tokio::test]
    async fn r2_presigned_upload_binds_type_and_length() {
        use tideway::storage::R2Config;

        let storage = ObjectStorage::r2(R2Config::new(
            "acct123",
            "uploads",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ))
        .unwrap();

        let upload = UploadPolicy::logo()
            .presign(&storage, "logo.webp", "image/webp", 2048)
            .await
            .unwrap();
        let url = url::Url::parse(&upload.url).unwrap();
        assert_eq!(url.host_str(), Some("acct123.r2.cloudflarestorage.com"));
        assert_eq!(url.path(), format!("/uploads/{}", upload.key));

        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["X-Amz-Expires"], "900");
        assert!(query["X-Amz-Credential"].contains("/auto/s3/aws4_request"));
        assert!(!query["X-Amz-Signature"].is_empty());
        let signed = &query["X-Amz-SignedHeaders"];
        assert!(signed.contains("content-type"), "{signed}");
        assert_eq!(upload.headers["content-type"], "image/webp");
        // SigV4 cannot bind Content-Length; size is verified by `UploadPolicy::confirm`.
        assert!(!upload.headers.contains_key("content-length"));

        let download = storage
            .presign_download(&upload.key, Duration::from_secs(60 * 60 * 24 * 30))
            .await
            .unwrap();
        assert_eq!(download.method, "GET");
        // Clamped to the SigV4 maximum of 7 days.
        assert_eq!(download.expires_in, 7 * 24 * 60 * 60);
    }
}
