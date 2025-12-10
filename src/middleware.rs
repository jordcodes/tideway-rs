use tower_http::request_id::{MakeRequestId, RequestId};
use uuid::Uuid;

/// Middleware for adding request ID to all requests
#[derive(Clone, Default)]
pub struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        let request_id = Uuid::new_v4().to_string().parse().ok()?;
        Some(RequestId::new(request_id))
    }
}
