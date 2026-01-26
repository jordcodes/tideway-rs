use std::sync::Arc;

use tideway::AppContext;

struct TestAuthProvider;

#[test]
fn test_with_optional_auth_provider_none() {
    let ctx = AppContext::builder()
        .with_optional_auth_provider::<TestAuthProvider>(None)
        .build();

    assert!(ctx.auth_provider_opt::<TestAuthProvider>().is_none());
}

#[test]
fn test_with_optional_auth_provider_some() {
    let provider = Arc::new(TestAuthProvider);
    let ctx = AppContext::builder()
        .with_optional_auth_provider(Some(provider))
        .build();

    assert!(ctx.auth_provider_opt::<TestAuthProvider>().is_some());
}

#[cfg(feature = "jobs")]
#[tokio::test]
async fn test_with_optional_job_queue() {
    let queue = Arc::new(tideway::InMemoryJobQueue::new(1, 1));
    let ctx = AppContext::builder()
        .with_optional_job_queue(Some(queue))
        .build();

    assert!(ctx.jobs_opt().is_some());

    let ctx = AppContext::builder().with_optional_job_queue(None).build();
    assert!(ctx.jobs_opt().is_none());
}

#[cfg(feature = "database")]
mod database_tests {
    use super::*;
    use async_trait::async_trait;
    use tideway::traits::database::{DatabaseConnection, DatabasePool};

    struct DummyConnection;

    impl DatabaseConnection for DummyConnection {
        fn is_valid(&self) -> bool {
            true
        }
    }

    struct DummyPool;

    #[async_trait]
    impl DatabasePool for DummyPool {
        async fn connection(&self) -> tideway::Result<Box<dyn DatabaseConnection>> {
            Ok(Box::new(DummyConnection))
        }

        fn is_healthy(&self) -> bool {
            true
        }

        async fn close(self: Box<Self>) -> tideway::Result<()> {
            Ok(())
        }

        fn connection_url(&self) -> Option<&str> {
            None
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn test_with_optional_database() {
        let pool = Arc::new(DummyPool) as Arc<dyn DatabasePool>;
        let ctx = AppContext::builder()
            .with_optional_database(Some(pool))
            .build();
        assert!(ctx.database_opt().is_some());

        let ctx = AppContext::builder()
            .with_optional_database(None)
            .build();
        assert!(ctx.database_opt().is_none());
    }
}
