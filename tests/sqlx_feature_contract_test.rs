#![cfg(feature = "database-sqlx")]
#![allow(deprecated)]

use tideway::database::sqlx_pool::{SqlxConnectionWrapper, SqlxPool};
use tideway::{DatabaseConnection, DatabasePool};

#[test]
fn database_sqlx_feature_exposes_database_contracts() {
    fn assert_pool<T: DatabasePool>() {}
    fn assert_connection<T: DatabaseConnection>() {}

    assert_pool::<SqlxPool>();
    assert_connection::<SqlxConnectionWrapper>();
}
