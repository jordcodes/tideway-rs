use tideway::prelude::*;

#[test]
fn prelude_core_items_are_usable() {
    let _config = ConfigBuilder::new().build().expect("valid default config");
    let _app = App::new();
}

#[cfg(feature = "database")]
mod database {
    #![deny(ambiguous_glob_imports)]

    use sea_orm::*;
    use tideway::prelude::*;

    #[test]
    fn prelude_and_sea_orm_glob_imports_coexist() {
        let connection: DatabaseConnection = DatabaseConnection::Disconnected;
        assert!(matches!(connection, DatabaseConnection::Disconnected));
        let _pool: Option<SeaOrmPool> = None;
    }

    #[test]
    fn prelude_connection_trait_alias_preserves_original_trait() {
        struct ConnectionHandle;

        impl DatabaseConnectionTrait for ConnectionHandle {
            fn is_valid(&self) -> bool {
                true
            }
        }

        let connection: Box<dyn tideway::DatabaseConnection> = Box::new(ConnectionHandle);
        let connection: Box<dyn DatabaseConnectionTrait> = connection;
        assert!(connection.is_valid());
    }
}
