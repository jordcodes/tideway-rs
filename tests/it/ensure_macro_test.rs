use tideway::{TidewayError, ensure};

#[test]
fn test_ensure_macro_err_expr() {
    fn check(value: i32) -> Result<(), TidewayError> {
        ensure!(
            value > 0,
            TidewayError::bad_request("Value must be positive")
        );
        Ok(())
    }

    assert!(check(1).is_ok());
    assert!(check(0).is_err());
}

#[test]
fn test_ensure_macro_msg_literal() {
    fn check(value: i32) -> Result<(), TidewayError> {
        ensure!(value > 0, "Value must be positive");
        Ok(())
    }

    assert!(check(1).is_ok());
    assert!(check(-1).is_err());
}
