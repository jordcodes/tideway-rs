/// Return early with a TidewayError if a condition is not met.
///
/// # Example
/// ```ignore
/// tideway::ensure!(amount > 0, TidewayError::bad_request("Amount must be positive"));
/// tideway::ensure!(user_id > 0, "Invalid user id");
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($crate::TidewayError::bad_request($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err.into());
        }
    };
}
