//! Internal utilities for the organizations module.

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp in seconds.
#[inline]
pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
