//! Session storage trait
//!
//! This trait abstracts session management, allowing users to swap between
//! cookie-based, database-backed, or custom implementations.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Session data stored in the session store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Session data as key-value pairs
    pub data: HashMap<String, String>,

    /// When the session was created
    pub created_at: SystemTime,

    /// When the session expires
    pub expires_at: SystemTime,
}

impl SessionData {
    /// Create a new session with expiration
    pub fn new(ttl: Duration) -> Self {
        let now = SystemTime::now();
        Self {
            data: HashMap::new(),
            created_at: now,
            expires_at: now + ttl,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Get a value from the session
    pub fn get(&self, key: &str) -> Option<&String> {
        self.data.get(key)
    }

    /// Set a value in the session
    pub fn set(&mut self, key: String, value: String) {
        self.data.insert(key, value);
    }

    /// Remove a value from the session
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.remove(key)
    }

    /// Extend the session expiration
    pub fn extend(&mut self, ttl: Duration) {
        self.expires_at = SystemTime::now() + ttl;
    }
}

/// Session storage trait
#[async_trait]
#[allow(async_fn_in_trait)] // async_trait macro handles Send/Sync bounds
pub trait SessionStore: Send + Sync {
    /// Load session data by session ID
    ///
    /// Returns `Ok(None)` if the session doesn't exist or has expired.
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>>;

    /// Save session data with a session ID
    async fn save(&self, session_id: &str, data: SessionData) -> Result<()>;

    /// Delete a session
    async fn delete(&self, session_id: &str) -> Result<()>;

    /// Clean up expired sessions
    ///
    /// This is typically called periodically by the application.
    async fn cleanup_expired(&self) -> Result<usize>;

    /// Check if the session store is healthy
    fn is_healthy(&self) -> bool;
}
