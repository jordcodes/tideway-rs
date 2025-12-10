//! WebSocket message types
//!
//! This module provides wrappers around Axum's WebSocket message types
//! for a cleaner API surface.

use serde::{Deserialize, Serialize};

/// WebSocket message types
#[derive(Debug, Clone)]
pub enum Message {
    /// Text message
    Text(String),
    /// Binary message
    Binary(Vec<u8>),
    /// Ping frame
    Ping(Vec<u8>),
    /// Pong frame
    Pong(Vec<u8>),
    /// Close frame
    Close(Option<CloseFrame>),
}

impl Message {
    /// Convert from Axum's WebSocket message
    pub fn from_axum(msg: axum::extract::ws::Message) -> Self {
        match msg {
            axum::extract::ws::Message::Text(text) => Message::Text(text.to_string()),
            axum::extract::ws::Message::Binary(data) => Message::Binary(data.to_vec()),
            axum::extract::ws::Message::Ping(data) => Message::Ping(data.to_vec()),
            axum::extract::ws::Message::Pong(data) => Message::Pong(data.to_vec()),
            axum::extract::ws::Message::Close(close_frame) => {
                Message::Close(close_frame.map(|f| CloseFrame {
                    code: f.code.into(),
                    reason: f.reason.to_string(),
                }))
            }
        }
    }

    /// Convert to Axum's WebSocket message
    pub fn into_axum(self) -> axum::extract::ws::Message {
        match self {
            Message::Text(text) => axum::extract::ws::Message::Text(axum::extract::ws::Utf8Bytes::from(text.as_str())),
            Message::Binary(data) => axum::extract::ws::Message::Binary(axum::body::Bytes::from(data)),
            Message::Ping(data) => axum::extract::ws::Message::Ping(axum::body::Bytes::from(data)),
            Message::Pong(data) => axum::extract::ws::Message::Pong(axum::body::Bytes::from(data)),
            Message::Close(close_frame) => {
                axum::extract::ws::Message::Close(close_frame.map(|f| {
                    // Convert close code - CloseCode is a newtype wrapper around u16
                    use axum::extract::ws::CloseCode;
                    let code = CloseCode::from(f.code);
                    axum::extract::ws::CloseFrame {
                        code,
                        reason: axum::extract::ws::Utf8Bytes::from(f.reason.as_str()),
                    }
                }))
            }
        }
    }
}

/// WebSocket close frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseFrame {
    /// Close code
    pub code: u16,
    /// Close reason
    pub reason: String,
}
