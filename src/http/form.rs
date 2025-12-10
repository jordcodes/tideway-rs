//! Form data extractors and helpers
//!
//! This module provides utilities for extracting and validating form data,
//! including multipart form data for file uploads.

use axum::extract::Form as AxumForm;

/// Form data extractor
///
/// This is a thin wrapper around Axum's `Form` extractor.
pub type Form<T> = AxumForm<T>;

/// Multipart form data extractor for file uploads
///
/// This is a thin wrapper around Axum's `Multipart` extractor.
/// Multipart support is enabled by default in Tideway's Axum dependency.
pub type Multipart = axum::extract::Multipart;

/// File upload configuration
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// Maximum file size in bytes
    pub max_size: usize,

    /// Allowed MIME types
    pub allowed_types: Vec<String>,

    /// Allowed file extensions
    pub allowed_extensions: Vec<String>,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            max_size: 10 * 1024 * 1024, // 10MB default
            allowed_types: vec![],
            allowed_extensions: vec![],
        }
    }
}

impl FileConfig {
    /// Create a new file config with size limit
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            max_size,
            ..Default::default()
        }
    }

    /// Add allowed MIME type
    pub fn allow_type(mut self, mime_type: impl Into<String>) -> Self {
        self.allowed_types.push(mime_type.into());
        self
    }

    /// Add allowed file extension
    pub fn allow_extension(mut self, ext: impl Into<String>) -> Self {
        self.allowed_extensions.push(ext.into());
        self
    }

    /// Validate file size
    pub fn validate_size(&self, size: usize) -> Result<(), String> {
        if size > self.max_size {
            return Err(format!("File size {} exceeds maximum {}", size, self.max_size));
        }
        Ok(())
    }

    /// Validate MIME type
    pub fn validate_type(&self, mime_type: &str) -> Result<(), String> {
        if !self.allowed_types.is_empty() && !self.allowed_types.contains(&mime_type.to_string()) {
            return Err(format!("MIME type {} not allowed", mime_type));
        }
        Ok(())
    }

    /// Validate file extension
    pub fn validate_extension(&self, filename: &str) -> Result<(), String> {
        if !self.allowed_extensions.is_empty() {
            if let Some(ext) = filename.split('.').last() {
                if !self.allowed_extensions.contains(&ext.to_lowercase()) {
                    return Err(format!("File extension .{} not allowed", ext));
                }
            } else {
                return Err("File has no extension".to_string());
            }
        }
        Ok(())
    }
}
