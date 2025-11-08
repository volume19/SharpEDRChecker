//! Error types for SharpEDRChecker
//!
//! Each module has its own error type, with automatic conversion to the top-level
//! `CheckerError` type for unified error handling.

use std::io;

/// Top-level error type for all checker operations
#[derive(Debug, thiserror::Error)]
pub enum CheckerError {
    /// File information extraction error
    #[error("File check failed: {0}")]
    File(#[from] FileError),

    /// Directory enumeration error
    #[error("Directory check failed: {0}")]
    Directory(#[from] DirectoryError),

    /// Process enumeration error
    #[error("Process check failed: {0}")]
    Process(#[from] ProcessError),

    /// Service enumeration error
    #[error("Service check failed: {0}")]
    Service(#[from] ServiceError),

    /// Driver enumeration error
    #[error("Driver check failed: {0}")]
    Driver(#[from] DriverError),

    /// Privilege check error
    #[error("Privilege check failed: {0}")]
    Privilege(#[from] PrivilegeError),

    /// Registry check error
    #[error("Registry check failed: {0}")]
    Registry(#[from] RegistryError),

    /// Operation not supported on this platform
    #[error("Operation not supported on this platform")]
    NotSupported,
}

/// Errors from file information extraction
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// File not found at the specified path
    #[error("File not found: {path}")]
    NotFound {
        /// The path that was not found
        path: String,
    },

    /// Invalid file path provided
    #[error("Invalid path: {path}")]
    InvalidPath {
        /// The invalid path
        path: String,
    },

    /// IO error during file operations
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Failed to parse PE file version info
    #[error("Failed to parse version info: {0}")]
    ParseError(String),

    /// Windows API error
    #[error("Windows API error: {0}")]
    WindowsApi(String),
}

/// Errors from directory enumeration
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    /// IO error during directory operations
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Access denied to directory
    #[error("Access denied: {path}")]
    AccessDenied {
        /// The path that was denied
        path: String,
    },
}

/// Errors from process enumeration
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// WMI query failed
    #[error("WMI query failed: {0}")]
    WmiError(String),

    /// Failed to enumerate process modules
    #[error("Failed to enumerate modules: {0}")]
    ModuleEnumeration(String),

    /// Windows API error
    #[error("Windows API error: {0}")]
    WindowsApi(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Errors from service enumeration
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// WMI query failed
    #[error("WMI query failed: {0}")]
    WmiError(String),

    /// Windows API error
    #[error("Windows API error: {0}")]
    WindowsApi(String),
}

/// Errors from driver enumeration
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Failed to enumerate device drivers
    #[error("Failed to enumerate drivers: {0}")]
    EnumerationFailed(String),

    /// Windows API error with Win32 error code
    #[error("Windows API error (code {code}): {message}")]
    WindowsApi {
        /// Win32 error code
        code: u32,
        /// Error message
        message: String,
    },

    /// Buffer size error
    #[error("Buffer size mismatch")]
    BufferError,
}

/// Errors from privilege checking
#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    /// Failed to get current process token
    #[error("Failed to get process token: {0}")]
    TokenError(String),

    /// Failed to query token information
    #[error("Failed to query token: {0}")]
    QueryError(String),

    /// Windows API error with Win32 error code
    #[error("Windows API error (code {code}): {message}")]
    WindowsApi {
        /// Win32 error code
        code: u32,
        /// Error message
        message: String,
    },
}

/// Errors from registry operations
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Not yet implemented
    #[error("Registry checking not yet implemented")]
    NotImplemented,

    /// Windows API error
    #[error("Windows API error: {0}")]
    WindowsApi(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let file_err = FileError::NotFound {
            path: "test.dll".to_string(),
        };
        assert_eq!(file_err.to_string(), "File not found: test.dll");

        let checker_err = CheckerError::File(file_err);
        assert!(checker_err.to_string().contains("File not found"));
    }

    #[test]
    fn test_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "test");
        let file_err: FileError = io_err.into();
        let checker_err: CheckerError = file_err.into();

        assert!(matches!(checker_err, CheckerError::File(_)));
    }

    #[test]
    fn test_not_supported_error() {
        let err = CheckerError::NotSupported;
        assert_eq!(
            err.to_string(),
            "Operation not supported on this platform"
        );
    }
}
