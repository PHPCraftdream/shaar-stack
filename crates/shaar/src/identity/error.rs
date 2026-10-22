//! Manual error type for the identity module.
//!
//! `thiserror` is not available; `Display` and `std::error::Error` are
//! implemented by hand. No variant ever carries or renders secret bytes:
//! `Io` stores the OS error (its text may contain the path, never file
//! contents read by this module) and the rest are pure markers.

use std::fmt;

/// Errors produced by identity creation and loading.
#[derive(Debug)]
pub enum IdentityError {
    /// The key file already exists; it was never overwritten.
    AlreadyExists,
    /// Underlying filesystem failure (permission denied, not found, ...).
    /// The OS error is preserved; its message never contains seed bytes.
    Io(std::io::Error),
    /// The existing file does not match the 32-raw-byte key file format
    /// (too short, too long, or trailing data).
    InvalidFormat,
    /// The existing file's permissions allow group or other access.
    /// The file is rejected, never chmod-fixed or overwritten.
    InsecurePermissions,
    /// The existing path is not a regular file (directory, symlink target
    /// of a non-regular type, device, ...).
    NotARegularFile,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "identity key file already exists"),
            Self::Io(e) => write!(f, "identity key file I/O error: {e}"),
            Self::InvalidFormat => {
                write!(f, "identity key file must be exactly 32 raw bytes")
            }
            Self::InsecurePermissions => {
                write!(f, "identity key file permissions are too broad")
            }
            Self::NotARegularFile => write!(f, "identity key path is not a regular file"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
