//! Mock PCD error types.

use core::{error, fmt};

/// An error from mock PCD operations.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// Proof binding hash is inconsistent with its components.
    BindingInvalid,
    /// Header hash in proof does not match the provided header data.
    HeaderMismatch,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::BindingInvalid => f.write_str("proof binding is invalid"),
            | Self::HeaderMismatch => f.write_str("header does not match proof"),
        }
    }
}

impl error::Error for ValidationError {}
