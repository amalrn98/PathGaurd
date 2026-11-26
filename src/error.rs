//! Error types shared across the crate.

use thiserror::Error;

/// Library error type.
#[derive(Debug, Error)]
pub enum Error {
    /// A wire message could not be parsed.
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    /// A field or message exceeded its size limit.
    #[error("message too large")]
    TooLarge,
    /// Authentication (signature or MAC) failed.
    #[error("authentication failed: {0}")]
    Auth(&'static str),
    /// A cryptographic operation failed.
    #[error("cryptographic failure: {0}")]
    Crypto(&'static str),
    /// The policy is invalid.
    #[error("invalid policy: {0}")]
    Policy(String),
}

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;
