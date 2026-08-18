//! Errors for range-based set reconciliation.

/// Errors that can occur during reconciliation or codec operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReconcileError {
    /// A local store or incoming set exceeded the configured maximum.
    #[error("set too large: {size} items exceeds maximum of {max}")]
    SetTooLarge { size: usize, max: usize },

    /// Range bounds were not strictly increasing (`a < b`).
    #[error("invalid range bounds: lower bound must be strictly less than upper bound")]
    InvalidBounds,

    /// A [`crate::Range`] had a `kind` that did not match its `content`.
    #[error("payload kind does not match content")]
    PayloadMismatch,

    /// LEB128 / delta decoding failed.
    #[error("codec error: {0}")]
    CodecError(String),

    /// The session exceeded [`crate::ReconcileConfig::max_rounds`].
    #[error("too many reconciliation rounds (max {max})")]
    TooManyRounds { max: usize },

    /// [`crate::ReconcileConfig`] failed validation.
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
}

/// Result type for reconciliation operations.
pub type Result<T> = std::result::Result<T, ReconcileError>;
