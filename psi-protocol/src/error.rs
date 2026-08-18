//! Error types for the PSI protocol.

/// Errors that can occur during PSI protocol execution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PsiError {
    /// Blinded points received from the remote party were invalid.
    #[error("Invalid blinded points: {0}")]
    InvalidBlindedPoints(String),

    /// A cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// A protocol message had a different number of points than required.
    #[error("message length mismatch: expected {expected} points, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },

    /// A local or remote set exceeded [`crate::MAX_ITEMS`].
    #[error("set too large: {size} items exceeds maximum of {max}")]
    SetTooLarge { size: usize, max: usize },
}

/// Result type for PSI operations.
pub type Result<T> = std::result::Result<T, PsiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", PsiError::InvalidBlindedPoints("test".to_string())),
            "Invalid blinded points: test"
        );
        assert_eq!(
            format!("{}", PsiError::CryptoError("test".to_string())),
            "Cryptographic error: test"
        );
        assert_eq!(
            format!(
                "{}",
                PsiError::LengthMismatch {
                    expected: 3,
                    actual: 1
                }
            ),
            "message length mismatch: expected 3 points, got 1"
        );
        assert_eq!(
            format!("{}", PsiError::SetTooLarge { size: 10, max: 5 }),
            "set too large: 10 items exceeds maximum of 5"
        );
    }

    #[test]
    fn test_result_type() {
        let ok_result: Result<()> = Ok(());
        let err_result: Result<()> = Err(PsiError::CryptoError("x".to_string()));
        assert!(ok_result.is_ok());
        assert!(err_result.is_err());
    }
}
