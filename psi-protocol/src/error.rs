//! Error types for the PSI protocol.

use std::fmt;

/// Errors that can occur during PSI protocol execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsiError {
    /// Input data was empty.
    EmptyInput,

    /// Blinded points received from remote were invalid.
    InvalidBlindedPoints(String),

    /// A cryptographic operation failed.
    CryptoError(String),
}

impl fmt::Display for PsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PsiError::EmptyInput => write!(f, "Input data cannot be empty"),
            PsiError::InvalidBlindedPoints(msg) => {
                write!(f, "Invalid blinded points: {}", msg)
            }
            PsiError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
        }
    }
}

impl std::error::Error for PsiError {}

/// Result type for PSI operations.
pub type Result<T> = std::result::Result<T, PsiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", PsiError::EmptyInput),
            "Input data cannot be empty"
        );
        assert_eq!(
            format!("{}", PsiError::InvalidBlindedPoints("test".to_string())),
            "Invalid blinded points: test"
        );
        assert_eq!(
            format!("{}", PsiError::CryptoError("test".to_string())),
            "Cryptographic error: test"
        );
    }

    #[test]
    fn test_result_type() {
        let ok_result: Result<()> = Ok(());
        let err_result: Result<()> = Err(PsiError::EmptyInput);
        assert!(ok_result.is_ok());
        assert!(err_result.is_err());
    }
}
