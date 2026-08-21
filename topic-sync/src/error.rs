//! Errors for the composed topic-sync session.

use psi::PsiError;
use reconciliation::ReconcileError;

/// Errors that can occur during a [`crate::TopicSync`] session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopicSyncError {
    /// A PSI sub-protocol failure.
    #[error(transparent)]
    Psi(#[from] PsiError),

    /// A reconciliation sub-protocol failure.
    #[error(transparent)]
    Reconcile(#[from] ReconcileError),

    /// A message arrived that is not valid in the current phase or role.
    #[error("unexpected message for the current session phase")]
    UnexpectedMessage,

    /// An intersection or framed topic hash has no local store.
    #[error("no local topic for hash")]
    UnknownTopic([u8; 32]),

    /// A framed topic hash did not match the topic currently in flight.
    #[error("topic hash mismatch")]
    TopicMismatch {
        /// Hash this side expected.
        expected: [u8; 32],
        /// Hash on the incoming frame.
        actual: [u8; 32],
    },

    /// The local topic set exceeds [`psi::MAX_ITEMS`].
    #[error("too many topics: {size} exceeds maximum of {max}")]
    TooManyTopics {
        /// Number of distinct topics that would be stored.
        size: usize,
        /// Maximum distinct topics.
        max: usize,
    },
}

/// Result type for topic-sync operations.
pub type Result<T> = std::result::Result<T, TopicSyncError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_unexpected() {
        assert_eq!(
            TopicSyncError::UnexpectedMessage.to_string(),
            "unexpected message for the current session phase"
        );
    }

    #[test]
    fn from_psi_and_reconcile() {
        let psi: TopicSyncError = PsiError::SetTooLarge { size: 2, max: 1 }.into();
        assert!(matches!(psi, TopicSyncError::Psi(_)));
        let rec: TopicSyncError = ReconcileError::InvalidBounds.into();
        assert!(matches!(rec, TopicSyncError::Reconcile(_)));
    }
}
