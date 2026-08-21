//! Outer protocol messages. Transport- and codec-agnostic.

use psi::{BlindedPointsMessage, DoubleBlindedPointsMessage};
use reconciliation::ReconcileMessage;

/// One in-flight LIP-182 payload tagged by a PSI topic hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileFrame {
    /// [`psi::hash_bytes`] of the topic. Never the raw topic bytes.
    pub topic_hash: [u8; 32],
    /// Inner reconciliation message for this topic.
    pub body: ReconcileMessage,
}

impl ReconcileFrame {
    /// Construct a frame.
    pub fn new(topic_hash: [u8; 32], body: ReconcileMessage) -> Self {
        Self { topic_hash, body }
    }
}

/// One message of the composed protocol.
///
/// PSI is embedded as a three-message sequential flow so the outer session
/// can use the same turn-taking `step` loop as reconciliation. Shared-topic
/// identifiers on the wire are PSI hashes, never raw topic bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncMessage {
    /// Initiator → responder. Blinded points of the initiator's topic set.
    PsiBlinded(BlindedPointsMessage),

    /// Responder → initiator. The responder's blinded points plus the
    /// double-blind of the initiator's first message.
    PsiOffer {
        /// Responder's own blinded topic points.
        blinded: BlindedPointsMessage,
        /// Double-blind of the initiator's [`SyncMessage::PsiBlinded`].
        double_blinded: DoubleBlindedPointsMessage,
    },

    /// Initiator → responder. Double-blind of the responder, and the first
    /// reconcile fingerprint when the topic intersection is non-empty.
    PsiDone {
        /// Double-blind of the responder's blinded points.
        double_blinded: DoubleBlindedPointsMessage,
        /// First shared topic's opening fingerprint, if any.
        first_reconcile: Option<ReconcileFrame>,
    },

    /// In-flight LIP-182 payload for exactly one topic.
    Reconcile(ReconcileFrame),

    /// The tagged topic's inner session is finished (absorbs the LIP-182
    /// empty closer). `next` is the initiator's opening fingerprint for the
    /// following topic, if any.
    ///
    /// Only the initiator sends this variant.
    TopicComplete {
        /// Hash of the topic that just finished.
        topic_hash: [u8; 32],
        /// Opening frame of the next shared topic, or `None` if this was last.
        next: Option<ReconcileFrame>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_new() {
        let hash = [7u8; 32];
        let frame = ReconcileFrame::new(hash, ReconcileMessage::empty());
        assert_eq!(frame.topic_hash, hash);
        assert!(frame.body.is_empty());
    }
}
