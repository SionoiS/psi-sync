//! Internal phase of a [`crate::TopicSync`] session.

use crate::result::TopicDiff;
use psi::{DoubleBlindedState, PreparedState, PsiProtocol};
use reconciliation::{Reconcile, ReconcileResult, Running};

/// Which side opened the outer session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

/// In-flight per-topic reconciliation after PSI has finished.
pub(crate) struct Reconciling<'a> {
    pub role: Role,
    /// Sorted intersection hashes. Walked from `completed` onward.
    pub hashes: Vec<[u8; 32]>,
    /// Number of topics whose diffs have been recorded.
    pub completed: usize,
    /// Inner LIP-182 session for `hashes[completed]`, if started.
    pub inner: Option<Reconcile<'a, Running>>,
    pub diffs: Vec<TopicDiff>,
}

impl Reconciling<'_> {
    pub(crate) fn record(&mut self, result: ReconcileResult) {
        let hash = self.hashes[self.completed];
        self.diffs.push(TopicDiff {
            topic_hash: hash,
            to_send: result.to_send,
            to_recv: result.to_recv,
        });
        self.completed += 1;
        self.inner = None;
    }

    pub(crate) fn current_hash(&self) -> Option<[u8; 32]> {
        self.hashes.get(self.completed).copied()
    }
}

/// Private type-state of the outer session.
pub(crate) enum Phase<'a> {
    /// Initiator has sent [`crate::SyncMessage::PsiBlinded`].
    InitiatorPsi(PsiProtocol<PreparedState>),
    /// Responder is waiting for the initiator's blinded points.
    ResponderPsi(PsiProtocol<PreparedState>),
    /// Responder has sent [`crate::SyncMessage::PsiOffer`].
    ResponderPsiMid(PsiProtocol<DoubleBlindedState>),
    /// Shared topics are being reconciled sequentially.
    Reconciling(Reconciling<'a>),
}
