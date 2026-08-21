//! Internal phase of a [`crate::TopicSync`] session.

use crate::result::TopicDiff;
use psi::{DoubleBlindedState, PreparedState, PsiProtocol};
use reconciliation::{Reconcile, ReconcileResult, Running};
use std::collections::HashMap;

/// In-flight per-topic reconciliation after PSI has finished.
pub(crate) struct Reconciling<'a> {
    /// Sorted intersection hashes. Result order, and the expected complete set.
    pub hashes: Vec<[u8; 32]>,
    /// Inner LIP-182 session per still-active topic.
    pub inner: HashMap<[u8; 32], Reconcile<'a, Running>>,
    pub diffs: Vec<TopicDiff>,
}

impl Reconciling<'_> {
    pub(crate) fn record(&mut self, hash: [u8; 32], result: ReconcileResult) {
        self.diffs.push(TopicDiff {
            topic_hash: hash,
            to_send: result.to_send,
            to_recv: result.to_recv,
        });
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
    /// Shared topics are being reconciled in parallel.
    Reconciling(Reconciling<'a>),
}
