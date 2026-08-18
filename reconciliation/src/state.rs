//! Type-state markers for [`crate::Reconcile`].

use crate::id::SyncId;
use std::collections::BTreeSet;

/// Marker trait implemented by protocol states.
///
/// Public so callers can name `Reconcile<'s, S: ReconcileState>`.
pub trait ReconcileState {}

/// In-progress session: `step` is available.
pub struct Running {
    pub(crate) to_send: BTreeSet<SyncId>,
    pub(crate) to_recv: BTreeSet<SyncId>,
    pub(crate) rounds: usize,
}

impl Running {
    pub(crate) fn new() -> Self {
        Self {
            to_send: BTreeSet::new(),
            to_recv: BTreeSet::new(),
            rounds: 0,
        }
    }
}

impl ReconcileState for Running {}
