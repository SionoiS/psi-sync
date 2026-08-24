//! Type-state markers for [`crate::Reconcile`].

/// Marker trait implemented by protocol states.
///
/// Public so callers can name `Reconcile<'s, S: ReconcileState>`.
pub trait ReconcileState {}

/// In-progress session: `step` is available.
pub struct Running {
    pub(crate) rounds: usize,
}

impl Running {
    pub(crate) fn new() -> Self {
        Self { rounds: 0 }
    }
}

impl ReconcileState for Running {}
