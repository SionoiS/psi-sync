//! Type-state reconciliation session.

use crate::error::{ReconcileError, Result};
use crate::id::SyncId;
use crate::process::process_payload;
use crate::range::{Range, ReconcileMessage};
use crate::source::{ReconcileSource, SessionBounds};
use crate::state::{ReconcileState, Running};
use crate::store::ReconcileStore;
use std::collections::BTreeSet;

/// Symmetric difference accumulated over a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileResult<T = SyncId> {
    /// Present locally, missing remotely.
    pub to_send: Vec<T>,
    /// Present remotely, missing locally.
    pub to_recv: Vec<T>,
}

/// Outcome of [`Reconcile::step`].
#[derive(Debug)]
pub enum ReconcileStep<'store, Src: ReconcileSource = ReconcileStore> {
    /// Send `message` and continue with `next`.
    Next {
        next: Reconcile<'store, Running, Src>,
        message: ReconcileMessage<Src::Item, Src::Bounds>,
    },
    /// Session over. Send `farewell` if this side produced the empty closer.
    Done {
        result: ReconcileResult<Src::Item>,
        farewell: Option<ReconcileMessage<Src::Item, Src::Bounds>>,
    },
}

/// One side of a reconciliation exchange.
///
/// Construct with [`Reconcile::initiate`] or [`Reconcile::respond`]. Only
/// [`Reconcile<Running>`] has [`step`](Reconcile::step).
pub struct Reconcile<'store, S: ReconcileState, Src: ReconcileSource = ReconcileStore> {
    store: &'store Src,
    state: S,
    to_send: BTreeSet<Src::Item>,
    to_recv: BTreeSet<Src::Item>,
}

impl<S: ReconcileState, Src: ReconcileSource> std::fmt::Debug for Reconcile<'_, S, Src> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reconcile").finish_non_exhaustive()
    }
}

type SourceMessage<Src> =
    ReconcileMessage<<Src as ReconcileSource>::Item, <Src as ReconcileSource>::Bounds>;
#[cfg(test)]
type PairResult<Src> = (
    ReconcileResult<<Src as ReconcileSource>::Item>,
    ReconcileResult<<Src as ReconcileSource>::Item>,
);

impl<'store, Src: ReconcileSource> Reconcile<'store, Running, Src> {
    /// Start as initiator: one Fingerprint over `bounds`.
    pub fn initiate(store: &'store Src, bounds: Src::Bounds) -> Result<(Self, SourceMessage<Src>)> {
        if !bounds.is_valid() {
            return Err(ReconcileError::InvalidBounds);
        }
        let session = Self {
            store,
            state: Running::new(),
            to_send: BTreeSet::new(),
            to_recv: BTreeSet::new(),
        };
        let fp = store.fingerprint(bounds.clone());
        let message = ReconcileMessage {
            ranges: vec![Range::fingerprint(bounds, fp)],
        };
        Ok((session, message))
    }

    /// Start as responder. The first [`step`](Self::step) consumes the initiator message.
    pub fn respond(store: &'store Src) -> Self {
        Self {
            store,
            state: Running::new(),
            to_send: BTreeSet::new(),
            to_recv: BTreeSet::new(),
        }
    }

    /// Process one incoming message. Consumes `self`.
    pub fn step(mut self, incoming: SourceMessage<Src>) -> Result<ReconcileStep<'store, Src>> {
        if incoming.is_empty() {
            return Ok(ReconcileStep::Done {
                result: self.into_result(),
                farewell: None,
            });
        }

        self.state.rounds += 1;
        if self.state.rounds > self.store.config().max_rounds {
            return Err(ReconcileError::TooManyRounds {
                max: self.store.config().max_rounds,
            });
        }

        let out = process_payload(self.store, &incoming);
        self.to_send.extend(out.to_send);
        self.to_recv.extend(out.to_recv);

        if out.reply.is_empty() {
            return Ok(ReconcileStep::Done {
                result: self.into_result(),
                farewell: Some(out.reply),
            });
        }

        Ok(ReconcileStep::Next {
            next: self,
            message: out.reply,
        })
    }

    fn into_result(self) -> ReconcileResult<Src::Item> {
        ReconcileResult {
            to_send: self.to_send.into_iter().collect(),
            to_recv: self.to_recv.into_iter().collect(),
        }
    }
}

/// Drive two sessions to completion over an in-memory channel.
#[cfg(test)]
pub(crate) fn run_pair<Src: ReconcileSource>(
    alice_store: &Src,
    bob_store: &Src,
    bounds: Src::Bounds,
) -> Result<PairResult<Src>> {
    let (alice, first) = Reconcile::initiate(alice_store, bounds)?;
    let bob = Reconcile::respond(bob_store);
    drive(alice, bob, first)
}

#[cfg(test)]
fn drive<'a, Src: ReconcileSource>(
    mut alice: Reconcile<'a, Running, Src>,
    mut bob: Reconcile<'a, Running, Src>,
    mut incoming: SourceMessage<Src>,
) -> Result<PairResult<Src>> {
    loop {
        match bob.step(incoming)? {
            ReconcileStep::Next { next, message } => {
                bob = next;
                match alice.step(message)? {
                    ReconcileStep::Next { next, message } => {
                        alice = next;
                        incoming = message;
                    }
                    ReconcileStep::Done { result, farewell } => {
                        let br = finish_peer(bob, farewell)?;
                        return Ok((result, br));
                    }
                }
            }
            ReconcileStep::Done { result, farewell } => {
                let ar = finish_peer(alice, farewell)?;
                return Ok((ar, result));
            }
        }
    }
}

#[cfg(test)]
fn finish_peer<Src: ReconcileSource>(
    session: Reconcile<'_, Running, Src>,
    farewell: Option<SourceMessage<Src>>,
) -> Result<ReconcileResult<Src::Item>> {
    match farewell {
        None => match session.step(ReconcileMessage::empty())? {
            ReconcileStep::Done { result, .. } => Ok(result),
            ReconcileStep::Next { .. } => {
                panic!("empty incoming must finish the session")
            }
        },
        Some(msg) => match session.step(msg)? {
            ReconcileStep::Done { result, .. } => Ok(result),
            ReconcileStep::Next { .. } => {
                panic!("closer must finish the session")
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::RangeBounds;
    use crate::config::ReconcileConfig;
    use crate::id::SyncId;
    use crate::range::Range;

    fn sid(t: u64, h0: u8) -> SyncId {
        let mut hash = [0u8; 32];
        hash[0] = h0;
        SyncId::new(t, hash)
    }

    fn store(ids: &[(u64, u8)]) -> ReconcileStore {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        for &(t, h) in ids {
            s.insert(sid(t, h)).unwrap();
        }
        s
    }

    fn window() -> RangeBounds {
        RangeBounds::window(0, 1_000).unwrap()
    }

    #[test]
    fn identical_stores() {
        let ids = [(1, 1), (2, 2), (3, 3)];
        let a = store(&ids);
        let b = store(&ids);
        let (ar, br) = run_pair(&a, &b, window()).unwrap();
        assert!(ar.to_send.is_empty() && ar.to_recv.is_empty());
        assert!(br.to_send.is_empty() && br.to_recv.is_empty());
    }

    #[test]
    fn alice_only_extras() {
        let alice = store(&[(1, 1), (2, 2), (3, 3)]);
        let bob = store(&[(1, 1)]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_send, vec![sid(2, 2), sid(3, 3)]);
        assert!(ar.to_recv.is_empty());
        assert_eq!(br.to_recv, ar.to_send);
        assert!(br.to_send.is_empty());
    }

    #[test]
    fn bob_only_extras() {
        let alice = store(&[(1, 1)]);
        let bob = store(&[(1, 1), (4, 4)]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_recv, vec![sid(4, 4)]);
        assert!(ar.to_send.is_empty());
        assert_eq!(br.to_send, ar.to_recv);
        assert!(br.to_recv.is_empty());
    }

    #[test]
    fn both_sided_extras() {
        let alice = store(&[(1, 1), (2, 2)]);
        let bob = store(&[(1, 1), (3, 3)]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_send, br.to_recv);
        assert_eq!(ar.to_recv, br.to_send);
        assert_eq!(ar.to_send, vec![sid(2, 2)]);
        assert_eq!(ar.to_recv, vec![sid(3, 3)]);
    }

    #[test]
    fn empty_vs_nonempty() {
        let alice = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let bob = store(&[(5, 9)]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert!(ar.to_send.is_empty());
        assert_eq!(ar.to_recv, vec![sid(5, 9)]);
        assert_eq!(br.to_send, ar.to_recv);
        assert!(br.to_recv.is_empty());
    }

    #[test]
    fn empty_incoming_is_done() {
        let store = store(&[(1, 1)]);
        let s = Reconcile::respond(&store);
        match s.step(ReconcileMessage::empty()).unwrap() {
            ReconcileStep::Done { farewell: None, .. } => {}
            other => panic!("expected Done without farewell, got {other:?}"),
        }
    }

    #[test]
    fn threshold_sends_item_set() {
        let cfg = ReconcileConfig {
            threshold: 2,
            partitions: 8,
            ..Default::default()
        };
        let mut alice = ReconcileStore::new(cfg).unwrap();
        let mut bob = ReconcileStore::new(cfg).unwrap();
        alice.insert(sid(1, 1)).unwrap();
        alice.insert(sid(2, 2)).unwrap();
        bob.insert(sid(1, 1)).unwrap();
        let (sess, first) = Reconcile::initiate(&alice, window()).unwrap();
        assert_eq!(first.ranges.len(), 1);
        assert!(matches!(first.ranges[0], Range::Fingerprint { .. }));
        let bob_sess = Reconcile::respond(&bob);
        match bob_sess.step(first).unwrap() {
            ReconcileStep::Next { message, .. } => {
                assert_eq!(message.ranges.len(), 1);
                match &message.ranges[0] {
                    Range::Items { set, .. } => assert!(!set.reconciled),
                    other => panic!("expected item set, got {other:?}"),
                }
                match sess.step(message).unwrap() {
                    ReconcileStep::Next { message: reply, .. } => match &reply.ranges[0] {
                        Range::Items { set, .. } => assert!(set.reconciled),
                        other => panic!("expected reconciled item set, got {other:?}"),
                    },
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_bounds_initiate() {
        let store = store(&[]);
        let a = SyncId::min_at(5);
        let err = Reconcile::initiate(&store, RangeBounds { a, b: a }).unwrap_err();
        assert_eq!(err, ReconcileError::InvalidBounds);
    }

    #[test]
    fn max_rounds() {
        let cfg = ReconcileConfig {
            max_rounds: 1,
            ..Default::default()
        };
        let store = ReconcileStore::new(cfg).unwrap();
        let s = Reconcile::respond(&store);
        let fp = ReconcileMessage {
            ranges: vec![Range::fingerprint(window(), [1u8; 32])],
        };
        let ReconcileStep::Next { next, .. } = s.step(fp.clone()).unwrap() else {
            panic!("expected Next");
        };
        let err = next.step(fp).unwrap_err();
        assert!(matches!(err, ReconcileError::TooManyRounds { max: 1 }));
    }
}

#[cfg(test)]
mod generic_item_tests {
    use super::*;
    use crate::bounds::RangeBounds;
    use crate::config::ReconcileConfig;
    use crate::item::ReconcileItem;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Key(u64);

    impl ReconcileItem for Key {
        type Fingerprint = u64;

        fn empty_fingerprint() -> u64 {
            0
        }

        fn accumulate(fp: &mut u64, item: &Self) {
            *fp ^= item.0;
        }

        fn combine(a: &u64, b: &u64) -> u64 {
            a ^ b
        }
    }

    fn store(ids: &[u64]) -> ReconcileStore<Key> {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        for &n in ids {
            s.insert(Key(n)).unwrap();
        }
        s
    }

    fn window() -> RangeBounds<Key> {
        RangeBounds::new(Key(0), Key(1_000)).unwrap()
    }

    #[test]
    fn identical_stores() {
        let ids = [1, 2, 3];
        let a = store(&ids);
        let b = store(&ids);
        let (ar, br) = run_pair(&a, &b, window()).unwrap();
        assert!(ar.to_send.is_empty() && ar.to_recv.is_empty());
        assert!(br.to_send.is_empty() && br.to_recv.is_empty());
    }

    #[test]
    fn alice_only_extras() {
        let alice = store(&[1, 2, 3]);
        let bob = store(&[1]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_send, vec![Key(2), Key(3)]);
        assert!(ar.to_recv.is_empty());
        assert_eq!(br.to_recv, ar.to_send);
        assert!(br.to_send.is_empty());
    }

    #[test]
    fn bob_only_extras() {
        let alice = store(&[1]);
        let bob = store(&[1, 4]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_recv, vec![Key(4)]);
        assert!(ar.to_send.is_empty());
        assert_eq!(br.to_send, ar.to_recv);
        assert!(br.to_recv.is_empty());
    }

    #[test]
    fn both_sided_extras() {
        let alice = store(&[1, 2]);
        let bob = store(&[1, 3]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_send, br.to_recv);
        assert_eq!(ar.to_recv, br.to_send);
        assert_eq!(ar.to_send, vec![Key(2)]);
        assert_eq!(ar.to_recv, vec![Key(3)]);
    }

    #[test]
    fn empty_vs_nonempty() {
        let alice = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let bob = store(&[5]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert!(ar.to_send.is_empty());
        assert_eq!(ar.to_recv, vec![Key(5)]);
        assert_eq!(br.to_send, ar.to_recv);
        assert!(br.to_recv.is_empty());
    }

    #[test]
    fn item_partition_when_above_threshold() {
        let cfg = ReconcileConfig {
            threshold: 2,
            partitions: 4,
            ..Default::default()
        };
        let mut alice = ReconcileStore::new(cfg).unwrap();
        let mut bob = ReconcileStore::new(cfg).unwrap();
        for n in 1..=20u64 {
            alice.insert(Key(n)).unwrap();
            if n % 2 == 0 {
                bob.insert(Key(n)).unwrap();
            }
        }
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.to_send.len(), 10);
        assert!(ar.to_recv.is_empty());
        assert_eq!(ar.to_send, br.to_recv);
    }
}
