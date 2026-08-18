//! Multi-round reconciliation session.

use crate::bounds::RangeBounds;
use crate::error::{ReconcileError, Result};
use crate::process::process_payload;
use crate::range::{Range, RangesData, SyncScope};
use crate::store::ReconcileStore;
use crate::SyncId;
use std::collections::BTreeSet;

/// Symmetric difference accumulated over a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileResult {
    /// Present locally, missing remotely.
    pub to_send: Vec<SyncId>,
    /// Present remotely, missing locally.
    pub to_recv: Vec<SyncId>,
}

/// Outcome of one [`ReconcileSession::step`].
///
/// If `Continue` carries a [terminal](RangesData::is_terminal) payload, send
/// it and stop — the peer will `Done` on receipt. Call [`ReconcileSession::into_result`]
/// for the local diffs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileRound {
    /// Send this payload and wait for the next one (unless it is terminal).
    Continue(RangesData),
    /// The peer sent a terminal payload; do not send further.
    Done(ReconcileResult),
}

/// One side of a reconciliation exchange.
#[derive(Clone, Debug)]
pub struct ReconcileSession {
    scope: SyncScope,
    to_send: BTreeSet<SyncId>,
    to_recv: BTreeSet<SyncId>,
    rounds: usize,
    max_rounds: usize,
}

impl ReconcileSession {
    /// Start as initiator: one Fingerprint over `bounds`.
    pub fn initiate(
        store: &ReconcileStore,
        bounds: RangeBounds,
        scope: SyncScope,
    ) -> Result<(Self, RangesData)> {
        if bounds.a >= bounds.b {
            return Err(ReconcileError::InvalidBounds);
        }
        let session = Self::new(scope.clone(), store.config().max_rounds);
        let payload = RangesData {
            scope,
            ranges: vec![Range::fingerprint(bounds, store.fingerprint(bounds))],
        };
        Ok((session, payload))
    }

    /// Start as responder. The first `step` consumes the initiator payload.
    pub fn respond(scope: SyncScope) -> Self {
        Self::new(scope, crate::config::DEFAULT_MAX_ROUNDS)
    }

    /// Responder with an explicit round cap (matches the store’s config).
    pub fn respond_with_config(scope: SyncScope, store: &ReconcileStore) -> Self {
        Self::new(scope, store.config().max_rounds)
    }

    fn new(scope: SyncScope, max_rounds: usize) -> Self {
        Self {
            scope,
            to_send: BTreeSet::new(),
            to_recv: BTreeSet::new(),
            rounds: 0,
            max_rounds,
        }
    }

    /// Process one incoming payload.
    pub fn step(&mut self, store: &ReconcileStore, incoming: RangesData) -> Result<ReconcileRound> {
        incoming.validate()?;

        if incoming.is_terminal() {
            return Ok(ReconcileRound::Done(self.snapshot()));
        }

        self.rounds += 1;
        if self.rounds > self.max_rounds {
            return Err(ReconcileError::TooManyRounds {
                max: self.max_rounds,
            });
        }

        let out = process_payload(store, &self.scope, &incoming);
        self.to_send.extend(out.to_send);
        self.to_recv.extend(out.to_recv);
        Ok(ReconcileRound::Continue(out.reply))
    }

    /// Local diffs so far. Use after a terminal [`ReconcileRound::Continue`].
    pub fn into_result(self) -> ReconcileResult {
        self.snapshot()
    }

    fn snapshot(&self) -> ReconcileResult {
        ReconcileResult {
            to_send: self.to_send.iter().copied().collect(),
            to_recv: self.to_recv.iter().copied().collect(),
        }
    }
}

/// Drive two sessions to completion over an in-memory channel.
#[cfg(test)]
pub(crate) fn run_pair(
    alice_store: &ReconcileStore,
    bob_store: &ReconcileStore,
    bounds: RangeBounds,
    scope: SyncScope,
) -> Result<(ReconcileResult, ReconcileResult)> {
    let (mut alice, first) = ReconcileSession::initiate(alice_store, bounds, scope.clone())?;
    let mut bob = ReconcileSession::respond_with_config(scope, bob_store);

    let mut incoming_to_bob = first;
    loop {
        match bob.step(bob_store, incoming_to_bob)? {
            ReconcileRound::Continue(msg) => {
                if msg.is_terminal() {
                    match alice.step(alice_store, msg)? {
                        ReconcileRound::Done(a) => return Ok((a, bob.into_result())),
                        ReconcileRound::Continue(_) => {
                            return Ok((alice.into_result(), bob.into_result()));
                        }
                    }
                }
                match alice.step(alice_store, msg)? {
                    ReconcileRound::Continue(next) => {
                        if next.is_terminal() {
                            match bob.step(bob_store, next)? {
                                ReconcileRound::Done(b) => {
                                    return Ok((alice.into_result(), b));
                                }
                                ReconcileRound::Continue(_) => {
                                    return Ok((alice.into_result(), bob.into_result()));
                                }
                            }
                        }
                        incoming_to_bob = next;
                    }
                    ReconcileRound::Done(a) => return Ok((a, bob.into_result())),
                }
            }
            ReconcileRound::Done(b) => return Ok((alice.into_result(), b)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReconcileConfig;
    use crate::id::SyncId;

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
        let (ar, br) = run_pair(&a, &b, window(), SyncScope::any()).unwrap();
        assert!(ar.to_send.is_empty() && ar.to_recv.is_empty());
        assert!(br.to_send.is_empty() && br.to_recv.is_empty());
    }

    #[test]
    fn alice_only_extras() {
        let alice = store(&[(1, 1), (2, 2), (3, 3)]);
        let bob = store(&[(1, 1)]);
        let (ar, br) = run_pair(&alice, &bob, window(), SyncScope::any()).unwrap();
        assert_eq!(ar.to_send, vec![sid(2, 2), sid(3, 3)]);
        assert!(ar.to_recv.is_empty());
        assert_eq!(br.to_recv, ar.to_send);
        assert!(br.to_send.is_empty());
    }

    #[test]
    fn bob_only_extras() {
        let alice = store(&[(1, 1)]);
        let bob = store(&[(1, 1), (4, 4)]);
        let (ar, br) = run_pair(&alice, &bob, window(), SyncScope::any()).unwrap();
        assert_eq!(ar.to_recv, vec![sid(4, 4)]);
        assert!(ar.to_send.is_empty());
        assert_eq!(br.to_send, ar.to_recv);
        assert!(br.to_recv.is_empty());
    }

    #[test]
    fn both_sided_extras() {
        let alice = store(&[(1, 1), (2, 2)]);
        let bob = store(&[(1, 1), (3, 3)]);
        let (ar, br) = run_pair(&alice, &bob, window(), SyncScope::any()).unwrap();
        assert_eq!(ar.to_send, br.to_recv);
        assert_eq!(ar.to_recv, br.to_send);
        assert_eq!(ar.to_send, vec![sid(2, 2)]);
        assert_eq!(ar.to_recv, vec![sid(3, 3)]);
    }

    #[test]
    fn empty_vs_nonempty() {
        let alice = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let bob = store(&[(5, 9)]);
        let (ar, br) = run_pair(&alice, &bob, window(), SyncScope::any()).unwrap();
        assert!(ar.to_send.is_empty());
        assert_eq!(ar.to_recv, vec![sid(5, 9)]);
        assert_eq!(br.to_send, ar.to_recv);
        assert!(br.to_recv.is_empty());
    }

    #[test]
    fn empty_incoming_is_done() {
        let store = store(&[(1, 1)]);
        let mut s = ReconcileSession::respond(SyncScope::any());
        let round = s.step(&store, RangesData::empty(SyncScope::any())).unwrap();
        assert!(matches!(round, ReconcileRound::Done(_)));
    }

    #[test]
    fn scope_mismatch_yields_empty() {
        let alice = store(&[(1, 1), (2, 2)]);
        let bob = store(&[(1, 1)]);
        let a_scope = SyncScope {
            cluster: 1,
            shards: vec![1],
        };
        let b_scope = SyncScope {
            cluster: 2,
            shards: vec![1],
        };
        let (mut sess, first) = ReconcileSession::initiate(&alice, window(), a_scope).unwrap();
        let mut bob_sess = ReconcileSession::respond(b_scope);
        match bob_sess.step(&bob, first).unwrap() {
            ReconcileRound::Continue(msg) => {
                assert!(msg.is_terminal());
                match sess.step(&alice, msg).unwrap() {
                    ReconcileRound::Done(r) => {
                        assert!(r.to_send.is_empty() && r.to_recv.is_empty());
                    }
                    other => panic!("expected Done, got {other:?}"),
                }
            }
            other => panic!("expected Continue(empty), got {other:?}"),
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
        let (mut sess, first) =
            ReconcileSession::initiate(&alice, window(), SyncScope::any()).unwrap();
        assert_eq!(first.ranges.len(), 1);
        assert_eq!(first.ranges[0].kind, crate::range::RangeType::Fingerprint);
        let mut bob_sess = ReconcileSession::respond(SyncScope::any());
        match bob_sess.step(&bob, first).unwrap() {
            ReconcileRound::Continue(msg) => {
                assert_eq!(msg.ranges.len(), 1);
                assert_eq!(msg.ranges[0].kind, crate::range::RangeType::ItemSet);
                match &msg.ranges[0].content {
                    crate::range::RangeContent::Items(set) => {
                        assert!(!set.reconciled);
                    }
                    _ => panic!("expected item set"),
                }
                match sess.step(&alice, msg).unwrap() {
                    ReconcileRound::Continue(reply) => match &reply.ranges[0].content {
                        crate::range::RangeContent::Items(set) => {
                            assert!(set.reconciled);
                        }
                        _ => panic!("expected reconciled item set"),
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
        let err = ReconcileSession::initiate(&store, RangeBounds { a, b: a }, SyncScope::any())
            .unwrap_err();
        assert_eq!(err, ReconcileError::InvalidBounds);
    }

    #[test]
    fn payload_mismatch() {
        let store = store(&[(1, 1)]);
        let mut s = ReconcileSession::respond(SyncScope::any());
        let bad = RangesData {
            scope: SyncScope::any(),
            ranges: vec![Range {
                bounds: window(),
                kind: crate::range::RangeType::Skip,
                content: crate::range::RangeContent::Fingerprint([0; 32]),
            }],
        };
        assert_eq!(
            s.step(&store, bad).unwrap_err(),
            ReconcileError::PayloadMismatch
        );
    }

    #[test]
    fn max_rounds() {
        let cfg = ReconcileConfig {
            max_rounds: 1,
            ..Default::default()
        };
        let store = ReconcileStore::new(cfg).unwrap();
        let mut s = ReconcileSession::respond_with_config(SyncScope::any(), &store);
        let fp = RangesData {
            scope: SyncScope::any(),
            ranges: vec![Range::fingerprint(window(), [1u8; 32])],
        };
        s.step(&store, fp.clone()).unwrap();
        let err = s.step(&store, fp).unwrap_err();
        assert!(matches!(err, ReconcileError::TooManyRounds { max: 1 }));
    }
}
