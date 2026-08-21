//! # Topic-sync
//!
//! Compose [`psi`] and [`reconciliation`] into one two-party session:
//!
//! 1. **PSI** on each party's topic set. Both learn only the topics they share.
//! 2. **Range-based reconciliation** once per shared topic. Both learn the
//!    [`SyncId`]s to send and receive for that topic's messages.
//!
//! Exclusive topics never appear on the reconciliation wire. The crate does
//! not transfer payloads, does not talk to the network, and does not mutate
//! stores with `to_recv` IDs.
//!
//! ## Protocol
//!
//! The outer channel is turn-taking (`step` consumes `self`). PSI is
//! therefore embedded as three sequential messages rather than two parallel
//! exchanges; the `psi` crate itself is unchanged.
//!
//! 1. Initiator → responder: [`SyncMessage::PsiBlinded`].
//! 2. Responder → initiator: [`SyncMessage::PsiOffer`].
//! 3. Initiator → responder: [`SyncMessage::PsiDone`] (double-blind, plus the
//!    first topic's fingerprint when the intersection is non-empty).
//! 4. For each shared topic, in lexicographic PSI-hash order: inner
//!    [`reconciliation::Reconcile`] frames, tagged by topic hash.
//! 5. The initiator ends each topic with [`SyncMessage::TopicComplete`],
//!    which absorbs the LIP-182 empty closer and may carry the next
//!    topic's opening fingerprint.
//!
//! Empty topic intersection is a successful no-op: `PsiDone` has
//! `first_reconcile: None` and no reconcile frames are sent.
//!
//! ## Example
//!
//! ```
//! use topic_sync::{
//!     RangeBounds, ReconcileStore, SyncId, SyncStep, TopicStores, TopicSync,
//! };
//!
//! let mut alice_topics = TopicStores::new();
//! let mut bob_topics = TopicStores::new();
//!
//! let mut shared = ReconcileStore::new(Default::default())?;
//! shared.insert(SyncId::new(1, [1u8; 32]))?;
//! alice_topics.insert(b"shared".to_vec(), shared.clone())?;
//! bob_topics.insert(b"shared".to_vec(), shared)?;
//!
//! let mut alice_only = ReconcileStore::new(Default::default())?;
//! alice_only.insert(SyncId::new(2, [2u8; 32]))?;
//! alice_topics.insert(b"alice-only".to_vec(), alice_only)?;
//!
//! let bounds = RangeBounds::window(0, 10)?;
//! let (mut alice, mut incoming) = TopicSync::initiate(&alice_topics, bounds)?;
//! let mut bob = TopicSync::respond(&bob_topics, bounds)?;
//!
//! let (alice_result, bob_result) = loop {
//!     match bob.step(incoming)? {
//!         SyncStep::Next { next, message } => {
//!             bob = next;
//!             match alice.step(message)? {
//!                 SyncStep::Next { next, message } => {
//!                     alice = next;
//!                     incoming = message;
//!                 }
//!                 SyncStep::Done { result, farewell } => {
//!                     let br = match farewell {
//!                         Some(msg) => match bob.step(msg)? {
//!                             SyncStep::Done { result, .. } => result,
//!                             SyncStep::Next { .. } => unreachable!(),
//!                         },
//!                         None => unreachable!(),
//!                     };
//!                     break (result, br);
//!                 }
//!             }
//!         }
//!         SyncStep::Done { result, farewell } => {
//!             let ar = match farewell {
//!                 Some(msg) => match alice.step(msg)? {
//!                     SyncStep::Done { result, .. } => result,
//!                     SyncStep::Next { .. } => unreachable!(),
//!                 },
//!                 None => unreachable!(),
//!             };
//!             break (ar, result);
//!         }
//!     }
//! };
//!
//! assert_eq!(alice_result.len(), 1);
//! assert_eq!(bob_result.len(), 1);
//! assert_eq!(alice_result.topics[0].to_send, bob_result.topics[0].to_recv);
//! # Ok::<(), topic_sync::TopicSyncError>(())
//! ```
//!
//! ## Threat model
//!
//! Honest-but-curious peers. The channel must be **authenticated,
//! confidential, and order-preserving**. Topic-set sizes leak from PSI
//! message lengths. Shared topic hashes appear on reconcile frames.
//! Exclusive topic bytes never leave this crate. Message identifiers in a
//! differing range leak (same as [`reconciliation`]). A malicious peer can
//! lie about its set or stall. There are no proofs of correct computation.

pub use error::{Result, TopicSyncError};
pub use message::{ReconcileFrame, SyncMessage};
pub use psi::{hash_bytes, BlindedPointsMessage, DoubleBlindedPointsMessage};
pub use reconciliation::{RangeBounds, ReconcileConfig, ReconcileMessage, ReconcileStore, SyncId};
pub use result::{SyncResult, TopicDiff};
pub use session::{SyncStep, TopicSync};
pub use stores::TopicStores;

mod error;
mod message;
mod result;
mod session;
mod state;
mod stores;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::session::{run_pair, run_pair_traced};
    use reconciliation::ReconcileConfig;
    use std::collections::HashSet;

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

    fn insert(map: &mut TopicStores, topic: &[u8], ids: &[(u64, u8)]) {
        map.insert(topic.to_vec(), store(ids)).unwrap();
    }

    fn hashes_on_wire(msgs: &[SyncMessage]) -> HashSet<[u8; 32]> {
        let mut set = HashSet::new();
        for msg in msgs {
            match msg {
                SyncMessage::PsiDone {
                    first_reconcile, ..
                } => {
                    if let Some(frame) = first_reconcile {
                        set.insert(frame.topic_hash);
                    }
                }
                SyncMessage::Reconcile(frame) => {
                    set.insert(frame.topic_hash);
                }
                SyncMessage::TopicComplete { topic_hash, next } => {
                    set.insert(*topic_hash);
                    if let Some(frame) = next {
                        set.insert(frame.topic_hash);
                    }
                }
                SyncMessage::PsiBlinded(_) | SyncMessage::PsiOffer { .. } => {}
            }
        }
        set
    }

    #[test]
    fn overlapping_topics_complementary_diffs() {
        let mut alice = TopicStores::new();
        let mut bob = TopicStores::new();
        insert(&mut alice, b"shared", &[(1, 1), (2, 2)]);
        insert(&mut bob, b"shared", &[(1, 1), (3, 3)]);
        insert(&mut alice, b"alice-only", &[(9, 9)]);
        insert(&mut bob, b"bob-only", &[(8, 8)]);

        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.len(), 1);
        assert_eq!(br.len(), 1);
        assert_eq!(ar.topics[0].topic_hash, hash_bytes(b"shared"));
        assert_eq!(ar.topics[0].to_send, vec![sid(2, 2)]);
        assert_eq!(ar.topics[0].to_recv, vec![sid(3, 3)]);
        assert_eq!(ar.topics[0].to_send, br.topics[0].to_recv);
        assert_eq!(ar.topics[0].to_recv, br.topics[0].to_send);
    }

    #[test]
    fn no_topic_overlap_no_reconcile_frames() {
        let mut alice = TopicStores::new();
        let mut bob = TopicStores::new();
        insert(&mut alice, b"alice-only", &[(1, 1)]);
        insert(&mut bob, b"bob-only", &[(2, 2)]);

        let (ar, br, wire) = run_pair_traced(&alice, &bob, window()).unwrap();
        assert!(ar.is_empty());
        assert!(br.is_empty());
        assert!(hashes_on_wire(&wire).is_empty());
        assert!(wire.iter().all(|m| !matches!(
            m,
            SyncMessage::Reconcile(_) | SyncMessage::TopicComplete { .. }
        )));
    }

    #[test]
    fn identical_shared_topic_empty_diff() {
        let mut alice = TopicStores::new();
        let mut bob = TopicStores::new();
        insert(&mut alice, b"t", &[(1, 1), (2, 2)]);
        insert(&mut bob, b"t", &[(1, 1), (2, 2)]);

        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.len(), 1);
        assert!(ar.topics[0].to_send.is_empty());
        assert!(ar.topics[0].to_recv.is_empty());
        assert_eq!(ar, br);
    }

    #[test]
    fn several_shared_topics_sorted_hashes() {
        let mut alice = TopicStores::new();
        let mut bob = TopicStores::new();
        insert(&mut alice, b"aaa", &[(1, 1)]);
        insert(&mut bob, b"aaa", &[(1, 1)]);
        insert(&mut alice, b"zzz", &[(2, 2), (4, 4)]);
        insert(&mut bob, b"zzz", &[(2, 2), (5, 5)]);
        insert(&mut alice, b"mmm", &[(3, 3)]);
        insert(&mut bob, b"mmm", &[(3, 3)]);

        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert_eq!(ar.len(), 3);
        let hashes: Vec<_> = ar.topics.iter().map(|d| d.topic_hash).collect();
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        assert_eq!(hashes, sorted);

        let zzz = hash_bytes(b"zzz");
        let zzz_diff = ar.topics.iter().find(|d| d.topic_hash == zzz).unwrap();
        assert_eq!(zzz_diff.to_send, vec![sid(4, 4)]);
        assert_eq!(zzz_diff.to_recv, vec![sid(5, 5)]);
        assert_eq!(
            ar.topics,
            br.topics
                .iter()
                .map(|d| TopicDiff {
                    topic_hash: d.topic_hash,
                    to_send: d.to_recv.clone(),
                    to_recv: d.to_send.clone(),
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn exclusive_topics_never_on_wire() {
        let mut alice = TopicStores::new();
        let mut bob = TopicStores::new();
        insert(&mut alice, b"shared", &[(1, 1)]);
        insert(&mut bob, b"shared", &[(1, 1)]);
        insert(&mut alice, b"secret-a", &[(2, 2)]);
        insert(&mut bob, b"secret-b", &[(3, 3)]);

        let (_, _, wire) = run_pair_traced(&alice, &bob, window()).unwrap();
        let seen = hashes_on_wire(&wire);
        assert!(seen.contains(&hash_bytes(b"shared")));
        assert!(!seen.contains(&hash_bytes(b"secret-a")));
        assert!(!seen.contains(&hash_bytes(b"secret-b")));
    }

    #[test]
    fn empty_stores() {
        let alice = TopicStores::new();
        let bob = TopicStores::new();
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert!(ar.is_empty());
        assert!(br.is_empty());
    }

    #[test]
    fn empty_vs_nonempty_topics() {
        let mut alice = TopicStores::new();
        let bob = TopicStores::new();
        insert(&mut alice, b"only-alice", &[(1, 1)]);
        let (ar, br) = run_pair(&alice, &bob, window()).unwrap();
        assert!(ar.is_empty());
        assert!(br.is_empty());
    }

    #[test]
    fn unexpected_reconcile_during_psi() {
        let stores = TopicStores::new();
        let (alice, _) = TopicSync::initiate(&stores, window()).unwrap();
        let err = alice
            .step(SyncMessage::Reconcile(ReconcileFrame::new(
                [0u8; 32],
                ReconcileMessage::empty(),
            )))
            .unwrap_err();
        assert_eq!(err, TopicSyncError::UnexpectedMessage);
    }

    #[test]
    fn topic_mismatch_on_first_reconcile() {
        let mut alice = TopicStores::new();
        let mut bob = TopicStores::new();
        insert(&mut alice, b"shared", &[(1, 1)]);
        insert(&mut bob, b"shared", &[(1, 1)]);

        let (alice_sess, first) = TopicSync::initiate(&alice, window()).unwrap();
        let bob_sess = TopicSync::respond(&bob, window()).unwrap();
        let SyncStep::Next {
            next: bob_sess,
            message: offer,
        } = bob_sess.step(first).unwrap()
        else {
            panic!("expected offer");
        };
        let SyncStep::Next {
            message:
                SyncMessage::PsiDone {
                    double_blinded,
                    first_reconcile: Some(frame),
                },
            ..
        } = alice_sess.step(offer).unwrap()
        else {
            panic!("expected PsiDone with first reconcile");
        };

        let tampered = SyncMessage::PsiDone {
            double_blinded,
            first_reconcile: Some(ReconcileFrame::new([0x11; 32], frame.body)),
        };
        let err = bob_sess.step(tampered).unwrap_err();
        assert!(matches!(err, TopicSyncError::TopicMismatch { .. }));
    }

    #[test]
    fn invalid_bounds() {
        let stores = TopicStores::new();
        let a = SyncId::min_at(5);
        let bounds = RangeBounds { a, b: a };
        let err = TopicSync::initiate(&stores, bounds).unwrap_err();
        assert!(matches!(
            err,
            TopicSyncError::Reconcile(reconciliation::ReconcileError::InvalidBounds)
        ));
    }
}
