//! Range-based set reconciliation (Rust API).
//!
//! Two peers holding ordered sets of [`ReconcileItem`]s exchange
//! [`ReconcileMessage`]s until they agree on the symmetric difference.
//! The set requirement is a total order; fingerprints test range equality
//! without listing items. [`SyncId`] is the default item type (time then
//! hash). [`ReconcileStore`] holds items in a monoid tree; [`TaggedStore`]
//! adds a tag axis (topic × item).
//!
//! This is **not** private set intersection — see the `psi` crate. There
//! is no transfer protocol.
//!
//! The session is type-state: only [`Reconcile<Running>`] can [`Reconcile::step`].
//! `step` consumes `self`, like `psi::PsiProtocol::compute`. Each `step` reads
//! a consistent snapshot of [`ReconcileStore`]; inserts on the live store are
//! allowed and become visible in later rounds (already-`Skip`ped ranges miss
//! them). Removes/`prune_before` keep in-flight snapshots intact (path copy).
//!
//! ## Example
//!
//! ```
//! use sync::{
//!     RangeBounds, Reconcile, ReconcileStep, ReconcileStore, SyncId,
//! };
//!
//! let alice_store = ReconcileStore::new(Default::default())?;
//! let bob_store = ReconcileStore::new(Default::default())?;
//! alice_store.insert(SyncId::new(1, [1u8; 32]))?;
//! alice_store.insert(SyncId::new(2, [2u8; 32]))?;
//! bob_store.insert(SyncId::new(1, [1u8; 32]))?;
//!
//! let bounds = RangeBounds::window(0, 10)?;
//! let (mut alice, first) = Reconcile::initiate(&alice_store, bounds)?;
//! let mut bob = Reconcile::respond(&bob_store);
//!
//! let mut incoming = first;
//! let (ar, br) = loop {
//!     match bob.step(incoming)? {
//!         ReconcileStep::Next { next, message } => {
//!             bob = next;
//!             match alice.step(message)? {
//!                 ReconcileStep::Next { next, message } => {
//!                     alice = next;
//!                     incoming = message;
//!                 }
//!                 ReconcileStep::Done { result, farewell } => {
//!                     let br = match farewell {
//!                         Some(msg) => match bob.step(msg)? {
//!                             ReconcileStep::Done { result, .. } => result,
//!                             ReconcileStep::Next { .. } => unreachable!(),
//!                         },
//!                         None => match bob.step(sync::ReconcileMessage::empty())? {
//!                             ReconcileStep::Done { result, .. } => result,
//!                             ReconcileStep::Next { .. } => unreachable!(),
//!                         },
//!                     };
//!                     break (result, br);
//!                 }
//!             }
//!         }
//!         ReconcileStep::Done { result, farewell } => {
//!             let ar = match farewell {
//!                 Some(msg) => match alice.step(msg)? {
//!                     ReconcileStep::Done { result, .. } => result,
//!                     ReconcileStep::Next { .. } => unreachable!(),
//!                 },
//!                 None => match alice.step(sync::ReconcileMessage::empty())? {
//!                     ReconcileStep::Done { result, .. } => result,
//!                     ReconcileStep::Next { .. } => unreachable!(),
//!                 },
//!             };
//!             break (ar, result);
//!         }
//!     }
//! };
//!
//! assert_eq!(ar.to_send.len(), 1);
//! assert_eq!(br.to_recv, ar.to_send);
//! # Ok::<(), sync::ReconcileError>(())
//! ```
//!
//! Any [`ReconcileItem`] works. This newtype uses a `u64` fingerprint:
//!
//! ```
//! use sync::{
//!     RangeBounds, Reconcile, ReconcileItem, ReconcileStep, ReconcileStore,
//! };
//!
//! #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
//! struct Key(u64);
//!
//! impl ReconcileItem for Key {
//!     type Fingerprint = u64;
//!     fn empty_fingerprint() -> u64 { 0 }
//!     fn accumulate(fp: &mut u64, item: &Self) { *fp ^= item.0; }
//!     fn combine(a: &u64, b: &u64) -> u64 { a ^ b }
//! }
//!
//! let alice = ReconcileStore::new(Default::default())?;
//! let bob = ReconcileStore::new(Default::default())?;
//! alice.insert(Key(1))?;
//! alice.insert(Key(2))?;
//! bob.insert(Key(1))?;
//!
//! let bounds = RangeBounds::new(Key(0), Key(10))?;
//! let (alice_sess, first) = Reconcile::initiate(&alice, bounds)?;
//! let bob_sess = Reconcile::respond(&bob);
//! match bob_sess.step(first)? {
//!     ReconcileStep::Done { result, .. } => {
//!         assert_eq!(result.to_recv.len(), 1);
//!     }
//!     ReconcileStep::Next { message, next } => {
//!         let _ = (alice_sess.step(message)?, next);
//!     }
//! }
//! # Ok::<(), sync::ReconcileError>(())
//! ```
//!
//! ## Threat model
//!
//! Peers are trusted to follow the protocol. Fingerprints leak a digest of
//! items in a range (XOR of hashes for [`SyncId`]). Equal XOR fingerprints
//! are treated as equal ranges; a collision can hide a real difference.
//! Item sets leak every identifier in a differing range.
//! A peer can Skip or invent IDs. Use an authenticated channel.
//!
//! ## Codec
//!
//! [`codec::encode`] / [`codec::decode`] are optional. The session never
//! calls them. Cluster/shard headers are written as zero and ignored.
//! Session replies use exclusive `elements` plus `needed`; the codec encodes
//! that shape (`elements` then `needed`).

pub use bounds::RangeBounds;
pub use config::ReconcileConfig;
pub use error::{ReconcileError, Result};
pub use id::{SyncId, EMPTY_HASH, FULL_HASH};
pub use item::ReconcileItem;
pub use range::{ItemSet, Range, ReconcileMessage};
pub use session::{Reconcile, ReconcileResult, ReconcileStep};
pub use source::{ReconcileSource, SessionBounds};
pub use state::{ReconcileState, Running};
pub use store::ReconcileStore;
pub use tagged::{RectBounds, TagRange, Tagged, TaggedStore};

pub mod codec;

mod bounds;
mod config;
mod error;
mod fingerprint;
mod id;
mod item;
mod partition;
mod process;
mod range;
mod range_tree;
mod session;
mod source;
mod state;
mod store;
mod tagged;
mod tree;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::session::run_pair;

    #[test]
    fn large_almost_equal_sets() {
        fn mix(tag: u8, i: u64) -> [u8; 32] {
            let mut hash = [0u8; 32];
            hash[0] = tag;
            hash[1..9].copy_from_slice(&i.to_be_bytes());
            hash[9..17].copy_from_slice(&(i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_le_bytes());
            hash[17] = tag.wrapping_add(i as u8);
            hash
        }

        let alice = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let bob = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        for i in 0..1000u64 {
            let id = SyncId::new(1_000 + i, mix(0x11, i));
            alice.insert(id).unwrap();
            if i >= 50 {
                bob.insert(id).unwrap();
            }
        }
        for i in 0..50u64 {
            bob.insert(SyncId::new(3_000 + i, mix(0x22, i))).unwrap();
        }

        let bounds = RangeBounds::window(0, 10_000).unwrap();
        assert_ne!(
            alice.fingerprint(bounds),
            bob.fingerprint(bounds),
            "test hashes must not XOR-collide"
        );
        let (ar, br) = run_pair(&alice, &bob, bounds).unwrap();
        assert_eq!(ar.to_send.len(), 50);
        assert_eq!(ar.to_recv.len(), 50);
        assert_eq!(ar.to_send, br.to_recv);
        assert_eq!(ar.to_recv, br.to_send);
    }
}
