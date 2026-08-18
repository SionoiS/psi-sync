//! Range-based set reconciliation ([LIP-182][lip] algorithm, Rust API).
//!
//! Two peers holding ordered [`SyncId`] sets exchange [`ReconcileMessage`]s
//! until they agree on the symmetric difference. This is **not** private set
//! intersection — see the `psi` crate. There is no transfer protocol.
//!
//! [lip]: https://lip.logos.co/messaging/core/raw/sync.html
//!
//! The session is type-state: only [`Reconcile<Running>`] can [`Reconcile::step`].
//! `step` consumes `self`, like `psi::PsiProtocol::compute`.
//!
//! ## Example
//!
//! ```
//! use reconciliation::{
//!     RangeBounds, Reconcile, ReconcileStep, ReconcileStore, SyncId,
//! };
//!
//! let mut alice_store = ReconcileStore::new(Default::default())?;
//! let mut bob_store = ReconcileStore::new(Default::default())?;
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
//!                         None => match bob.step(reconciliation::ReconcileMessage::empty())? {
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
//!                 None => match alice.step(reconciliation::ReconcileMessage::empty())? {
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
//! # Ok::<(), reconciliation::ReconcileError>(())
//! ```
//!
//! ## Threat model
//!
//! Peers are trusted to follow the protocol. Fingerprints leak the XOR of
//! hashes in a range. Item sets leak every [`SyncId`] in a differing range.
//! A peer can Skip or invent IDs. Use an authenticated channel.
//!
//! ## Codec
//!
//! [`codec::encode`] / [`codec::decode`] are optional. The session never
//! calls them. Cluster/shard headers are written as zero and ignored.

pub use bounds::RangeBounds;
pub use config::ReconcileConfig;
pub use error::{ReconcileError, Result};
pub use id::{SyncId, EMPTY_HASH, FULL_HASH};
pub use range::{ItemSet, Range, ReconcileMessage};
pub use session::{Reconcile, ReconcileResult, ReconcileStep};
pub use state::{ReconcileState, Running};
pub use store::ReconcileStore;

pub mod codec;

mod bounds;
mod config;
mod error;
mod fingerprint;
mod id;
mod partition;
mod process;
mod range;
mod session;
mod state;
mod store;

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

        let mut alice = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let mut bob = ReconcileStore::new(ReconcileConfig::default()).unwrap();
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
