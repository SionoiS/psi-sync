//! Range-based set reconciliation ([LIP-182 WAKU-SYNC][lip]).
//!
//! Two peers holding ordered [`SyncId`] sets exchange [`RangesData`] payloads
//! until they agree on the symmetric difference: items to send and items to
//! request. This is **not** private set intersection — see the `psi` crate for
//! ECDH-PSI. This crate does **not** implement the LIP transfer protocol.
//!
//! [lip]: https://lip.logos.co/messaging/core/raw/sync.html
//!
//! ## Protocol
//!
//! 1. The initiator sends one [`RangeType::Fingerprint`] over a
//!    [`RangeBounds`] window.
//! 2. Each peer replies with Skip (XOR matches), an [`ItemSet`] (range is
//!    small), or more fingerprints (range is large and is partitioned).
//! 3. Item sets are compared with a merge walk. The first item set has
//!    `reconciled = false`; the reply has `true` so both sides learn the
//!    difference without a transfer protocol.
//! 4. An empty [`RangesData::ranges`] list ends the session.
//!
//! ## Example
//!
//! ```
//! use reconciliation::{
//!     RangeBounds, ReconcileRound, ReconcileSession, ReconcileStore, SyncId, SyncScope,
//! };
//!
//! let mut alice = ReconcileStore::new(Default::default())?;
//! let mut bob = ReconcileStore::new(Default::default())?;
//! alice.insert(SyncId::new(1, [1u8; 32]))?;
//! alice.insert(SyncId::new(2, [2u8; 32]))?;
//! bob.insert(SyncId::new(1, [1u8; 32]))?;
//!
//! let bounds = RangeBounds::window(0, 10)?;
//! let scope = SyncScope::any();
//! let (mut a, first) = ReconcileSession::initiate(&alice, bounds, scope.clone())?;
//! let mut b = ReconcileSession::respond(scope);
//!
//! let mut incoming = first;
//! let (ar, br) = loop {
//!     match b.step(&bob, incoming)? {
//!         ReconcileRound::Continue(msg) => {
//!             if msg.is_terminal() {
//!                 let ar = match a.step(&alice, msg)? {
//!                     ReconcileRound::Done(r) => r,
//!                     ReconcileRound::Continue(_) => a.into_result(),
//!                 };
//!                 break (ar, b.into_result());
//!             }
//!             match a.step(&alice, msg)? {
//!                 ReconcileRound::Continue(next) => incoming = next,
//!                 ReconcileRound::Done(ar) => break (ar, b.into_result()),
//!             }
//!         }
//!         ReconcileRound::Done(br) => break (a.into_result(), br),
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
//! LIP-182 treats participants as fully trusted and assumes hashes belong to
//! valid messages. Fingerprints leak the XOR of hashes in a range. Item sets
//! leak every [`SyncId`] in a differing range. A peer can Skip or invent IDs.
//! Use an authenticated channel.
//!
//! ## Codec
//!
//! [`codec::encode`] / [`codec::decode`] implement LIP LEB128 + range deltas.
//! The first range’s lower **timestamp** is written explicitly (Nwaku). The
//! LIP text that the first lower bound is `SyncID(0, 0)` would drop a sliding
//! window start; this crate does not do that. There is no libp2p length prefix.

pub use bounds::RangeBounds;
pub use codec::{decode, encode};
pub use config::ReconcileConfig;
pub use error::{ReconcileError, Result};
pub use id::{SyncId, EMPTY_HASH, FULL_HASH};
pub use range::{ItemSet, Range, RangeContent, RangeType, RangesData, SyncScope};
pub use session::{ReconcileResult, ReconcileRound, ReconcileSession};
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
        let (ar, br) = run_pair(&alice, &bob, bounds, SyncScope::any()).unwrap();
        assert_eq!(ar.to_send.len(), 50);
        assert_eq!(ar.to_recv.len(), 50);
        assert_eq!(ar.to_send, br.to_recv);
        assert_eq!(ar.to_recv, br.to_send);
    }
}
