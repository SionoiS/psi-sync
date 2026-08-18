//! # Private Set Intersection (PSI) Protocol
//!
//! Two-party ECDH private set intersection on the Ristretto group
//! (`curve25519-dalek`). Honest peers learn the SHA-512/256 identifiers of
//! items they both hold, and nothing about the rest of each other's sets.
//!
//! ## Features
//!
//! - **Transport agnostic**: the crate does not send bytes. You serialize and
//!   exchange the two message types on any channel.
//! - **Serialization agnostic**: messages are plain structs. The wire form of
//!   a point is [`CompressedRistretto::to_bytes`](curve25519_dalek::ristretto::CompressedRistretto::to_bytes)
//!   (`[u8; 32]`).
//! - **Symmetric API**: both parties call the same methods. There is no
//!   client/server role.
//! - **Type-state**: `compute` is only available before `finalize`; invalid
//!   sequencing does not compile.
//!
//! ## Protocol
//!
//! Both parties follow the same two network rounds:
//!
//! 1. **Prepare** (local): [`PsiProtocol::new`] hashes items, maps them to
//!    the curve with DST `psi-sync/v1`, and blinds them.
//! 2. **Round 1**: exchange [`BlindedPointsMessage`] (`message()`).
//! 3. **Double-blind** (local): [`PsiProtocol::compute`] multiplies the
//!    peer's points by the local secret.
//! 4. **Round 2**: exchange [`DoubleBlindedPointsMessage`]. **Order must be
//!    preserved** — each returned point corresponds to the received point at
//!    the same index.
//! 5. **Finalize** (local): [`PsiProtocol<DoubleBlindedState>::finalize`]
//!    returns a [`PsiResult`].
//!
//! ## Example
//!
//! ```
//! use psi::PsiProtocol;
//!
//! let alice_items = vec![b"apple".to_vec(), b"banana".to_vec()];
//! let bob_items = vec![b"banana".to_vec(), b"cherry".to_vec()];
//!
//! let alice = PsiProtocol::new(&alice_items)?;
//! let bob = PsiProtocol::new(&bob_items)?;
//!
//! let alice_msg = alice.message();
//! let bob_msg = bob.message();
//!
//! let (alice_mid, alice_double) = alice.compute(bob_msg)?;
//! let (bob_mid, bob_double) = bob.compute(alice_msg)?;
//!
//! let alice_result = alice_mid.finalize(bob_double)?;
//! let bob_result = bob_mid.finalize(alice_double)?;
//!
//! assert_eq!(alice_result.len(), 1);
//! assert_eq!(bob_result.len(), 1);
//! # Ok::<(), psi::PsiError>(())
//! ```
//!
//! Map result identifiers back to local items with [`hash_bytes`]:
//!
//! ```
//! use psi::hash_bytes;
//!
//! let item = b"banana";
//! let id = hash_bytes(item);
//! assert_eq!(id.len(), 32);
//! ```
//!
//! ## Threat model
//!
//! This protocol is **honest-but-curious** (semi-honest):
//!
//! - The channel must be **authenticated, confidential, and order-preserving**
//!   (for example TLS). A MITM that reorders the second message can cause a
//!   party to attribute the intersection to the wrong local items.
//! - Set **sizes leak** (message lengths).
//! - A **malicious peer can lie** about its set and about the second message.
//!   There are no proofs of correct computation.
//! - Intersection membership comparison is not constant-time.
//!
//! ## Re-exports
//!
//! The public types are [`PsiProtocol`], [`PsiState`], [`PreparedState`],
//! [`DoubleBlindedState`], the two message structs, [`PsiResult`],
//! [`PsiError`], [`hash_bytes`], and [`MAX_ITEMS`].

pub use crypto::hash_bytes;
pub use error::{PsiError, Result};
pub use messages::{BlindedPointsMessage, DoubleBlindedPointsMessage, PsiResult};
pub use protocol::{PsiProtocol, MAX_ITEMS};
pub use state::{DoubleBlindedState, PreparedState, PsiState};

mod crypto;
mod error;
mod messages;
mod protocol;
mod state;

/// Integration tests for the full PSI protocol.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::collections::HashSet;

    fn random_topic_hash(rng: &mut OsRng) -> [u8; 32] {
        let mut array = [0u8; 32];
        rng.fill_bytes(&mut array);
        array
    }

    fn run(alice_items: &[Vec<u8>], bob_items: &[Vec<u8>]) -> (PsiResult, PsiResult) {
        let alice = PsiProtocol::new(alice_items).unwrap();
        let bob = PsiProtocol::new(bob_items).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (bob_mid, bob_double) = bob.compute(alice_msg).unwrap();

        let alice_result = alice_mid.finalize(bob_double).unwrap();
        let bob_result = bob_mid.finalize(alice_double).unwrap();
        (alice_result, bob_result)
    }

    #[test]
    fn test_full_protocol_with_intersection() {
        let mut rng = OsRng;
        let mut alice_items = Vec::new();
        let mut bob_items = Vec::new();

        for _ in 0..90 {
            alice_items.push(random_topic_hash(&mut rng).to_vec());
            bob_items.push(random_topic_hash(&mut rng).to_vec());
        }

        for _ in 0..10 {
            let common = random_topic_hash(&mut rng).to_vec();
            alice_items.push(common.clone());
            bob_items.push(common);
        }

        let (alice_result, bob_result) = run(&alice_items, &bob_items);

        assert_eq!(alice_result.len(), 10);
        assert_eq!(bob_result.len(), 10);

        let alice_set: HashSet<_> = alice_result.intersection_hashes.into_iter().collect();
        let bob_set: HashSet<_> = bob_result.intersection_hashes.into_iter().collect();
        assert_eq!(alice_set, bob_set);

        assert_eq!(alice_result.double_blinded_map.len(), 10);
        assert_eq!(bob_result.double_blinded_map.len(), 10);
    }

    #[test]
    fn test_full_protocol_no_intersection() {
        let (alice_result, bob_result) = run(
            &[b"apple".to_vec(), b"banana".to_vec()],
            &[b"cherry".to_vec(), b"date".to_vec()],
        );

        assert_eq!(alice_result.len(), 0);
        assert_eq!(bob_result.len(), 0);
    }

    #[test]
    fn test_full_protocol_single_item_intersection() {
        let common_item = b"common".to_vec();
        let (alice_result, bob_result) = run(
            &[b"alice_only".to_vec(), common_item.clone()],
            &[b"bob_only".to_vec(), common_item],
        );

        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }
}
