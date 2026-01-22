//! # Private Set Intersection (PSI) Protocol
//!
//! This library implements Private Set Intersection (PSI) using Elliptic Curve
//! Diffie-Hellman (ECDH) on the Ristretto group (curve25519-dalek).
//!
//! The protocol allows two parties (Alice and Bob) to compute the intersection
//! of their private sets without revealing any additional information about
//! non-intersecting elements.
//!
//! ## Features
//!
//! - **Transport Agnostic**: The library handles the protocol logic but leaves
//!   message exchange to the user, allowing integration with any transport layer.
//! - **Serialization Agnostic**: Message types are plain Rust structs; users
//!   choose their preferred serialization format (e.g., JSON, bincode, CBOR).
//! - **Symmetric API**: Both parties use the same API; no distinction
//!   between client and server.
//! - **Input as Byte Arrays**: Accepts `Vec<u8>` as input, handling hashing
//!   internally.
//! - **Type-State Pattern**: Uses Rust's type system to enforce valid protocol
//!   transitions at compile time.
//!
//! ## Protocol Overview
//!
//! Both parties follow identical steps:
//!
//! 1. **Initialize**: Create a `PsiProtocol` with items - this performs all
//!    cryptographic setup (hashing, blinding) in one call.
//!
//! 2. **Exchange Phase** (user-handled): Exchange blinded points via the
//!    preferred transport (e.g., TCP, HTTP, in-memory). In production, use TLS.
//!
//! 3. **Compute Phase**: Compute intersection with remote's message, returning
//!    the results as a `PsiResult`.
//!
//! ## Example Usage
//!
//! ```ignore
//! use psi_protocol::{PsiProtocol, PsiError};
//!
//! // Alice's side - start with items
//! let alice_items = vec![b"apple".to_vec(), b"banana".to_vec()];
//! let alice = PsiProtocol::new(&alice_items)?;
//!
//! // Bob's side - start with items
//! let bob_items = vec![b"banana".to_vec(), b"cherry".to_vec()];
//! let bob = PsiProtocol::new(&bob_items)?;
//!
//! // Exchange messages (via user's transport)
//! let alice_msg = alice.message();
//! let bob_msg = bob.message();
//! // send_to_remote(alice_msg);
//! // let bob_received = receive_from_remote();
//!
//! // Compute intersection
//! let (_alice_final, alice_result) = alice.compute(bob_msg)?;
//! let (_bob_final, bob_result) = bob.compute(alice_msg)?;
//!
//! // Both get the same intersection
//! assert_eq!(alice_result.intersection_hashes, bob_result.intersection_hashes);
//! # Ok::<(), PsiError>(())
//! ```
//!
//! ## Security Considerations
//!
//! - The exchange of blinded points (Step 2) MUST be secured with TLS in
//!   production to prevent man-in-the-middle attacks.
//! - Only elements in the intersection are revealed to both parties.
//! - Blinded points leak no information about underlying elements.
//!
//! ## Modules
//!
//! - [`messages`] - Message types for protocol exchange
//! - [`protocol`] - Core protocol implementation
//! - [`state`] - Protocol state types (type-state pattern)
//! - [`crypto`] - Cryptographic operations
//! - [`error`] - Error types

pub use messages::{BlindedPointsMessage, DoubleBlindedPointsMessage, PsiResult};
pub use protocol::PsiProtocol;
pub use state::{PsiState, PreparedState, DoubleBlindedState, FinalState};
pub use error::{PsiError, Result};

mod crypto;
mod error;
mod messages;
mod protocol;
mod state;

/// Integration tests for the full PSI protocol.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use rand::RngCore;
    use rand::rngs::OsRng;

    fn random_topic_hash(rng: &mut rand::rngs::OsRng) -> [u8; 32] {
        let mut array = [0u8; 32];
        rng.fill_bytes(&mut array);
        array
    }

    #[test]
    fn test_full_protocol_with_intersection() {
        // Create test data: 90 unique each, 10 common
        let mut rng = OsRng;
        let mut alice_items = Vec::new();
        let mut bob_items = Vec::new();

        for _ in 0..90 {
            alice_items.push(random_topic_hash(&mut rng).to_vec());
            bob_items.push(random_topic_hash(&mut rng).to_vec());
        }

        // Add 10 common items
        for _ in 0..10 {
            let common = random_topic_hash(&mut rng).to_vec();
            alice_items.push(common.clone());
            bob_items.push(common);
        }

        // Execute protocol
        let alice = PsiProtocol::new(&alice_items).unwrap();
        let bob = PsiProtocol::new(&bob_items).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg).unwrap();
        let (bob_intermediate, bob_double_msg) = bob.compute(alice_msg).unwrap();

        let (_alice_final, alice_result) = alice_intermediate.finalize(bob_double_msg).unwrap();
        let (_bob_final, bob_result) = bob_intermediate.finalize(alice_double_msg).unwrap();

        // Verify results
        assert_eq!(alice_result.len(), 10);
        assert_eq!(bob_result.len(), 10);

        // Convert to sets for comparison (order may differ)
        let alice_set: std::collections::HashSet<_> = alice_result.intersection_hashes.into_iter().collect();
        let bob_set: std::collections::HashSet<_> = bob_result.intersection_hashes.into_iter().collect();
        assert_eq!(alice_set, bob_set);

        assert_eq!(alice_result.double_blinded_map.len(), 10);
        assert_eq!(bob_result.double_blinded_map.len(), 10);
    }

    #[test]
    fn test_full_protocol_no_intersection() {
        let alice_items = vec![b"apple".to_vec(), b"banana".to_vec()];
        let bob_items = vec![b"cherry".to_vec(), b"date".to_vec()];

        let alice = PsiProtocol::new(&alice_items).unwrap();
        let bob = PsiProtocol::new(&bob_items).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg).unwrap();
        let (bob_intermediate, bob_double_msg) = bob.compute(alice_msg).unwrap();

        let (_alice_final, alice_result) = alice_intermediate.finalize(bob_double_msg).unwrap();
        let (_bob_final, bob_result) = bob_intermediate.finalize(alice_double_msg).unwrap();

        assert_eq!(alice_result.len(), 0);
        assert_eq!(bob_result.len(), 0);
    }

    #[test]
    fn test_full_protocol_single_item_intersection() {
        let common_item = b"common".to_vec();
        let alice_items = vec![b"alice_only".to_vec(), common_item.clone()];
        let bob_items = vec![b"bob_only".to_vec(), common_item];

        let alice = PsiProtocol::new(&alice_items).unwrap();
        let bob = PsiProtocol::new(&bob_items).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg).unwrap();
        let (bob_intermediate, bob_double_msg) = bob.compute(alice_msg).unwrap();

        let (_alice_final, alice_result) = alice_intermediate.finalize(bob_double_msg).unwrap();
        let (_bob_final, bob_result) = bob_intermediate.finalize(alice_double_msg).unwrap();

        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }
}
