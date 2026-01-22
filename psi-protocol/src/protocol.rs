//! Core protocol implementation using the type-state pattern.

use crate::crypto::{decompress_point, hash_inputs_to_points, blind_points};
use crate::messages::{BlindedPointsMessage, DoubleBlindedPointsMessage, PsiResult};
use crate::state::{PsiState, PreparedState, DoubleBlindedState, FinalState};
use crate::error::{PsiError, Result};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;

/// Protocol wrapper that holds the current state.
///
/// This generic wrapper enforces type-level state tracking - each state
/// has different available methods, preventing invalid operations.
#[derive(Debug)]
pub struct PsiProtocol<S: PsiState> {
    state: S,
}

impl PsiProtocol<PreparedState> {
    /// Create a new protocol instance from items.
    ///
    /// This performs ALL initial setup in one call:
    /// - Generates random secret scalar
    /// - Hashes all items
    /// - Blinds points with the secret
    ///
    /// # Arguments
    /// * `items` - Slice of byte vectors representing the private set
    ///
    /// # Returns
    /// A `PsiProtocol<PreparedState>` ready for message exchange
    ///
    /// # Errors
    /// Returns `PsiError::EmptyInput` if items is empty
    ///
    /// # Example
    /// ```ignore
    /// use psi_protocol::PsiProtocol;
    ///
    /// let items = vec![b"apple".to_vec(), b"banana".to_vec()];
    /// let alice = PsiProtocol::new(&items)?;
    /// # Ok::<(), psi_protocol::PsiError>(())
    /// ```
    pub fn new(items: &[Vec<u8>]) -> Result<Self> {
        if items.is_empty() {
            return Err(PsiError::EmptyInput);
        }

        let secret = crate::crypto::random_scalar();
        let hash_to_point = hash_inputs_to_points(items);
        let hash_to_blinded = blind_points(&hash_to_point, &secret);

        // Build reverse mapping from blinded point to hash
        let blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]> =
            hash_to_blinded.iter()
                .map(|(hash, point)| (*point, *hash))
                .collect();

        // Track the order of hashes (consistent with blinded_points iteration)
        let hash_order: Vec<[u8; 32]> = hash_to_blinded.keys().copied().collect();

        Ok(Self {
            state: PreparedState::new(secret, hash_to_blinded, blinded_to_hash, hash_order),
        })
    }

    /// Get the blinded points message for exchange with remote party.
    ///
    /// Returns a message containing only blinded points (no hashes)
    /// that should be sent to the remote party.
    ///
    /// # Returns
    /// A `BlindedPointsMessage` ready to be serialized and sent
    ///
    /// # Example
    /// ```ignore
    /// let alice = PsiProtocol::new(&items)?;
    /// let alice_msg = alice.message();
    /// // send_to_remote(alice_msg);
    /// ```
    pub fn message(&self) -> BlindedPointsMessage {
        // Use hash_order to ensure consistent ordering
        let blinded_points: Vec<CompressedRistretto> = self.state
            .hash_order()
            .iter()
            .map(|hash| *self.state.blinded_map().get(hash).unwrap())
            .collect();
        BlindedPointsMessage::new(blinded_points)
    }

    /// Compute double-blinded points from remote's single-blinded points.
    ///
    /// This consumes the `PsiProtocol<PreparedState>` and returns:
    /// - `PsiProtocol<DoubleBlindedState>` - intermediate state ready for finalization
    /// - `DoubleBlindedPointsMessage` - message to send to remote party
    ///
    /// # Arguments
    /// * `remote_msg` - The blinded points message received from the remote party
    ///
    /// # Returns
    /// A tuple of (PsiProtocol<DoubleBlindedState>, DoubleBlindedPointsMessage)
    ///
    /// # Errors
    /// Returns `PsiError::InvalidBlindedPoints` if remote's points cannot be processed
    ///
    /// # Example
    /// ```ignore
    /// let alice = PsiProtocol::new(&items)?;
    /// let alice_msg = alice.message();
    /// let bob_msg = receive_from_remote();
    ///
    /// let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg)?;
    /// // Exchange alice_double_msg with remote
    /// # Ok::<(), psi_protocol::PsiError>(())
    /// ```
    pub fn compute(
        self,
        remote_msg: BlindedPointsMessage,
    ) -> Result<(PsiProtocol<DoubleBlindedState>, DoubleBlindedPointsMessage)> {
        // Compute double-blinded values from remote's single-blinded points
        // These are: my_secret * remote_blinded_point
        // This will be sent back to the remote party
        let double_blinded_to_send: Vec<CompressedRistretto> = remote_msg
            .blinded_points
            .iter()
            .map(|blinded_point| {
                let point = decompress_point(blinded_point)?;
                Ok((self.state.secret_scalar() * point).compress())
            })
            .collect::<Result<Vec<_>>>()?;

        // Create double-blinded state with hash_order
        let double_blinded_state = DoubleBlindedState::new(
            *self.state.secret_scalar(),
            self.state.blinded_map().clone(),
            self.state.blinded_to_hash().clone(),
            double_blinded_to_send.clone(),
            self.state.hash_order().to_vec(),
        );

        // Create the message to send back to remote (contains double-blinded of remote's points)
        let message = DoubleBlindedPointsMessage::new(double_blinded_to_send);

        Ok((PsiProtocol { state: double_blinded_state }, message))
    }
}

impl PsiProtocol<DoubleBlindedState> {
    /// Finalize the protocol by computing the intersection from double-blinded points.
    ///
    /// This consumes the `PsiProtocol<DoubleBlindedState>` and returns:
    /// - `PsiProtocol<FinalState>` - the final state (cannot compute again)
    /// - `PsiResult` - the intersection results
    ///
    /// # Arguments
    /// * `remote_msg` - The double-blinded points message received from the remote party
    ///
    /// # Returns
    /// A tuple of (PsiProtocol<FinalState>, PsiResult)
    ///
    /// # Errors
    /// Returns `PsiError::InvalidBlindedPoints` if remote's points cannot be processed
    ///
    /// # Example
    /// ```ignore
    /// let alice = PsiProtocol::new(&items)?;
    /// let alice_msg = alice.message();
    /// let bob_msg = receive_from_remote();
    ///
    /// let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg)?;
    /// let (bob_intermediate, bob_double_msg) = bob.compute(alice_msg)?;
    ///
    /// // Exchange double-blinded messages
    /// let (_alice_final, alice_result) = alice_intermediate.finalize(bob_double_msg)?;
    /// let (_bob_final, bob_result) = bob_intermediate.finalize(alice_double_msg)?;
    /// # Ok::<(), psi_protocol::PsiError>(())
    /// ```
    pub fn finalize(
        self,
        remote_msg: DoubleBlindedPointsMessage,
    ) -> Result<(PsiProtocol<FinalState>, PsiResult)> {
        // Build a set of double-blinded points we computed from remote's single-blinded points
        // These are: a*(b*K) for each of Bob's items (where K is Bob's hash)
        let computed_double_blinded_set: std::collections::HashSet<CompressedRistretto> =
            self.state.double_blinded_from_remote().iter().cloned().collect();

        // The received double-blinded points are: b*(a*H) for each of our items (in order)
        // For each received point at index i, check if it matches any of our computed points
        let mut intersection_hashes = Vec::new();
        let mut double_blinded_map = HashMap::new();

        for (index, remote_double_blinded) in remote_msg.double_blinded_points.iter().enumerate() {
            if computed_double_blinded_set.contains(remote_double_blinded) {
                // Found a match! This means a*(b*K) = b*(a*Hi) for some K, so Hi = K (common item)
                // The hash at this index is in the intersection
                if let Some(&hash) = self.state.hash_order().get(index) {
                    intersection_hashes.push(hash);
                    double_blinded_map.insert(hash, *remote_double_blinded);
                }
            }
        }

        // Create final state (secret is dropped)
        let final_state = FinalState::new(double_blinded_map.clone());
        let result = PsiResult::new(intersection_hashes, double_blinded_map);

        Ok((PsiProtocol { state: final_state }, result))
    }
}

impl PsiProtocol<FinalState> {
    /// Get the double-blinded mapping from the final state.
    ///
    /// This is useful for verification or debugging purposes.
    ///
    /// # Returns
    /// A reference to the HashMap mapping intersection hashes to double-blinded points
    #[cfg(test)]
    pub fn double_blinded_map(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        self.state.double_blinded_map()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_protocol_new_empty() {
        let result = PsiProtocol::new(&[]);
        assert!(matches!(result, Err(PsiError::EmptyInput)));
    }

    #[test]
    fn test_psi_protocol_new_single_item() {
        let items = vec![b"test".to_vec()];
        let result = PsiProtocol::new(&items);
        assert!(result.is_ok());
        let proto = result.unwrap();
        let msg = proto.message();
        assert_eq!(msg.len(), 1);
    }

    #[test]
    fn test_psi_protocol_new_multiple_items() {
        let items = vec![
            b"apple".to_vec(),
            b"banana".to_vec(),
            b"cherry".to_vec(),
        ];
        let result = PsiProtocol::new(&items);
        assert!(result.is_ok());
        let proto = result.unwrap();
        let msg = proto.message();
        assert_eq!(msg.len(), 3);
    }

    #[test]
    fn test_psi_protocol_compute_no_intersection() {
        let alice = PsiProtocol::new(&vec![b"apple".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&vec![b"banana".to_vec()]).unwrap();

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
    fn test_psi_protocol_compute_with_intersection() {
        let alice = PsiProtocol::new(&vec![b"apple".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&vec![b"apple".to_vec()]).unwrap();

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

    #[test]
    fn test_psi_protocol_compute_symmetric() {
        let alice = PsiProtocol::new(&vec![
            b"apple".to_vec(),
            b"banana".to_vec(),
            b"cherry".to_vec(),
        ]).unwrap();
        let bob = PsiProtocol::new(&vec![
            b"banana".to_vec(),
            b"date".to_vec(),
        ]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg).unwrap();
        let (bob_intermediate, bob_double_msg) = bob.compute(alice_msg).unwrap();

        let (_alice_final, alice_result) = alice_intermediate.finalize(bob_double_msg).unwrap();
        let (_bob_final, bob_result) = bob_intermediate.finalize(alice_double_msg).unwrap();

        // Both should find the same intersection (banana)
        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }

    #[test]
    fn test_psi_protocol_compute_drops_secret() {
        // This is a compile-time test - FinalState should not have access to secret
        let alice = PsiProtocol::new(&vec![b"test".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&vec![b"test".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_intermediate, alice_double_msg) = alice.compute(bob_msg).unwrap();
        let (bob_intermediate, bob_double_msg) = bob.compute(alice_msg).unwrap();

        let (alice_final, _alice_result) = alice_intermediate.finalize(bob_double_msg).unwrap();
        let _ = bob_intermediate;

        // The following should NOT compile - secret is not accessible in FinalState
        // let _secret = alice_final.state.secret; // This would be a compile error
        // But we can access the double-blinded map:
        let _map = alice_final.double_blinded_map();
    }
}
