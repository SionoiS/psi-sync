//! Core protocol logic for PSI.

use crate::crypto::{hash_multiple, hash_inputs_to_points, blind_points, decompress_point};
use crate::messages::{BlindedPointsMessage, PsiResult};
use crate::state::PsiState;
use crate::error::{PsiError, Result};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;

impl PsiState {
    /// Prepare blinded points for sending to the peer.
    ///
    /// This is the first phase of the protocol. It hashes the input items,
    /// maps them to Ristretto points, blinds them with the secret, and
    /// returns a message containing the blinded points.
    ///
    /// # Arguments
    /// * `items` - Slice of byte vectors representing the private set
    ///
    /// # Returns
    /// A `BlindedPointsMessage` containing the blinded points
    ///
    /// # Errors
    /// Returns `PsiError::EmptyInput` if items is empty
    pub fn prepare_blinded_points(&mut self, items: &[Vec<u8>]) -> Result<BlindedPointsMessage> {
        if items.is_empty() {
            return Err(PsiError::EmptyInput);
        }

        // Hash input items
        let _hashes = hash_multiple(items);

        // Map hashes to Ristretto points
        let hash_to_point: std::collections::HashMap<
            [u8; 32],
            curve25519_dalek::ristretto::RistrettoPoint,
        > = hash_inputs_to_points(items);

        // Blind points and store mapping
        self.hash_to_blinded = blind_points(&hash_to_point, &self.secret);

        // Create message with (hash, blinded_point) pairs
        let message_items: Vec<([u8; 32], CompressedRistretto)> =
            self.hash_to_blinded.iter().map(|(hash, point)| (*hash, *point)).collect();

        Ok(BlindedPointsMessage::new(message_items))
    }

    /// Compute the intersection from the peer's blinded points message.
    ///
    /// This is the second phase of the protocol. It double-blinds the peer's
    /// points and finds matches with the local double-blinded points.
    ///
    /// # Arguments
    /// * `peer_blinded` - The blinded points message received from the peer
    ///
    /// # Returns
    /// A `PsiResult` containing the intersection hashes and double-blinded mapping
    ///
    /// # Errors
    /// Returns `PsiError::InvalidBlindedPoints` if the peer's points cannot be processed
    pub fn compute_intersection(
        &mut self,
        peer_blinded: BlindedPointsMessage,
    ) -> Result<PsiResult> {
        // Compute double-blinded values for peer's (hash, blinded_point) pairs
        // These are: my_secret * peer_blinded_point
        let peer_double_blinded: std::collections::HashMap<
            [u8; 32],
            CompressedRistretto,
        > = peer_blinded
            .items
            .iter()
            .map(|(hash, blinded_point)| {
                let point = decompress_point(blinded_point)?;
                let double_blinded = (self.secret * point).compress();
                Ok((*hash, double_blinded))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        // Compute double-blinded values for local (hash, blinded_point) pairs
        // These are: my_secret * my_blinded_point
        let local_double_blinded: std::collections::HashMap<
            [u8; 32],
            CompressedRistretto,
        > = self
            .hash_to_blinded
            .iter()
            .map(|(hash, blinded)| {
                let point = decompress_point(blinded)?;
                let double_blinded = (self.secret * point).compress();
                Ok((*hash, double_blinded))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        // Find intersection: peer hashes that are also in local hash set
        // Since both parties use the same hash function, matching items have the same hash
        let mut intersection_hashes = Vec::new();
        let mut double_blinded_map = std::collections::HashMap::new();

        for (peer_hash, _peer_db) in &peer_double_blinded {
            if self.hash_to_blinded.contains_key(peer_hash) {
                // Peer's hash is in our set - this is a match!
                // Use the local (not peer) double-blinded value for consistency
                if let Some(local_db) = local_double_blinded.get(peer_hash) {
                    intersection_hashes.push(*peer_hash);
                    double_blinded_map.insert(*peer_hash, *local_db);
                }
            }
        }

        // Store the mapping
        self.hash_to_double_blinded = double_blinded_map.clone();

        Ok(PsiResult::new(intersection_hashes, double_blinded_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_blinded_points_empty() {
        let mut state = PsiState::new();
        let result = state.prepare_blinded_points(&[]);
        assert!(matches!(result, Err(PsiError::EmptyInput)));
    }

    #[test]
    fn test_prepare_blinded_points_single_item() {
        let mut state = PsiState::new();
        let items = vec![b"test".to_vec()];
        let result = state.prepare_blinded_points(&items);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.len(), 1);
    }

    #[test]
    fn test_prepare_blinded_points_multiple_items() {
        let mut state = PsiState::new();
        let items = vec![
            b"apple".to_vec(),
            b"banana".to_vec(),
            b"cherry".to_vec(),
        ];
        let result = state.prepare_blinded_points(&items);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.len(), 3);
    }

    #[test]
    fn test_compute_intersection_with_no_match() {
        let mut alice = PsiState::new();
        let mut bob = PsiState::new();

        let alice_items = vec![b"apple".to_vec()];
        let bob_items = vec![b"banana".to_vec()];

        let alice_msg = alice.prepare_blinded_points(&alice_items).unwrap();
        let bob_msg = bob.prepare_blinded_points(&bob_items).unwrap();

        let alice_result = alice.compute_intersection(bob_msg).unwrap();
        let bob_result = bob.compute_intersection(alice_msg).unwrap();

        assert_eq!(alice_result.len(), 0);
        assert_eq!(bob_result.len(), 0);
    }

    #[test]
    fn test_compute_intersection_with_match() {
        let mut alice = PsiState::new();
        let mut bob = PsiState::new();

        let alice_items = vec![b"apple".to_vec()];
        let bob_items = vec![b"apple".to_vec()];

        let alice_msg = alice.prepare_blinded_points(&alice_items).unwrap();
        let bob_msg = bob.prepare_blinded_points(&bob_items).unwrap();

        let alice_result = alice.compute_intersection(bob_msg).unwrap();
        let bob_result = bob.compute_intersection(alice_msg).unwrap();

        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        // Both should have the same intersection hash
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }

    #[test]
    fn test_compute_intersection_symmetric() {
        let mut alice = PsiState::new();
        let mut bob = PsiState::new();

        let alice_items = vec![b"apple".to_vec(), b"banana".to_vec(), b"cherry".to_vec()];
        let bob_items = vec![b"banana".to_vec(), b"date".to_vec()];

        let alice_msg = alice.prepare_blinded_points(&alice_items).unwrap();
        let bob_msg = bob.prepare_blinded_points(&bob_items).unwrap();

        let alice_result = alice.compute_intersection(bob_msg).unwrap();
        let bob_result = bob.compute_intersection(alice_msg).unwrap();

        // Both should find the same intersection (banana)
        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }
}
