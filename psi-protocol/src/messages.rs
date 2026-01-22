//! Message types exchanged between PSI protocol peers.

use crate::error::{PsiError, Result};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;

/// Message containing blinded points sent to peer.
///
/// This message is sent from one peer to another after the
/// `prepare_blinded_points` phase. It contains pairs of hashes
/// and blinded Ristretto points for all items in the sender's set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedPointsMessage {
    /// Pairs of (hash, blinded_point) for each item
    pub items: Vec<([u8; 32], CompressedRistretto)>,
}

impl BlindedPointsMessage {
    /// Create a new blinded points message.
    ///
    /// # Arguments
    /// * `items` - Vector of (hash, blinded_point) pairs
    ///
    /// # Returns
    /// A new `BlindedPointsMessage` instance
    pub fn new(items: Vec<([u8; 32], CompressedRistretto)>) -> Self {
        Self { items }
    }

    /// Create a new blinded points message, validating that it's not empty.
    ///
    /// # Arguments
    /// * `items` - Vector of (hash, blinded_point) pairs
    ///
    /// # Returns
    /// A new `BlindedPointsMessage` instance
    ///
    /// # Errors
    /// Returns `PsiError::InvalidBlindedPoints` if the vector is empty.
    pub fn new_validated(items: Vec<([u8; 32], CompressedRistretto)>) -> Result<Self> {
        if items.is_empty() {
            return Err(PsiError::InvalidBlindedPoints(
                "Blinded points vector cannot be empty".to_string(),
            ));
        }
        Ok(Self { items })
    }

    /// Returns the number of items in this message.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if this message contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get just the blinded points (without hashes).
    pub fn blinded_points(&self) -> Vec<CompressedRistretto> {
        self.items.iter().map(|(_, point)| *point).collect()
    }
}

/// Final result of the PSI protocol.
///
/// Contains the intersection of the two private sets and a mapping
/// from intersection hashes to their double-blinded point representations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsiResult {
    /// Hashes of elements in the intersection
    pub intersection_hashes: Vec<[u8; 32]>,
    /// Double-blinded points mapped to intersection hashes
    pub double_blinded_map: HashMap<[u8; 32], CompressedRistretto>,
}

impl PsiResult {
    /// Create a new PSI result.
    ///
    /// # Arguments
    /// * `intersection_hashes` - Hashes of elements in the intersection
    /// * `double_blinded_map` - Mapping from intersection hashes to double-blinded points
    pub fn new(
        intersection_hashes: Vec<[u8; 32]>,
        double_blinded_map: HashMap<[u8; 32], CompressedRistretto>,
    ) -> Self {
        Self {
            intersection_hashes,
            double_blinded_map,
        }
    }

    /// Returns the number of elements in the intersection.
    pub fn len(&self) -> usize {
        self.intersection_hashes.len()
    }

    /// Returns true if the intersection is empty.
    pub fn is_empty(&self) -> bool {
        self.intersection_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blinded_points_message_new() {
        let items = vec![([1u8; 32], CompressedRistretto([0u8; 32]))];
        let msg = BlindedPointsMessage::new(items.clone());
        assert_eq!(msg.items, items);
        assert_eq!(msg.len(), 1);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_blinded_points_message_empty() {
        let msg = BlindedPointsMessage::new(vec![]);
        assert_eq!(msg.len(), 0);
        assert!(msg.is_empty());
    }

    #[test]
    fn test_blinded_points_message_validated() {
        let items = vec![([1u8; 32], CompressedRistretto([0u8; 32]))];
        let msg = BlindedPointsMessage::new_validated(items.clone());
        assert!(msg.is_ok());
        assert_eq!(msg.unwrap().items, items);
    }

    #[test]
    fn test_blinded_points_message_validated_empty() {
        let msg = BlindedPointsMessage::new_validated(vec![]);
        assert!(msg.is_err());
        assert_eq!(msg.unwrap_err(), PsiError::InvalidBlindedPoints(
            "Blinded points vector cannot be empty".to_string()
        ));
    }

    #[test]
    fn test_psi_result() {
        let hash = [1u8; 32];
        let point = CompressedRistretto([0u8; 32]);
        let mut map = HashMap::new();
        map.insert(hash, point);

        let result = PsiResult::new(vec![hash], map.clone());
        assert_eq!(result.len(), 1);
        assert!(!result.is_empty());
        assert_eq!(result.intersection_hashes, vec![hash]);
        assert_eq!(result.double_blinded_map, map);
    }

    #[test]
    fn test_psi_result_empty() {
        let result = PsiResult::new(vec![], HashMap::new());
        assert_eq!(result.len(), 0);
        assert!(result.is_empty());
    }
}
