//! Message types exchanged between PSI protocol parties.

use crate::error::{PsiError, Result};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;

/// Message containing blinded points sent to remote party.
///
/// This message is sent from one party to another after the
/// initialization phase. It contains ONLY blinded Ristretto points
/// for all items in the sender's set - no hashes are included.
/// This improves privacy by not revealing any hash information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedPointsMessage {
    /// Blinded points for each item (no hashes included)
    pub blinded_points: Vec<CompressedRistretto>,
}

impl BlindedPointsMessage {
    /// Create a new blinded points message.
    ///
    /// # Arguments
    /// * `blinded_points` - Vector of blinded points
    ///
    /// # Returns
    /// A new `BlindedPointsMessage` instance
    pub fn new(blinded_points: Vec<CompressedRistretto>) -> Self {
        Self { blinded_points }
    }

    /// Create a new blinded points message, validating that it's not empty.
    ///
    /// # Arguments
    /// * `blinded_points` - Vector of blinded points
    ///
    /// # Returns
    /// A new `BlindedPointsMessage` instance
    ///
    /// # Errors
    /// Returns `PsiError::InvalidBlindedPoints` if the vector is empty.
    pub fn new_validated(blinded_points: Vec<CompressedRistretto>) -> Result<Self> {
        if blinded_points.is_empty() {
            return Err(PsiError::InvalidBlindedPoints(
                "Blinded points vector cannot be empty".to_string(),
            ));
        }
        Ok(Self { blinded_points })
    }

    /// Returns the number of items in this message.
    pub fn len(&self) -> usize {
        self.blinded_points.len()
    }

    /// Returns true if this message contains no items.
    pub fn is_empty(&self) -> bool {
        self.blinded_points.is_empty()
    }
}

/// Message containing double-blinded points sent to remote party.
///
/// This message is sent after receiving the remote's single-blinded points.
/// It contains the double-blinded Ristretto points for all items that were
/// received from the remote party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleBlindedPointsMessage {
    /// Double-blinded points computed from remote's single-blinded points
    pub double_blinded_points: Vec<CompressedRistretto>,
}

impl DoubleBlindedPointsMessage {
    /// Create a new double-blinded points message.
    ///
    /// # Arguments
    /// * `double_blinded_points` - Vector of double-blinded points
    ///
    /// # Returns
    /// A new `DoubleBlindedPointsMessage` instance
    pub fn new(double_blinded_points: Vec<CompressedRistretto>) -> Self {
        Self { double_blinded_points }
    }

    /// Returns the number of items in this message.
    pub fn len(&self) -> usize {
        self.double_blinded_points.len()
    }

    /// Returns true if this message contains no items.
    pub fn is_empty(&self) -> bool {
        self.double_blinded_points.is_empty()
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
        let blinded_points = vec![CompressedRistretto([0u8; 32])];
        let msg = BlindedPointsMessage::new(blinded_points.clone());
        assert_eq!(msg.blinded_points, blinded_points);
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
        let blinded_points = vec![CompressedRistretto([0u8; 32])];
        let msg = BlindedPointsMessage::new_validated(blinded_points.clone());
        assert!(msg.is_ok());
        assert_eq!(msg.unwrap().blinded_points, blinded_points);
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

    #[test]
    fn test_double_blinded_points_message_new() {
        let double_blinded_points = vec![CompressedRistretto([0u8; 32])];
        let msg = DoubleBlindedPointsMessage::new(double_blinded_points.clone());
        assert_eq!(msg.double_blinded_points, double_blinded_points);
        assert_eq!(msg.len(), 1);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_double_blinded_points_message_empty() {
        let msg = DoubleBlindedPointsMessage::new(vec![]);
        assert_eq!(msg.len(), 0);
        assert!(msg.is_empty());
    }
}
