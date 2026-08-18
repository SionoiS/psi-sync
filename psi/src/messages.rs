//! Message types exchanged between PSI protocol parties.

use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;

/// First-round message: this party's blinded points.
///
/// Contains only compressed Ristretto points — no item identifiers.
/// **Order is significant.** The peer must double-blind these points and
/// return them in the same order so this party can map matches back to items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedPointsMessage {
    /// Blinded points for each distinct local item.
    pub blinded_points: Vec<CompressedRistretto>,
}

impl BlindedPointsMessage {
    /// Create a new blinded points message. Empty is allowed (empty set).
    pub fn new(blinded_points: Vec<CompressedRistretto>) -> Self {
        Self { blinded_points }
    }

    /// Number of points in this message.
    pub fn len(&self) -> usize {
        self.blinded_points.len()
    }

    /// True if this message contains no points.
    pub fn is_empty(&self) -> bool {
        self.blinded_points.is_empty()
    }
}

/// Second-round message: double-blinded points computed from the peer's
/// first-round message.
///
/// **Order is significant.** These points must correspond 1:1, in order, to
/// the blinded points received from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleBlindedPointsMessage {
    /// Double-blinded points computed from the remote party's first message.
    pub double_blinded_points: Vec<CompressedRistretto>,
}

impl DoubleBlindedPointsMessage {
    /// Create a new double-blinded points message. Empty is allowed.
    pub fn new(double_blinded_points: Vec<CompressedRistretto>) -> Self {
        Self {
            double_blinded_points,
        }
    }

    /// Number of points in this message.
    pub fn len(&self) -> usize {
        self.double_blinded_points.len()
    }

    /// True if this message contains no points.
    pub fn is_empty(&self) -> bool {
        self.double_blinded_points.is_empty()
    }
}

/// Final result of the PSI protocol.
///
/// Identifiers are [`crate::hash_bytes`] outputs, not the original items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsiResult {
    /// Hashes of elements in the intersection.
    pub intersection_hashes: Vec<[u8; 32]>,
    /// Double-blinded points mapped to intersection hashes.
    pub double_blinded_map: HashMap<[u8; 32], CompressedRistretto>,
}

impl PsiResult {
    /// Create a new PSI result.
    pub fn new(
        intersection_hashes: Vec<[u8; 32]>,
        double_blinded_map: HashMap<[u8; 32], CompressedRistretto>,
    ) -> Self {
        Self {
            intersection_hashes,
            double_blinded_map,
        }
    }

    /// Number of elements in the intersection.
    pub fn len(&self) -> usize {
        self.intersection_hashes.len()
    }

    /// True if the intersection is empty.
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
