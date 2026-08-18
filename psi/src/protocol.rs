//! Core protocol implementation using the type-state pattern.

use crate::crypto::{blind_points, decompress_point, hash_inputs_to_points};
use crate::error::{PsiError, Result};
use crate::messages::{BlindedPointsMessage, DoubleBlindedPointsMessage, PsiResult};
use crate::state::{DoubleBlindedState, PreparedState, PsiState};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;
use std::fmt;

/// Maximum number of distinct items in a local set or incoming message.
pub const MAX_ITEMS: usize = 1_048_576;

/// Reject sets larger than [`MAX_ITEMS`].
pub(crate) fn check_set_size(n: usize) -> Result<()> {
    if n > MAX_ITEMS {
        return Err(PsiError::SetTooLarge {
            size: n,
            max: MAX_ITEMS,
        });
    }
    Ok(())
}

/// Protocol wrapper that holds the current state.
///
/// Each state exposes different methods, so invalid transitions do not compile.
pub struct PsiProtocol<S: PsiState> {
    state: S,
}

impl<S: PsiState + fmt::Debug> fmt::Debug for PsiProtocol<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PsiProtocol")
            .field("state", &self.state)
            .finish()
    }
}

impl PsiProtocol<PreparedState> {
    /// Create a new protocol instance from items.
    ///
    /// This performs all initial setup in one call: generate a secret scalar,
    /// hash items to identifiers, map them to the curve, and blind the points.
    /// Duplicate items collapse (set semantics). An empty input is valid and
    /// produces an empty message; the intersection with any peer is empty.
    ///
    /// # Errors
    ///
    /// Returns [`PsiError::SetTooLarge`] if the number of distinct items exceeds
    /// [`MAX_ITEMS`].
    ///
    /// # Example
    ///
    /// ```
    /// use psi::PsiProtocol;
    ///
    /// let items = vec![b"apple".to_vec(), b"banana".to_vec()];
    /// let alice = PsiProtocol::new(&items)?;
    /// # Ok::<(), psi::PsiError>(())
    /// ```
    pub fn new(items: &[Vec<u8>]) -> Result<Self> {
        let hash_to_point = hash_inputs_to_points(items);
        check_set_size(hash_to_point.len())?;

        let secret = crate::crypto::random_scalar();
        let hash_to_blinded = blind_points(&hash_to_point, &secret);
        let hash_order: Vec<[u8; 32]> = hash_to_blinded.keys().copied().collect();

        Ok(Self {
            state: PreparedState::new(secret, hash_to_blinded, hash_order),
        })
    }

    /// Blinded points to send to the peer (no item identifiers).
    ///
    /// Order is significant: the peer must double-blind and return points in
    /// this same order.
    ///
    /// # Example
    ///
    /// ```
    /// use psi::PsiProtocol;
    ///
    /// let items = vec![b"apple".to_vec()];
    /// let alice = PsiProtocol::new(&items)?;
    /// let alice_msg = alice.message();
    /// assert_eq!(alice_msg.len(), 1);
    /// # Ok::<(), psi::PsiError>(())
    /// ```
    pub fn message(&self) -> BlindedPointsMessage {
        let blinded_points: Vec<CompressedRistretto> = self
            .state
            .hash_order()
            .iter()
            .map(|hash| {
                *self
                    .state
                    .blinded_map()
                    .get(hash)
                    .expect("hash_order/blinded_map invariant")
            })
            .collect();
        BlindedPointsMessage::new(blinded_points)
    }

    /// Double-blind the peer's first-round points.
    ///
    /// Consumes `PreparedState` and returns an intermediate protocol object
    /// plus the message to send back. The peer will `finalize` with that
    /// message.
    ///
    /// # Errors
    ///
    /// Returns [`PsiError::SetTooLarge`] if the peer sent more than
    /// [`MAX_ITEMS`] points, or [`PsiError::CryptoError`] if a point does not
    /// decompress.
    ///
    /// # Example
    ///
    /// ```
    /// use psi::PsiProtocol;
    ///
    /// let alice = PsiProtocol::new(&[b"apple".to_vec()])?;
    /// let bob = PsiProtocol::new(&[b"apple".to_vec()])?;
    /// let bob_msg = bob.message();
    /// let (_alice_mid, alice_double) = alice.compute(bob_msg)?;
    /// assert_eq!(alice_double.len(), 1);
    /// # Ok::<(), psi::PsiError>(())
    /// ```
    pub fn compute(
        self,
        remote_msg: BlindedPointsMessage,
    ) -> Result<(PsiProtocol<DoubleBlindedState>, DoubleBlindedPointsMessage)> {
        check_set_size(remote_msg.len())?;

        let double_blinded_to_send: Vec<CompressedRistretto> = remote_msg
            .blinded_points
            .iter()
            .map(|blinded_point| {
                let point = decompress_point(blinded_point)?;
                Ok((self.state.secret_scalar() * point).compress())
            })
            .collect::<Result<Vec<_>>>()?;

        let double_blinded_state = DoubleBlindedState::new(
            double_blinded_to_send.clone(),
            self.state.hash_order().to_vec(),
        );
        let message = DoubleBlindedPointsMessage::new(double_blinded_to_send);

        Ok((
            PsiProtocol {
                state: double_blinded_state,
            },
            message,
        ))
    }
}

impl PsiProtocol<DoubleBlindedState> {
    /// Compute the intersection from the peer's double-blinded points.
    ///
    /// `remote_msg` must contain exactly one point per item this party sent
    /// in the first message, in that same order.
    ///
    /// # Errors
    ///
    /// Returns [`PsiError::LengthMismatch`] if the message length does not
    /// equal the local set size.
    ///
    /// # Example
    ///
    /// ```
    /// use psi::PsiProtocol;
    ///
    /// let alice = PsiProtocol::new(&[b"apple".to_vec(), b"banana".to_vec()])?;
    /// let bob = PsiProtocol::new(&[b"banana".to_vec(), b"cherry".to_vec()])?;
    ///
    /// let alice_msg = alice.message();
    /// let bob_msg = bob.message();
    ///
    /// let (alice_mid, alice_double) = alice.compute(bob_msg)?;
    /// let (bob_mid, bob_double) = bob.compute(alice_msg)?;
    ///
    /// let alice_result = alice_mid.finalize(bob_double)?;
    /// let bob_result = bob_mid.finalize(alice_double)?;
    /// assert_eq!(alice_result.len(), 1);
    /// assert_eq!(bob_result.len(), 1);
    /// # Ok::<(), psi::PsiError>(())
    /// ```
    pub fn finalize(self, remote_msg: DoubleBlindedPointsMessage) -> Result<PsiResult> {
        let expected = self.state.hash_order().len();
        let actual = remote_msg.double_blinded_points.len();
        if actual != expected {
            return Err(PsiError::LengthMismatch { expected, actual });
        }

        let computed_double_blinded_set: std::collections::HashSet<CompressedRistretto> = self
            .state
            .double_blinded_from_remote()
            .iter()
            .cloned()
            .collect();

        let mut intersection_hashes = Vec::new();
        let mut double_blinded_map = HashMap::new();

        for (index, remote_double_blinded) in remote_msg.double_blinded_points.iter().enumerate() {
            if computed_double_blinded_set.contains(remote_double_blinded) {
                let hash = self.state.hash_order()[index];
                intersection_hashes.push(hash);
                double_blinded_map.insert(hash, *remote_double_blinded);
            }
        }

        Ok(PsiResult::new(intersection_hashes, double_blinded_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::DoubleBlindedPointsMessage;

    #[test]
    fn test_check_set_size() {
        assert!(check_set_size(0).is_ok());
        assert!(check_set_size(MAX_ITEMS).is_ok());
        assert_eq!(
            check_set_size(MAX_ITEMS + 1),
            Err(PsiError::SetTooLarge {
                size: MAX_ITEMS + 1,
                max: MAX_ITEMS,
            })
        );
    }

    #[test]
    fn test_psi_new_empty() {
        let proto = PsiProtocol::new(&[]).unwrap();
        assert_eq!(proto.message().len(), 0);
    }

    #[test]
    fn test_psi_new_single_item() {
        let items = vec![b"test".to_vec()];
        let proto = PsiProtocol::new(&items).unwrap();
        assert_eq!(proto.message().len(), 1);
    }

    #[test]
    fn test_psi_new_multiple_items() {
        let items = vec![b"apple".to_vec(), b"banana".to_vec(), b"cherry".to_vec()];
        let proto = PsiProtocol::new(&items).unwrap();
        assert_eq!(proto.message().len(), 3);
    }

    #[test]
    fn test_psi_duplicate_items() {
        let proto = PsiProtocol::new(&[b"apple".to_vec(), b"apple".to_vec()]).unwrap();
        assert_eq!(proto.message().len(), 1);
    }

    #[test]
    fn test_psi_compute_no_intersection() {
        let alice = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&[b"banana".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (bob_mid, bob_double) = bob.compute(alice_msg).unwrap();

        let alice_result = alice_mid.finalize(bob_double).unwrap();
        let bob_result = bob_mid.finalize(alice_double).unwrap();

        assert_eq!(alice_result.len(), 0);
        assert_eq!(bob_result.len(), 0);
    }

    #[test]
    fn test_psi_compute_with_intersection() {
        let alice = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (bob_mid, bob_double) = bob.compute(alice_msg).unwrap();

        let alice_result = alice_mid.finalize(bob_double).unwrap();
        let bob_result = bob_mid.finalize(alice_double).unwrap();

        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }

    #[test]
    fn test_psi_compute_symmetric() {
        let alice =
            PsiProtocol::new(&[b"apple".to_vec(), b"banana".to_vec(), b"cherry".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&[b"banana".to_vec(), b"date".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (bob_mid, bob_double) = bob.compute(alice_msg).unwrap();

        let alice_result = alice_mid.finalize(bob_double).unwrap();
        let bob_result = bob_mid.finalize(alice_double).unwrap();

        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }

    #[test]
    fn test_psi_empty_vs_nonempty() {
        let alice = PsiProtocol::new(&[]).unwrap();
        let bob = PsiProtocol::new(&[b"banana".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (bob_mid, bob_double) = bob.compute(alice_msg).unwrap();

        let alice_result = alice_mid.finalize(bob_double).unwrap();
        let bob_result = bob_mid.finalize(alice_double).unwrap();

        assert_eq!(alice_result.len(), 0);
        assert_eq!(bob_result.len(), 0);
    }

    #[test]
    fn test_psi_unequal_sizes() {
        let shared = b"shared".to_vec();
        let alice = PsiProtocol::new(&[
            b"a1".to_vec(),
            b"a2".to_vec(),
            shared.clone(),
            b"a3".to_vec(),
            b"a4".to_vec(),
        ])
        .unwrap();
        let bob = PsiProtocol::new(&[shared, b"b1".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();

        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (bob_mid, bob_double) = bob.compute(alice_msg).unwrap();

        let alice_result = alice_mid.finalize(bob_double).unwrap();
        let bob_result = bob_mid.finalize(alice_double).unwrap();

        assert_eq!(alice_result.len(), 1);
        assert_eq!(bob_result.len(), 1);
        assert_eq!(
            alice_result.intersection_hashes,
            bob_result.intersection_hashes
        );
    }

    #[test]
    fn test_finalize_length_too_short() {
        let alice = PsiProtocol::new(&[b"apple".to_vec(), b"banana".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();

        let bob_msg = bob.message();
        let (alice_mid, _) = alice.compute(bob_msg).unwrap();

        let err = alice_mid
            .finalize(DoubleBlindedPointsMessage::new(vec![]))
            .unwrap_err();
        assert_eq!(
            err,
            PsiError::LengthMismatch {
                expected: 2,
                actual: 0
            }
        );
    }

    #[test]
    fn test_finalize_length_too_long() {
        let alice = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();
        let bob = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();

        let alice_msg = alice.message();
        let bob_msg = bob.message();
        let (alice_mid, alice_double) = alice.compute(bob_msg).unwrap();
        let (_, bob_double) = bob.compute(alice_msg).unwrap();

        let mut too_long = bob_double.double_blinded_points;
        too_long.push(alice_double.double_blinded_points[0]);

        let err = alice_mid
            .finalize(DoubleBlindedPointsMessage::new(too_long))
            .unwrap_err();
        assert_eq!(
            err,
            PsiError::LengthMismatch {
                expected: 1,
                actual: 2
            }
        );
    }

    #[test]
    fn test_compute_invalid_point() {
        let alice = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();
        let bad = BlindedPointsMessage::new(vec![CompressedRistretto([0xffu8; 32])]);
        let err = alice.compute(bad).unwrap_err();
        assert!(matches!(err, PsiError::CryptoError(_)));
    }

    #[test]
    fn test_prepared_debug_does_not_include_secret() {
        let alice = PsiProtocol::new(&[b"apple".to_vec()]).unwrap();
        let rendered = format!("{alice:?}");
        assert!(rendered.contains("PsiProtocol"));
        assert!(rendered.contains("PreparedState"));
        // Redacted Debug has item count, not a 64-hex-looking scalar dump.
        assert!(!rendered.contains("secret"));
    }
}
