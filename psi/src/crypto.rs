//! Cryptographic operations for the PSI protocol.

use crate::error::{PsiError, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

/// Domain-separation tag mixed into hash-to-curve (not into [`hash_bytes`]).
pub(crate) const H2C_DST: &[u8] = b"psi-sync/v1";

/// Hash a byte array to a 32-byte identifier (first 32 bytes of SHA-512,
/// not SHA-512/256).
///
/// Intersection results report these identifiers, not the original items.
/// Callers map results back by hashing their local items with this function.
pub fn hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..32]);
    hash
}

/// Map a 32-byte item identifier to a Ristretto point using hash-to-curve.
///
/// The DST is prepended so the same identifier used in another protocol does
/// not produce the same curve point.
pub(crate) fn hash_to_point(hash: &[u8; 32]) -> RistrettoPoint {
    let mut labeled = Vec::with_capacity(H2C_DST.len() + hash.len());
    labeled.extend_from_slice(H2C_DST);
    labeled.extend_from_slice(hash);
    RistrettoPoint::hash_from_bytes::<Sha512>(&labeled)
}

/// Hash-to-curve of an item identifier with no DST. Used only to lock DST in.
#[cfg(test)]
pub(crate) fn hash_to_point_without_dst(hash: &[u8; 32]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(hash)
}

/// Hash multiple byte arrays to Ristretto points.
///
/// Duplicate inputs collapse to a single map entry (set semantics).
pub(crate) fn hash_inputs_to_points(inputs: &[Vec<u8>]) -> HashMap<[u8; 32], RistrettoPoint> {
    inputs
        .iter()
        .map(|input| {
            let hash = hash_bytes(input);
            (hash, hash_to_point(&hash))
        })
        .collect()
}

/// Blind a Ristretto point by multiplying it with a scalar.
pub(crate) fn blind_point(point: &RistrettoPoint, secret: &Scalar) -> CompressedRistretto {
    (secret * point).compress()
}

/// Blind multiple points with a scalar.
pub(crate) fn blind_points(
    points: &HashMap<[u8; 32], RistrettoPoint>,
    secret: &Scalar,
) -> HashMap<[u8; 32], CompressedRistretto> {
    points
        .iter()
        .map(|(hash, point)| (*hash, blind_point(point, secret)))
        .collect()
}

/// Generate a random scalar using OsRng.
pub(crate) fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    Scalar::random(&mut rng)
}

/// Decompress a compressed Ristretto point.
///
/// # Errors
/// Returns `PsiError::CryptoError` if decompression fails.
pub(crate) fn decompress_point(compressed: &CompressedRistretto) -> Result<RistrettoPoint> {
    compressed
        .decompress()
        .ok_or_else(|| PsiError::CryptoError("Failed to decompress Ristretto point".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes() {
        let input = b"test input";
        let hash1 = hash_bytes(input);
        let hash2 = hash_bytes(input);
        assert_eq!(
            hash1, hash2,
            "Hashing same input should produce same output"
        );

        let different_input = b"different input";
        let hash3 = hash_bytes(different_input);
        assert_ne!(
            hash1, hash3,
            "Hashing different input should produce different output"
        );
    }

    #[test]
    fn test_hash_bytes_stable() {
        // First 32 bytes of SHA-512("test input"). Pinned so accidental hash
        // changes fail the build.
        let expected = [
            0x40, 0xaa, 0x1b, 0x20, 0x3c, 0x9d, 0x8e, 0xe1, 0x50, 0xb2, 0x1c, 0x3c, 0x7c, 0xda,
            0x82, 0x61, 0x49, 0x2e, 0x54, 0x20, 0xc5, 0xf2, 0xb9, 0xf7, 0x38, 0x07, 0x00, 0xe0,
            0x94, 0xc3, 0x03, 0xb4,
        ];
        assert_eq!(hash_bytes(b"test input"), expected);
    }

    #[test]
    fn test_hash_to_point() {
        let hash = [42u8; 32];
        let point1 = hash_to_point(&hash);
        let point2 = hash_to_point(&hash);
        assert_eq!(point1, point2, "Hash-to-curve should be deterministic");
        assert_ne!(
            point1,
            hash_to_point_without_dst(&hash),
            "DST must change the curve point"
        );
    }

    #[test]
    fn test_hash_inputs_to_points() {
        let inputs = vec![b"apple".to_vec(), b"banana".to_vec()];
        let map = hash_inputs_to_points(&inputs);
        assert_eq!(map.len(), 2);

        let h0 = hash_bytes(b"apple");
        let h1 = hash_bytes(b"banana");
        assert!(map.contains_key(&h0));
        assert!(map.contains_key(&h1));
    }

    #[test]
    fn test_hash_inputs_to_points_dedup() {
        let inputs = vec![b"apple".to_vec(), b"apple".to_vec()];
        let map = hash_inputs_to_points(&inputs);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_blind_point() {
        let hash = [42u8; 32];
        let point = hash_to_point(&hash);
        let secret = random_scalar();
        let blinded = blind_point(&point, &secret);

        let decompressed = decompress_point(&blinded);
        assert!(decompressed.is_ok(), "Blinded point should be valid");
    }

    #[test]
    fn test_blind_points() {
        let inputs = vec![b"apple".to_vec(), b"banana".to_vec()];
        let points = hash_inputs_to_points(&inputs);
        let secret = random_scalar();
        let blinded = blind_points(&points, &secret);

        assert_eq!(blinded.len(), 2);
        for compressed in blinded.values() {
            assert!(decompress_point(compressed).is_ok());
        }
    }

    #[test]
    fn test_random_scalar() {
        let scalar1 = random_scalar();
        let scalar2 = random_scalar();
        assert_ne!(scalar1, scalar2, "Random scalars should be different");
    }

    #[test]
    fn test_decompress_point() {
        let hash = [42u8; 32];
        let point = hash_to_point(&hash);
        let compressed = point.compress();
        let decompressed = decompress_point(&compressed);

        assert!(decompressed.is_ok());
        assert_eq!(decompressed.unwrap(), point);
    }

    #[test]
    fn test_decompress_point_invalid() {
        // All-0xFF is not a valid Ristretto encoding.
        let invalid = CompressedRistretto([0xffu8; 32]);
        let result = decompress_point(&invalid);
        assert!(matches!(result, Err(PsiError::CryptoError(_))));
    }
}
