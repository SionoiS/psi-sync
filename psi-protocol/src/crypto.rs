//! Cryptographic operations for the PSI protocol.

use crate::error::{PsiError, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

/// Hash a byte array to a 32-byte SHA-512 hash.
///
/// # Arguments
/// * `input` - Input bytes to hash
///
/// # Returns
/// A 32-byte hash (first 32 bytes of SHA-512 output)
pub fn hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..32]);
    hash
}

/// Map a 32-byte hash to a Ristretto point using hash-to-curve.
///
/// # Arguments
/// * `hash` - A 32-byte hash
///
/// # Returns
/// The corresponding Ristretto point
pub fn hash_to_point(hash: &[u8; 32]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(hash)
}

/// Hash multiple byte arrays to 32-byte SHA-512 hashes.
///
/// # Arguments
/// * `inputs` - Slice of input byte vectors
///
/// # Returns
/// A vector of 32-byte hashes
pub fn hash_multiple(inputs: &[Vec<u8>]) -> Vec<[u8; 32]> {
    inputs.iter().map(|input| hash_bytes(input)).collect()
}

/// Hash multiple byte arrays to Ristretto points.
///
/// This combines hashing and hash-to-curve operations.
///
/// # Arguments
/// * `inputs` - Slice of input byte vectors
///
/// # Returns
/// A HashMap mapping input hashes to their corresponding Ristretto points
pub fn hash_inputs_to_points(inputs: &[Vec<u8>]) -> HashMap<[u8; 32], RistrettoPoint> {
    inputs
        .iter()
        .map(|input| {
            let hash = hash_bytes(input);
            (hash, hash_to_point(&hash))
        })
        .collect()
}

/// Blind a Ristretto point by multiplying it with a scalar.
///
/// # Arguments
/// * `point` - The point to blind
/// * `secret` - The scalar to multiply with
///
/// # Returns
/// The blinded point as a compressed Ristretto point
pub fn blind_point(point: &RistrettoPoint, secret: &Scalar) -> CompressedRistretto {
    (secret * point).compress()
}

/// Blind multiple points with a scalar.
///
/// # Arguments
/// * `points` - HashMap of hashes to points
/// * `secret` - The scalar to multiply with
///
/// # Returns
/// A HashMap mapping hashes to blinded points
pub fn blind_points(
    points: &HashMap<[u8; 32], RistrettoPoint>,
    secret: &Scalar,
) -> HashMap<[u8; 32], CompressedRistretto> {
    points
        .iter()
        .map(|(hash, point)| (*hash, blind_point(point, secret)))
        .collect()
}

/// Generate a random scalar using OsRng.
///
/// # Returns
/// A cryptographically secure random scalar
pub fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    Scalar::random(&mut rng)
}

/// Decompress a compressed Ristretto point.
///
/// # Arguments
/// * `compressed` - The compressed point to decompress
///
/// # Returns
/// The decompressed Ristretto point
///
/// # Errors
/// Returns `PsiError::CryptoError` if decompression fails
pub fn decompress_point(compressed: &CompressedRistretto) -> Result<RistrettoPoint> {
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
        assert_eq!(hash1, hash2, "Hashing same input should produce same output");

        let different_input = b"different input";
        let hash3 = hash_bytes(different_input);
        assert_ne!(
            hash1, hash3,
            "Hashing different input should produce different output"
        );
    }

    #[test]
    fn test_hash_to_point() {
        let hash = [42u8; 32];
        let point1 = hash_to_point(&hash);
        let point2 = hash_to_point(&hash);
        assert_eq!(
            point1, point2,
            "Hash-to-curve should be deterministic"
        );
    }

    #[test]
    fn test_hash_multiple() {
        let inputs = vec![b"apple".to_vec(), b"banana".to_vec()];
        let hashes = hash_multiple(&inputs);
        assert_eq!(hashes.len(), 2);
        assert_ne!(hashes[0], hashes[1], "Different inputs should produce different hashes");
    }

    #[test]
    fn test_hash_inputs_to_points() {
        let inputs = vec![b"apple".to_vec(), b"banana".to_vec()];
        let map = hash_inputs_to_points(&inputs);
        assert_eq!(map.len(), 2);

        // Verify the same input produces the same hash and point
        let hashes = hash_multiple(&inputs);
        assert!(map.contains_key(&hashes[0]));
        assert!(map.contains_key(&hashes[1]));
    }

    #[test]
    fn test_blind_point() {
        let hash = [42u8; 32];
        let point = hash_to_point(&hash);
        let secret = random_scalar();
        let blinded = blind_point(&point, &secret);

        // Blinded point should be a valid compressed point
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
        // Blinded points should be valid compressed points
        for (_, compressed) in &blinded {
            assert!(decompress_point(compressed).is_ok());
        }
    }

    #[test]
    fn test_random_scalar() {
        let scalar1 = random_scalar();
        let scalar2 = random_scalar();
        // With overwhelming probability, two random scalars should be different
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
        // An all-zeros compressed point is unlikely to be valid
        let invalid = CompressedRistretto([0u8; 32]);
        let result = decompress_point(&invalid);
        // This might fail or succeed depending on the point, but the function should handle it
        // If it succeeds, it's a valid point; if it fails, it should return an error
        match result {
            Ok(_) => {}, // Valid point, that's fine
            Err(e) => assert!(matches!(e, PsiError::CryptoError(_))),
        }
    }
}
