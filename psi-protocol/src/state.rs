//! Protocol state types for the type-state pattern PSI implementation.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use std::collections::HashMap;

/// Marker trait that all protocol states must implement.
///
/// This trait enables the generic `PsiProtocol<S: PsiState>` wrapper
/// to accept any valid protocol state.
pub trait PsiState {}

/// First state: After preparation - contains blinded points ready for exchange.
///
/// This state exists after the protocol has been initialized with items
/// and the points have been blinded. The blinded points are ready to be
/// exchanged with a remote party.
#[derive(Debug)]
pub struct PreparedState {
    /// Secret scalar used for blinding
    secret: Scalar,
    /// Mapping from input hash to single-blinded point
    hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
    /// Reverse mapping from blinded point to hash (for final result lookup)
    blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]>,
    /// Ordered list of hashes (matches the order of blinded points in the message)
    hash_order: Vec<[u8; 32]>,
}

impl PreparedState {
    /// Create a new PreparedState with the given secret and blinded mappings.
    pub(crate) fn new(
        secret: Scalar,
        hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
        blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]>,
        hash_order: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            secret,
            hash_to_blinded,
            blinded_to_hash,
            hash_order,
        }
    }

    /// Get the secret scalar (for testing purposes).
    #[cfg(test)]
    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    /// Get the hash to blinded mapping (for testing purposes).
    #[cfg(test)]
    pub fn hash_to_blinded(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_blinded
    }

    /// Get a reference to the hash_to_blinded map.
    pub(crate) fn blinded_map(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_blinded
    }

    /// Get the secret scalar.
    pub(crate) fn secret_scalar(&self) -> &Scalar {
        &self.secret
    }

    /// Get the blinded_to_hash reverse mapping.
    pub(crate) fn blinded_to_hash(&self) -> &HashMap<CompressedRistretto, [u8; 32]> {
        &self.blinded_to_hash
    }

    /// Get the ordered list of hashes.
    pub(crate) fn hash_order(&self) -> &[[u8; 32]] {
        &self.hash_order
    }
}

impl PsiState for PreparedState {}

/// Second state: During computation - contains remote data for intersection.
///
/// This state exists internally during the computation phase when we have
/// both local and remote data. It's used to compute the intersection.
#[derive(Debug)]
pub struct ComputingState {
    /// Secret scalar used for blinding
    secret: Scalar,
    /// Mapping from input hash to single-blinded point (local)
    hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
    /// Reverse mapping from blinded point to hash (local)
    blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]>,
    /// Remote blinded points (no hashes - we don't have them!)
    remote_blinded_points: Vec<CompressedRistretto>,
}

impl ComputingState {
    /// Create a new ComputingState with local and remote data.
    pub(crate) fn new(
        secret: Scalar,
        hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
        blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]>,
        remote_blinded_points: Vec<CompressedRistretto>,
    ) -> Self {
        Self {
            secret,
            hash_to_blinded,
            blinded_to_hash,
            remote_blinded_points,
        }
    }

    /// Get the secret scalar (for testing purposes).
    #[cfg(test)]
    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    /// Get the secret scalar.
    pub(crate) fn secret_scalar(&self) -> &Scalar {
        &self.secret
    }

    /// Get the local blinded mapping.
    pub(crate) fn blinded_map(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_blinded
    }

    /// Get the blinded_to_hash reverse mapping.
    pub(crate) fn blinded_to_hash(&self) -> &HashMap<CompressedRistretto, [u8; 32]> {
        &self.blinded_to_hash
    }

    /// Get the remote blinded points.
    pub(crate) fn remote_blinded_points(&self) -> &[CompressedRistretto] {
        &self.remote_blinded_points
    }
}

impl PsiState for ComputingState {}

/// Third state: After double-blinding - ready for final exchange.
///
/// This state exists after we've double-blinded the remote's single-blinded points.
/// The double-blinded points are ready to be exchanged with the remote party for
/// the final intersection computation.
#[derive(Debug)]
pub struct DoubleBlindedState {
    /// Secret scalar used for blinding
    secret: Scalar,
    /// Mapping from input hash to single-blinded point (local)
    hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
    /// Reverse mapping from blinded point to hash (local)
    blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]>,
    /// Double-blinded points computed FROM remote's single-blinded points
    double_blinded_from_remote: Vec<CompressedRistretto>,
    /// Ordered list of hashes (matches the order of blinded points in our message)
    hash_order: Vec<[u8; 32]>,
}

impl DoubleBlindedState {
    /// Create a new DoubleBlindedState with local data and computed double-blinded points.
    pub(crate) fn new(
        secret: Scalar,
        hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
        blinded_to_hash: HashMap<CompressedRistretto, [u8; 32]>,
        double_blinded_from_remote: Vec<CompressedRistretto>,
        hash_order: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            secret,
            hash_to_blinded,
            blinded_to_hash,
            double_blinded_from_remote,
            hash_order,
        }
    }

    /// Get the secret scalar (for testing purposes).
    #[cfg(test)]
    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    /// Get the secret scalar.
    pub(crate) fn secret_scalar(&self) -> &Scalar {
        &self.secret
    }

    /// Get the local blinded mapping.
    pub(crate) fn blinded_map(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_blinded
    }

    /// Get the blinded_to_hash reverse mapping.
    pub(crate) fn blinded_to_hash(&self) -> &HashMap<CompressedRistretto, [u8; 32]> {
        &self.blinded_to_hash
    }

    /// Get the double-blinded points computed from remote's single-blinded points.
    pub(crate) fn double_blinded_from_remote(&self) -> &[CompressedRistretto] {
        &self.double_blinded_from_remote
    }

    /// Get the ordered list of hashes.
    pub(crate) fn hash_order(&self) -> &[[u8; 32]] {
        &self.hash_order
    }
}

impl PsiState for DoubleBlindedState {}

/// Final state: Complete - contains the intersection results.
///
/// This state exists after the intersection has been computed.
/// The secret is dropped for security (no longer needed).
#[derive(Debug)]
pub struct FinalState {
    /// Mapping from intersection hashes to their double-blinded point representations
    hash_to_double_blinded: HashMap<[u8; 32], CompressedRistretto>,
}

impl FinalState {
    /// Create a new FinalState with the intersection results.
    pub(crate) fn new(
        hash_to_double_blinded: HashMap<[u8; 32], CompressedRistretto>,
    ) -> Self {
        Self {
            hash_to_double_blinded,
        }
    }

    /// Get the hash to double-blinded mapping (for testing purposes).
    #[cfg(test)]
    pub fn hash_to_double_blinded(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_double_blinded
    }

    /// Get the double-blinded mapping.
    pub(crate) fn double_blinded_map(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_double_blinded
    }
}

impl PsiState for FinalState {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_scalar;

    #[test]
    fn test_prepared_state_new() {
        let secret = random_scalar();
        let hash_map = HashMap::new();
        let blinded_map = HashMap::new();
        let hash_order = vec![];
        let state = PreparedState::new(secret, hash_map, blinded_map, hash_order);
        assert!(!state.hash_to_blinded().contains_key(&[0u8; 32]));
    }

    #[test]
    fn test_computing_state_new() {
        let secret = random_scalar();
        let local_map = HashMap::new();
        let blinded_map = HashMap::new();
        let remote_points = vec![];
        let state = ComputingState::new(secret, local_map, blinded_map, remote_points);
        assert!(!state.blinded_map().contains_key(&[0u8; 32]));
    }

    #[test]
    fn test_final_state_new() {
        let map = HashMap::new();
        let state = FinalState::new(map);
        assert!(!state.hash_to_double_blinded().contains_key(&[0u8; 32]));
    }

    #[test]
    fn test_all_states_implement_psi_state() {
        // This test verifies that all state types implement PsiState
        fn assert_implements_psistate<S: PsiState>() {}

        assert_implements_psistate::<PreparedState>();
        assert_implements_psistate::<ComputingState>();
        assert_implements_psistate::<DoubleBlindedState>();
        assert_implements_psistate::<FinalState>();
    }
}
