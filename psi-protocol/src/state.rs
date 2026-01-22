//! Protocol state management for PSI.

use crate::crypto::random_scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use std::collections::HashMap;

/// State for one side of the PSI protocol.
///
/// `PsiState` holds the cryptographic secret and the internal mappings
/// needed to complete the PSI protocol. Each peer should create their
/// own `PsiState` instance.
#[derive(Debug, Clone)]
pub struct PsiState {
    /// Secret scalar used for blinding
    pub(crate) secret: Scalar,
    /// Mapping from input hash to single-blinded point
    pub(crate) hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
    /// Mapping from input hash to double-blinded point (populated after `compute_intersection`)
    pub(crate) hash_to_double_blinded: HashMap<[u8; 32], CompressedRistretto>,
}

impl PsiState {
    /// Create a new PsiState with a fresh random secret.
    ///
    /// # Returns
    /// A new `PsiState` instance
    pub fn new() -> Self {
        Self {
            secret: random_scalar(),
            hash_to_blinded: HashMap::new(),
            hash_to_double_blinded: HashMap::new(),
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

    /// Get the hash to double-blinded mapping (for testing purposes).
    #[cfg(test)]
    pub fn hash_to_double_blinded(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_double_blinded
    }
}

impl Default for PsiState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_state_new() {
        let state = PsiState::new();
        assert!(!state.hash_to_blinded().contains_key(&[0u8; 32]));
        assert!(!state.hash_to_double_blinded().contains_key(&[0u8; 32]));
    }

    #[test]
    fn test_psi_state_default() {
        let state = PsiState::default();
        assert!(!state.hash_to_blinded().contains_key(&[0u8; 32]));
    }
}
