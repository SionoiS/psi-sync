//! Protocol state types for the type-state pattern PSI implementation.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroize;

/// Marker trait implemented by protocol state types.
///
/// Public so callers can name `PsiProtocol<S: PsiState>` when storing a
/// protocol object. The trait is sealed by having no methods; only this
/// crate implements it.
pub trait PsiState {}

/// After preparation: blinded points are ready for the first exchange.
pub struct PreparedState {
    secret: Scalar,
    hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
    hash_order: Vec<[u8; 32]>,
}

impl PreparedState {
    pub(crate) fn new(
        secret: Scalar,
        hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
        hash_order: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            secret,
            hash_to_blinded,
            hash_order,
        }
    }

    pub(crate) fn blinded_map(&self) -> &HashMap<[u8; 32], CompressedRistretto> {
        &self.hash_to_blinded
    }

    pub(crate) fn secret_scalar(&self) -> &Scalar {
        &self.secret
    }

    pub(crate) fn hash_order(&self) -> &[[u8; 32]] {
        &self.hash_order
    }
}

impl Drop for PreparedState {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for PreparedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedState")
            .field("items", &self.hash_order.len())
            .finish_non_exhaustive()
    }
}

impl PsiState for PreparedState {}

/// After double-blinding the peer's points: ready for the second exchange.
pub struct DoubleBlindedState {
    double_blinded_from_remote: Vec<CompressedRistretto>,
    hash_order: Vec<[u8; 32]>,
}

impl DoubleBlindedState {
    pub(crate) fn new(
        double_blinded_from_remote: Vec<CompressedRistretto>,
        hash_order: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            double_blinded_from_remote,
            hash_order,
        }
    }

    pub(crate) fn double_blinded_from_remote(&self) -> &[CompressedRistretto] {
        &self.double_blinded_from_remote
    }

    pub(crate) fn hash_order(&self) -> &[[u8; 32]] {
        &self.hash_order
    }
}

impl fmt::Debug for DoubleBlindedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoubleBlindedState")
            .field("local_items", &self.hash_order.len())
            .field("remote_points", &self.double_blinded_from_remote.len())
            .finish_non_exhaustive()
    }
}

impl PsiState for DoubleBlindedState {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_scalar;

    #[test]
    fn test_prepared_state_new() {
        let secret = random_scalar();
        let state = PreparedState::new(secret, HashMap::new(), vec![]);
        assert!(state.blinded_map().is_empty());
        assert!(state.hash_order().is_empty());
    }

    #[test]
    fn test_double_blinded_state_new() {
        let state = DoubleBlindedState::new(vec![], vec![]);
        assert!(state.double_blinded_from_remote().is_empty());
        assert!(state.hash_order().is_empty());
    }

    #[test]
    fn test_all_states_implement_psi_state() {
        fn assert_implements_psistate<S: PsiState>() {}

        assert_implements_psistate::<PreparedState>();
        assert_implements_psistate::<DoubleBlindedState>();
    }

    #[test]
    fn test_prepared_state_debug_redacts_secret() {
        let secret = random_scalar();
        let secret_debug = format!("{secret:?}");
        let state = PreparedState::new(secret, HashMap::new(), vec![]);
        let rendered = format!("{state:?}");
        assert!(
            !rendered.contains(&secret_debug),
            "Debug must not include the blinding scalar: {rendered}"
        );
        assert!(rendered.contains("PreparedState"));
    }
}
