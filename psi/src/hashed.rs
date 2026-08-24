//! Cached hash-to-curve of a local PSI set.
//!
//! Hash-to-curve is deterministic and peer-independent. Sessions share one
//! [`HashedItems`] and still generate a fresh blinding scalar each time.

use crate::crypto::{hash_bytes, hash_inputs_to_points, hash_to_point};
use crate::error::Result;
use crate::protocol::check_set_size;
use curve25519_dalek::ristretto::RistrettoPoint;
use std::collections::HashMap;

/// Hash-to-curve cache for a local set of byte strings.
///
/// Safe to reuse across [`crate::PsiProtocol`] sessions. Do not reuse a
/// protocol's blinding scalar or first-round point order across peers.
#[derive(Clone, Debug, Default)]
pub struct HashedItems {
    hash_to_point: HashMap<[u8; 32], RistrettoPoint>,
}

impl HashedItems {
    /// Hash `items` to curve points. Duplicates collapse.
    ///
    /// # Errors
    ///
    /// Returns [`crate::PsiError::SetTooLarge`] if the number of distinct
    /// items exceeds [`crate::MAX_ITEMS`].
    pub fn new(items: &[Vec<u8>]) -> Result<Self> {
        let hash_to_point = hash_inputs_to_points(items);
        check_set_size(hash_to_point.len())?;
        Ok(Self { hash_to_point })
    }

    /// Insert `item`. Returns `true` if it was new.
    ///
    /// # Errors
    ///
    /// Returns [`crate::PsiError::SetTooLarge`] if a new item would exceed
    /// [`crate::MAX_ITEMS`].
    pub fn insert(&mut self, item: &[u8]) -> Result<bool> {
        let hash = hash_bytes(item);
        if self.hash_to_point.contains_key(&hash) {
            return Ok(false);
        }
        check_set_size(self.hash_to_point.len() + 1)?;
        self.hash_to_point.insert(hash, hash_to_point(&hash));
        Ok(true)
    }

    /// Remove `item` (by [`crate::hash_bytes`]). Returns `true` if it was present.
    pub fn remove(&mut self, item: &[u8]) -> bool {
        self.hash_to_point.remove(&hash_bytes(item)).is_some()
    }

    /// Remove a previously hashed identifier.
    pub fn remove_hash(&mut self, hash: &[u8; 32]) -> bool {
        self.hash_to_point.remove(hash).is_some()
    }

    /// Number of distinct items.
    pub fn len(&self) -> usize {
        self.hash_to_point.len()
    }

    /// True if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.hash_to_point.is_empty()
    }

    pub(crate) fn points(&self) -> &HashMap<[u8; 32], RistrettoPoint> {
        &self.hash_to_point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_dedups() {
        let h = HashedItems::new(&[b"apple".to_vec(), b"apple".to_vec()]).unwrap();
        assert_eq!(h.len(), 1);
        assert!(!h.is_empty());
    }

    #[test]
    fn insert_remove() {
        let mut h = HashedItems::new(&[]).unwrap();
        assert!(h.insert(b"apple").unwrap());
        assert!(!h.insert(b"apple").unwrap());
        assert_eq!(h.len(), 1);
        assert!(h.remove(b"apple"));
        assert!(!h.remove(b"apple"));
        assert!(h.is_empty());
    }

    #[test]
    fn incremental_matches_full() {
        let items = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let full = HashedItems::new(&items).unwrap();
        let mut inc = HashedItems::new(&[]).unwrap();
        for item in &items {
            inc.insert(item).unwrap();
        }
        assert_eq!(inc.len(), full.len());
        for hash in full.points().keys() {
            assert_eq!(inc.points().get(hash), full.points().get(hash));
        }
    }
}
