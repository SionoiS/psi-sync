//! Sorted in-memory store of [`SyncId`]s.

use crate::bounds::RangeBounds;
use crate::config::ReconcileConfig;
use crate::error::{ReconcileError, Result};
use crate::fingerprint::xor_slice;
use crate::id::{SyncId, EMPTY_HASH};

/// Ordered set of [`SyncId`]s plus the reconciliation tunables.
#[derive(Clone, Debug)]
pub struct ReconcileStore {
    items: Vec<SyncId>,
    config: ReconcileConfig,
}

impl ReconcileStore {
    /// Empty store. Rejects an invalid [`ReconcileConfig`].
    pub fn new(config: ReconcileConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            items: Vec::new(),
            config,
        })
    }

    /// Store configuration.
    pub fn config(&self) -> &ReconcileConfig {
        &self.config
    }

    /// Insert `id`. Duplicates are ignored. Errors if `max_items` would be exceeded.
    pub fn insert(&mut self, id: SyncId) -> Result<()> {
        match self.items.binary_search(&id) {
            Ok(_) => Ok(()),
            Err(idx) => {
                if self.items.len() >= self.config.max_items {
                    return Err(ReconcileError::SetTooLarge {
                        size: self.items.len() + 1,
                        max: self.config.max_items,
                    });
                }
                self.items.insert(idx, id);
                Ok(())
            }
        }
    }

    /// Drop every item with `timestamp < timestamp`. Returns the number removed.
    pub fn prune_before(&mut self, timestamp: u64) -> usize {
        let bound = SyncId {
            timestamp,
            hash: EMPTY_HASH,
        };
        let idx = self.items.partition_point(|id| *id < bound);
        self.items.drain(..idx);
        idx
    }

    /// Number of stored items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Items in `[bounds.a, bounds.b)`.
    pub fn slice(&self, bounds: RangeBounds) -> &[SyncId] {
        let start = self.items.partition_point(|id| *id < bounds.a);
        let end = self.items.partition_point(|id| *id < bounds.b);
        &self.items[start..end]
    }

    /// XOR of hashes of items in `bounds`. Empty slice → `[0; 32]`.
    pub fn fingerprint(&self, bounds: RangeBounds) -> [u8; 32] {
        xor_slice(self.slice(bounds).iter().map(|id| &id.hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SyncId;

    fn sid(t: u64, h0: u8) -> SyncId {
        let mut hash = [0u8; 32];
        hash[0] = h0;
        SyncId::new(t, hash)
    }

    #[test]
    fn insert_orders_and_dedups() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(2, 1)).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(2, 1)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.items[0], sid(1, 1));
        assert_eq!(s.items[1], sid(2, 1));
    }

    #[test]
    fn prune_before_drops_strictly_older() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(2, 1)).unwrap();
        s.insert(sid(3, 1)).unwrap();
        assert_eq!(s.prune_before(2), 1);
        assert_eq!(s.len(), 2);
        assert_eq!(s.items[0], sid(2, 1));
    }

    #[test]
    fn slice_exclusive_upper() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(10, 0)).unwrap();
        s.insert(sid(15, 0)).unwrap();
        s.insert(sid(20, 0)).unwrap();
        let bounds = RangeBounds::window(10, 20).unwrap();
        let sl = s.slice(bounds);
        assert_eq!(sl.len(), 2);
        assert_eq!(sl[0], sid(10, 0));
        assert_eq!(sl[1], sid(15, 0));
    }

    #[test]
    fn fingerprint_known_set() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let mut h1 = [0u8; 32];
        h1[0] = 0x0f;
        let mut h2 = [0u8; 32];
        h2[0] = 0xf0;
        s.insert(SyncId::new(1, h1)).unwrap();
        s.insert(SyncId::new(2, h2)).unwrap();
        let fp = s.fingerprint(RangeBounds::window(0, 10).unwrap());
        let mut expect = [0u8; 32];
        expect[0] = 0xff;
        assert_eq!(fp, expect);
    }
}
