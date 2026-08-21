//! Monoid-tree store of reconcilable items.

use crate::bounds::RangeBounds;
use crate::config::ReconcileConfig;
use crate::error::{ReconcileError, Result};
use crate::id::{SyncId, EMPTY_HASH};
use crate::item::ReconcileItem;
use crate::source::ReconcileSource;
use crate::tree::MonoidTree;

/// Ordered set of items plus the reconciliation tunables.
#[derive(Clone, Debug)]
pub struct ReconcileStore<T: ReconcileItem = SyncId> {
    items: MonoidTree<T>,
    config: ReconcileConfig,
}

impl<T: ReconcileItem> ReconcileStore<T> {
    /// Empty store. Rejects an invalid [`ReconcileConfig`].
    pub fn new(config: ReconcileConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            items: MonoidTree::new(),
            config,
        })
    }

    /// Store configuration.
    pub fn config(&self) -> &ReconcileConfig {
        &self.config
    }

    /// Insert `id`. Duplicates are ignored. Errors if `max_items` would be exceeded.
    pub fn insert(&mut self, id: T) -> Result<()> {
        if self.items.len() >= self.config.max_items && !self.items.contains(&id) {
            return Err(ReconcileError::SetTooLarge {
                size: self.items.len() + 1,
                max: self.config.max_items,
            });
        }
        self.items.insert(id);
        Ok(())
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
    pub fn items(&self, bounds: RangeBounds<T>) -> impl Iterator<Item = &T> {
        self.items.iter_range(&bounds.a, &bounds.b)
    }

    /// Number of items in `bounds`.
    pub fn count(&self, bounds: RangeBounds<T>) -> usize {
        self.items.count_range(&bounds.a, &bounds.b)
    }

    /// Fingerprint of items in `bounds`. Empty range → [`T::empty_fingerprint`].
    pub fn fingerprint(&self, bounds: RangeBounds<T>) -> T::Fingerprint {
        self.items.aggregate_range(&bounds.a, &bounds.b)
    }

    fn items_vec(&self, bounds: RangeBounds<T>) -> Vec<T> {
        self.items(bounds).cloned().collect()
    }
}

impl<T: ReconcileItem> ReconcileSource for ReconcileStore<T> {
    type Item = T;
    type Bounds = RangeBounds<T>;

    fn fingerprint(&self, bounds: Self::Bounds) -> T::Fingerprint {
        ReconcileStore::fingerprint(self, bounds)
    }

    fn items(&self, bounds: Self::Bounds) -> Vec<T> {
        self.items_vec(bounds)
    }

    fn count(&self, bounds: Self::Bounds) -> usize {
        ReconcileStore::count(self, bounds)
    }

    fn partition(&self, bounds: Self::Bounds, count: usize) -> Vec<Self::Bounds> {
        let local = self.items_vec(bounds.clone());
        T::partition(bounds, &local, count)
    }

    fn config(&self) -> &ReconcileConfig {
        ReconcileStore::config(self)
    }
}

impl ReconcileStore<SyncId> {
    /// Drop every item with `timestamp < timestamp`. Returns the number removed.
    pub fn prune_before(&mut self, timestamp: u64) -> usize {
        let bound = SyncId {
            timestamp,
            hash: EMPTY_HASH,
        };
        self.items.remove_before(&bound)
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
        let v: Vec<_> = s
            .items(RangeBounds::window(0, 10).unwrap())
            .cloned()
            .collect();
        assert_eq!(v[0], sid(1, 1));
        assert_eq!(v[1], sid(2, 1));
    }

    #[test]
    fn prune_before_drops_strictly_older() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(2, 1)).unwrap();
        s.insert(sid(3, 1)).unwrap();
        assert_eq!(s.prune_before(2), 1);
        assert_eq!(s.len(), 2);
        let v: Vec<_> = s
            .items(RangeBounds::window(0, 10).unwrap())
            .cloned()
            .collect();
        assert_eq!(v[0], sid(2, 1));
    }

    #[test]
    fn items_exclusive_upper() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(10, 0)).unwrap();
        s.insert(sid(15, 0)).unwrap();
        s.insert(sid(20, 0)).unwrap();
        let bounds = RangeBounds::window(10, 20).unwrap();
        let sl: Vec<_> = s.items(bounds).cloned().collect();
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

    #[test]
    fn max_items_rejects_new_but_allows_dup() {
        let cfg = ReconcileConfig {
            max_items: 1,
            ..Default::default()
        };
        let mut s = ReconcileStore::new(cfg).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(1, 1)).unwrap();
        assert_eq!(s.len(), 1);
        let err = s.insert(sid(2, 2)).unwrap_err();
        assert!(matches!(err, ReconcileError::SetTooLarge { max: 1, .. }));
    }
}
