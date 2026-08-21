//! Monoid-tree store of reconcilable items.

use crate::bounds::RangeBounds;
use crate::config::ReconcileConfig;
use crate::error::{ReconcileError, Result};
use crate::id::{SyncId, EMPTY_HASH};
use crate::item::ReconcileItem;
use crate::partition::partition_by_nth;
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

    /// Fingerprint and count of each sorted, disjoint bound in one tree walk.
    pub fn fingerprint_counts(&self, bounds: &[RangeBounds<T>]) -> Vec<(T::Fingerprint, usize)> {
        self.items.aggregate_and_count_ranges(bounds)
    }

    /// Fingerprints of sorted, disjoint `bounds` in one tree walk.
    pub fn fingerprints(&self, bounds: &[RangeBounds<T>]) -> Vec<T::Fingerprint> {
        self.items.aggregate_ranges(bounds)
    }

    /// Counts of sorted, disjoint `bounds` in one tree walk.
    pub fn counts(&self, bounds: &[RangeBounds<T>]) -> Vec<usize> {
        self.items.count_ranges(bounds)
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

    fn fingerprints(&self, bounds: &[Self::Bounds]) -> Vec<T::Fingerprint> {
        ReconcileStore::fingerprints(self, bounds)
    }

    fn fingerprint_counts(&self, bounds: &[Self::Bounds]) -> Vec<(T::Fingerprint, usize)> {
        ReconcileStore::fingerprint_counts(self, bounds)
    }

    fn items(&self, bounds: Self::Bounds) -> Vec<T> {
        self.items_vec(bounds)
    }

    fn count(&self, bounds: Self::Bounds) -> usize {
        ReconcileStore::count(self, bounds)
    }

    fn counts(&self, bounds: &[Self::Bounds]) -> Vec<usize> {
        ReconcileStore::counts(self, bounds)
    }

    fn partition(&self, bounds: Self::Bounds, count: usize) -> Vec<Self::Bounds> {
        if let Some(parts) = T::partition_domain_hot(bounds.clone(), count, self.config.hot_tail) {
            return parts;
        }
        let n = self.items.count_range(&bounds.a, &bounds.b);
        partition_by_nth(bounds.clone(), n, count, |k| {
            self.items.nth_in_range(&bounds.a, &bounds.b, k).cloned()
        })
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
    use crate::partition::{partition_by_items, partition_range, partition_range_with_hot};

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Key(u64);

    impl ReconcileItem for Key {
        type Fingerprint = u64;
        fn empty_fingerprint() -> u64 {
            0
        }
        fn accumulate(fp: &mut u64, item: &Self) {
            *fp ^= item.0;
        }
        fn combine(a: &u64, b: &u64) -> u64 {
            a ^ b
        }
    }

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

    #[test]
    fn generic_partition_tiles_like_items() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        let local: Vec<_> = (1..=8).map(|i| Key(i * 10)).collect();
        for k in &local {
            s.insert(k.clone()).unwrap();
        }
        let bounds = RangeBounds::new(Key(0), Key(100)).unwrap();
        let parts = ReconcileSource::partition(&s, bounds.clone(), 4);
        let expect = partition_by_items(bounds, &local, 4);
        assert_eq!(parts, expect);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].a, Key(0));
        assert_eq!(parts[3].b, Key(100));
        for w in parts.windows(2) {
            assert_eq!(w[0].b, w[1].a);
        }
        assert_eq!(parts[0].b, Key(30));
        assert_eq!(parts[1].b, Key(50));
        assert_eq!(parts[2].b, Key(70));
    }

    #[test]
    fn syncid_partition_equals_partition_range() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        for i in 0..50u64 {
            s.insert(sid(i, i as u8)).unwrap();
        }
        let bounds = RangeBounds::window(0, 100).unwrap();
        assert_eq!(
            ReconcileSource::partition(&s, bounds, 8),
            partition_range(bounds, 8)
        );
        let empty = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        assert_eq!(
            ReconcileSource::partition(&empty, bounds, 8),
            partition_range(bounds, 8)
        );
        let a = SyncId::min_at(5);
        let mut hb = [0u8; 32];
        hb[0] = 0x80;
        let b = SyncId {
            timestamp: 5,
            hash: hb,
        };
        let hash_bounds = RangeBounds::new(a, b).unwrap();
        assert_eq!(
            ReconcileSource::partition(&s, hash_bounds, 8),
            partition_range(hash_bounds, 8)
        );
    }

    #[test]
    fn syncid_hot_tail_tiles_cold_prefix_and_hot_window() {
        let cfg = ReconcileConfig {
            hot_tail: Some(100),
            partitions: 8,
            ..Default::default()
        };
        let s = ReconcileStore::new(cfg).unwrap();
        let bounds = RangeBounds::window(0, 1000).unwrap();
        let parts = ReconcileSource::partition(&s, bounds, 8);
        assert_eq!(parts, partition_range_with_hot(bounds, 8, Some(100)));
        assert_eq!(parts.len(), 9);
        assert_eq!(parts[0].a, bounds.a);
        assert_eq!(parts[0].b, SyncId::min_at(900));
        assert_eq!(parts[8].b, bounds.b);
        for w in parts.windows(2) {
            assert_eq!(w[0].b, w[1].a);
        }
        let hot = RangeBounds::window(900, 1000).unwrap();
        assert_eq!(&parts[1..], partition_range(hot, 8).as_slice());
    }

    #[test]
    fn generic_partition_ignores_hot_tail() {
        let cfg = ReconcileConfig {
            hot_tail: Some(100),
            ..Default::default()
        };
        let mut s = ReconcileStore::new(cfg).unwrap();
        let local: Vec<_> = (1..=8).map(|i| Key(i * 10)).collect();
        for k in &local {
            s.insert(k.clone()).unwrap();
        }
        let bounds = RangeBounds::new(Key(0), Key(100)).unwrap();
        let parts = ReconcileSource::partition(&s, bounds.clone(), 4);
        assert_eq!(parts, partition_by_items(bounds, &local, 4));
    }

    #[test]
    fn bulk_fingerprints_match_per_range() {
        let mut s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        for i in 0..40u64 {
            s.insert(sid(i, i as u8)).unwrap();
        }
        let bounds = [
            RangeBounds::window(0, 10).unwrap(),
            RangeBounds::window(15, 20).unwrap(),
            RangeBounds::window(30, 40).unwrap(),
        ];
        let bulk = ReconcileSource::fingerprint_counts(&s, &bounds);
        let bulk_fp = ReconcileSource::fingerprints(&s, &bounds);
        let bulk_n = ReconcileSource::counts(&s, &bounds);
        assert_eq!(bulk.len(), 3);
        for (i, b) in bounds.iter().enumerate() {
            assert_eq!(bulk[i].0, ReconcileSource::fingerprint(&s, *b));
            assert_eq!(bulk[i].1, ReconcileSource::count(&s, *b));
            assert_eq!(bulk_fp[i], bulk[i].0);
            assert_eq!(bulk_n[i], bulk[i].1);
        }
        assert!(ReconcileSource::fingerprint_counts(&s, &[] as &[RangeBounds]).is_empty());
        assert!(ReconcileSource::fingerprints(&s, &[] as &[RangeBounds]).is_empty());
        assert!(ReconcileSource::counts(&s, &[] as &[RangeBounds]).is_empty());
    }
}
