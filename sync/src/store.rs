//! Monoid-tree store of reconcilable items.

use crate::bounds::RangeBounds;
use crate::config::ReconcileConfig;
use crate::error::{ReconcileError, Result};
use crate::id::{SyncId, EMPTY_HASH};
use crate::item::ReconcileItem;
use crate::partition::partition_by_nth;
use crate::source::ReconcileSource;
use crate::tree::MonoidTree;
use std::sync::{Arc, Mutex};

/// Ordered set of items plus the reconciliation tunables.
///
/// Insert, remove, and prune take `&self`. Concurrent [`crate::Reconcile`]
/// sessions may share one store; each `step` snapshots the tree so a live
/// insert cannot tear fingerprints. [`Clone`] is a live alias (same tree).
/// [`Self::snapshot`] is an O(1) isolated copy.
#[derive(Debug)]
pub struct ReconcileStore<T: ReconcileItem = SyncId> {
    items: Arc<Mutex<MonoidTree<T>>>,
    config: ReconcileConfig,
}

impl<T: ReconcileItem> Clone for ReconcileStore<T> {
    fn clone(&self) -> Self {
        Self {
            items: Arc::clone(&self.items),
            config: self.config,
        }
    }
}

impl<T: ReconcileItem> ReconcileStore<T> {
    /// Empty store. Rejects an invalid [`ReconcileConfig`].
    pub fn new(config: ReconcileConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            items: Arc::new(Mutex::new(MonoidTree::new())),
            config,
        })
    }

    /// Isolated copy: later inserts on `self` are not visible here.
    pub fn snapshot(&self) -> Self {
        Self {
            items: Arc::new(Mutex::new(self.lock_tree().clone())),
            config: self.config,
        }
    }

    fn lock_tree(&self) -> std::sync::MutexGuard<'_, MonoidTree<T>> {
        self.items.lock().expect("reconcile store lock poisoned")
    }

    /// Store configuration.
    pub fn config(&self) -> &ReconcileConfig {
        &self.config
    }

    /// Insert `id`. Duplicates are ignored. Errors if `max_items` would be exceeded.
    ///
    /// The cap check and the insert share one lock so concurrent inserts
    /// cannot both pass `max_items`.
    pub fn insert(&self, id: T) -> Result<()> {
        let mut items = self.lock_tree();
        if items.len() >= self.config.max_items && !items.contains(&id) {
            return Err(ReconcileError::SetTooLarge {
                size: items.len() + 1,
                max: self.config.max_items,
            });
        }
        items.insert(id);
        Ok(())
    }

    /// Remove `id`. Returns `true` if it was present.
    pub fn remove(&self, id: &T) -> bool {
        self.lock_tree().remove(id)
    }

    /// Number of stored items.
    pub fn len(&self) -> usize {
        self.lock_tree().len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.lock_tree().is_empty()
    }

    /// Items in `[bounds.a, bounds.b)`, in order.
    ///
    /// Walks a snapshot so the lock is not held for the listing.
    pub fn items(&self, bounds: RangeBounds<T>) -> Vec<T> {
        let snap = self.lock_tree().clone();
        snap.iter_range(&bounds.a, &bounds.b).cloned().collect()
    }

    /// Number of items in `bounds`.
    pub fn count(&self, bounds: RangeBounds<T>) -> usize {
        self.lock_tree().count_range(&bounds.a, &bounds.b)
    }

    /// Fingerprint of items in `bounds`. Empty range → [`T::empty_fingerprint`].
    pub fn fingerprint(&self, bounds: RangeBounds<T>) -> T::Fingerprint {
        self.lock_tree().aggregate_range(&bounds.a, &bounds.b)
    }

    /// Fingerprint and count of each sorted, disjoint bound in one tree walk.
    pub fn fingerprint_counts(&self, bounds: &[RangeBounds<T>]) -> Vec<(T::Fingerprint, usize)> {
        self.lock_tree().aggregate_and_count_ranges(bounds)
    }

    /// Fingerprints of sorted, disjoint `bounds` in one tree walk.
    pub fn fingerprints(&self, bounds: &[RangeBounds<T>]) -> Vec<T::Fingerprint> {
        self.lock_tree().aggregate_ranges(bounds)
    }

    /// Counts of sorted, disjoint `bounds` in one tree walk.
    pub fn counts(&self, bounds: &[RangeBounds<T>]) -> Vec<usize> {
        self.lock_tree().count_ranges(bounds)
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
        ReconcileStore::items(self, bounds)
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
        let snap = self.lock_tree().clone();
        let n = snap.count_range(&bounds.a, &bounds.b);
        partition_by_nth(bounds.clone(), n, count, |k| {
            snap.nth_in_range(&bounds.a, &bounds.b, k).cloned()
        })
    }

    fn config(&self) -> &ReconcileConfig {
        ReconcileStore::config(self)
    }

    fn with_view<R>(&self, f: impl FnOnce(&Self) -> R) -> R {
        f(&self.snapshot())
    }
}

impl ReconcileStore<SyncId> {
    /// Drop every item with `timestamp < timestamp`. Returns the number removed.
    ///
    /// In-flight snapshots keep the pruned nodes; new sessions do not see them.
    pub fn prune_before(&self, timestamp: u64) -> usize {
        let bound = SyncId {
            timestamp,
            hash: EMPTY_HASH,
        };
        self.lock_tree().remove_before(&bound)
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
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(2, 1)).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(2, 1)).unwrap();
        assert_eq!(s.len(), 2);
        let v = s.items(RangeBounds::window(0, 10).unwrap());
        assert_eq!(v[0], sid(1, 1));
        assert_eq!(v[1], sid(2, 1));
    }

    #[test]
    fn remove_present_and_absent() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(1, 1)).unwrap();
        assert!(s.remove(&sid(1, 1)));
        assert!(!s.remove(&sid(1, 1)));
        assert!(s.is_empty());
    }

    #[test]
    fn remove_frees_max_items_slot() {
        let cfg = ReconcileConfig {
            max_items: 1,
            ..Default::default()
        };
        let s = ReconcileStore::new(cfg).unwrap();
        s.insert(sid(1, 1)).unwrap();
        assert!(s.remove(&sid(1, 1)));
        s.insert(sid(2, 2)).unwrap();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn prune_before_drops_strictly_older() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(2, 1)).unwrap();
        s.insert(sid(3, 1)).unwrap();
        assert_eq!(s.prune_before(2), 1);
        assert_eq!(s.len(), 2);
        let v = s.items(RangeBounds::window(0, 10).unwrap());
        assert_eq!(v[0], sid(2, 1));
    }

    #[test]
    fn items_exclusive_upper() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(10, 0)).unwrap();
        s.insert(sid(15, 0)).unwrap();
        s.insert(sid(20, 0)).unwrap();
        let bounds = RangeBounds::window(10, 20).unwrap();
        let sl = s.items(bounds);
        assert_eq!(sl.len(), 2);
        assert_eq!(sl[0], sid(10, 0));
        assert_eq!(sl[1], sid(15, 0));
    }

    #[test]
    fn fingerprint_known_set() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
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
        let s = ReconcileStore::new(cfg).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(1, 1)).unwrap();
        assert_eq!(s.len(), 1);
        let err = s.insert(sid(2, 2)).unwrap_err();
        assert!(matches!(err, ReconcileError::SetTooLarge { max: 1, .. }));
    }

    #[test]
    fn generic_partition_tiles_like_items() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
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
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
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
        let s = ReconcileStore::new(cfg).unwrap();
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
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
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

    #[test]
    fn clone_shares_live_tree() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(1, 1)).unwrap();
        let alias = s.clone();
        alias.insert(sid(2, 2)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.items(RangeBounds::window(0, 10).unwrap()),
            alias.items(RangeBounds::window(0, 10).unwrap())
        );
    }

    #[test]
    fn clone_is_snapshot_isolation() {
        let s = ReconcileStore::new(ReconcileConfig::default()).unwrap();
        s.insert(sid(1, 1)).unwrap();
        s.insert(sid(2, 2)).unwrap();
        let snap = s.snapshot();
        let fp = snap.fingerprint(RangeBounds::window(0, 10).unwrap());
        s.insert(sid(3, 3)).unwrap();
        s.remove(&sid(1, 1));
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.fingerprint(RangeBounds::window(0, 10).unwrap()), fp);
        assert_eq!(
            snap.items(RangeBounds::window(0, 10).unwrap()),
            vec![sid(1, 1), sid(2, 2)]
        );
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.items(RangeBounds::window(0, 10).unwrap()),
            vec![sid(2, 2), sid(3, 3)]
        );
    }

    #[test]
    fn concurrent_insert_respects_max_items() {
        let cfg = ReconcileConfig {
            max_items: 50,
            ..Default::default()
        };
        let store = std::sync::Arc::new(ReconcileStore::new(cfg).unwrap());
        let mut joins = Vec::new();
        for t in 0u64..4 {
            let store = store.clone();
            joins.push(std::thread::spawn(move || {
                for i in 0..40u64 {
                    let _ = store.insert(sid(t * 40 + i, i as u8));
                }
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        assert!(store.len() <= 50);
        assert_eq!(store.len(), 50);
    }
}
