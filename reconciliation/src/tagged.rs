//! Tagged items and a 2-D store (tag × total order).

use crate::bounds::RangeBounds;
use crate::config::ReconcileConfig;
use crate::error::{ReconcileError, Result};
use crate::fingerprint::xor_into;
use crate::id::{SyncId, EMPTY_HASH};
use crate::item::ReconcileItem;
use crate::partition::{partition_by_items, partition_by_nth};
use crate::range_tree::RangeTree;
use crate::source::{ReconcileSource, SessionBounds};
use std::collections::BTreeSet;
use std::ops::Bound;

/// Set element with a tag (topic) and a totally ordered item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged<K, T> {
    /// Tag / topic coordinate.
    pub tag: K,
    /// Totally ordered item.
    pub item: T,
}

impl<K, T> Tagged<K, T> {
    /// Construct a tagged item.
    pub fn new(tag: K, item: T) -> Self {
        Self { tag, item }
    }
}

impl<K: Ord, T: Ord> PartialOrd for Tagged<K, T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: Ord, T: Ord> Ord for Tagged<K, T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.tag
            .cmp(&other.tag)
            .then_with(|| self.item.cmp(&other.item))
    }
}

impl<K, T> ReconcileItem for Tagged<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    type Fingerprint = T::Fingerprint;

    fn empty_fingerprint() -> Self::Fingerprint {
        T::empty_fingerprint()
    }

    fn accumulate(fp: &mut Self::Fingerprint, item: &Self) {
        K::accumulate(fp, &item.tag);
        T::accumulate(fp, &item.item);
    }

    fn combine(a: &Self::Fingerprint, b: &Self::Fingerprint) -> Self::Fingerprint {
        T::combine(a, b)
    }
}

/// XOR fingerprint so a `[u8; 32]` tag can mix into a [`SyncId`] digest.
impl ReconcileItem for [u8; 32] {
    type Fingerprint = [u8; 32];

    fn empty_fingerprint() -> Self::Fingerprint {
        [0u8; 32]
    }

    fn accumulate(fp: &mut Self::Fingerprint, item: &Self) {
        xor_into(fp, item);
    }

    fn combine(a: &Self::Fingerprint, b: &Self::Fingerprint) -> Self::Fingerprint {
        let mut out = *a;
        xor_into(&mut out, b);
        out
    }
}

/// Tag span. [`TagRange::one`] is the per-topic query after PSI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagRange<K> {
    /// Lower tag bound.
    pub start: Bound<K>,
    /// Upper tag bound.
    pub end: Bound<K>,
}

impl<K: Clone + Ord> TagRange<K> {
    /// Every tag.
    pub fn all() -> Self {
        Self {
            start: Bound::Unbounded,
            end: Bound::Unbounded,
        }
    }

    /// A single tag.
    pub fn one(tag: K) -> Self {
        Self {
            start: Bound::Included(tag.clone()),
            end: Bound::Included(tag),
        }
    }

    /// Half-open interval `[a, b)`.
    pub fn interval(a: K, b: K) -> Result<Self> {
        if a < b {
            Ok(Self {
                start: Bound::Included(a),
                end: Bound::Excluded(b),
            })
        } else {
            Err(ReconcileError::InvalidBounds)
        }
    }

    /// True if `tag` lies in this span.
    pub fn contains(&self, tag: &K) -> bool {
        ge_start(tag, bound_ref(&self.start)) && lt_end(tag, bound_ref(&self.end))
    }

    fn is_one(&self) -> bool {
        matches!((&self.start, &self.end), (Bound::Included(a), Bound::Included(b)) if a == b)
    }
}

/// Axis-aligned query rectangle: tag span × item interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RectBounds<K, T> {
    /// Tag / topic span.
    pub tag: TagRange<K>,
    /// Item interval `[a, b)`.
    pub item: RangeBounds<T>,
}

impl<K: Clone + Ord, T: Clone + Ord> RectBounds<K, T> {
    /// Rectangle from a tag span and an item interval.
    pub fn new(tag: TagRange<K>, item: RangeBounds<T>) -> Result<Self> {
        if item.a < item.b && tag_range_nonempty(&tag) {
            Ok(Self { tag, item })
        } else {
            Err(ReconcileError::InvalidBounds)
        }
    }

    /// Singleton tag × item window. Safe for hashed topics after PSI.
    pub fn topic(tag: K, item: RangeBounds<T>) -> Result<Self> {
        Self::new(TagRange::one(tag), item)
    }

    /// All tags × item window. Exclusive tags in the window are visible.
    pub fn all_tags(item: RangeBounds<T>) -> Result<Self> {
        Self::new(TagRange::all(), item)
    }

    /// True if `item` lies in the tag span and the item interval.
    pub fn contains(&self, item: &Tagged<K, T>) -> bool {
        self.tag.contains(&item.tag) && self.item.contains(&item.item)
    }
}

impl<K, T> SessionBounds for RectBounds<K, T>
where
    K: Clone + Ord + std::fmt::Debug,
    T: Clone + Ord + std::fmt::Debug,
{
    type Item = Tagged<K, T>;

    fn is_valid(&self) -> bool {
        self.item.a < self.item.b && tag_range_nonempty(&self.tag)
    }

    fn merge_skip(&mut self, next: &Self) -> bool {
        if self.tag == next.tag {
            return self.item.merge_skip(&next.item);
        }
        if self.item == next.item && tag_spans_abut(&self.tag, &next.tag) {
            self.tag.end = next.tag.end.clone();
            true
        } else {
            false
        }
    }

    fn contains(&self, item: &Tagged<K, T>) -> bool {
        RectBounds::contains(self, item)
    }
}

/// In-memory 2-D store: tag × [`ReconcileItem`].
pub struct TaggedStore<T: ReconcileItem = SyncId, K = [u8; 32]>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
{
    tree: RangeTree<K, T>,
    config: ReconcileConfig,
}

impl<T, K> Clone for TaggedStore<T, K>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    fn clone(&self) -> Self {
        let parts = self.tree.flatten_all();
        let mut tree = RangeTree::new();
        tree.rebuild_from(parts);
        Self {
            tree,
            config: self.config,
        }
    }
}

impl<T, K> std::fmt::Debug for TaggedStore<T, K>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaggedStore")
            .field("len", &self.tree.len())
            .finish_non_exhaustive()
    }
}

impl<T, K> TaggedStore<T, K>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    /// Empty store. Rejects an invalid [`ReconcileConfig`].
    pub fn new(config: ReconcileConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            tree: RangeTree::new(),
            config,
        })
    }

    /// Store configuration.
    pub fn config(&self) -> &ReconcileConfig {
        &self.config
    }

    /// Insert `(tag, item)`. Duplicates of the same pair are ignored.
    pub fn insert(&mut self, tag: K, item: T) -> Result<()> {
        if self.tree.len() >= self.config.max_items && !self.tree.contains(&tag, &item) {
            return Err(ReconcileError::SetTooLarge {
                size: self.tree.len() + 1,
                max: self.config.max_items,
            });
        }
        self.tree.insert(tag, item);
        Ok(())
    }

    /// Number of stored points.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Fingerprint of points in `bounds`.
    pub fn fingerprint(&self, bounds: RectBounds<K, T>) -> T::Fingerprint {
        self.tree.fingerprint(
            bound_ref(&bounds.tag.start),
            bound_ref(&bounds.tag.end),
            &bounds.item.a,
            &bounds.item.b,
        )
    }

    /// Points in `bounds`, ordered by tag then item.
    pub fn items(&self, bounds: RectBounds<K, T>) -> Vec<Tagged<K, T>> {
        self.tree
            .collect(
                bound_ref(&bounds.tag.start),
                bound_ref(&bounds.tag.end),
                &bounds.item.a,
                &bounds.item.b,
            )
            .into_iter()
            .map(|(tag, item)| Tagged { tag, item })
            .collect()
    }

    /// Number of points in `bounds`.
    pub fn count(&self, bounds: RectBounds<K, T>) -> usize {
        self.tree.count(
            bound_ref(&bounds.tag.start),
            bound_ref(&bounds.tag.end),
            &bounds.item.a,
            &bounds.item.b,
        )
    }

    fn partition_rect(&self, bounds: RectBounds<K, T>, count: usize) -> Vec<RectBounds<K, T>> {
        partition_rect(self, bounds, count)
    }
}

impl TaggedStore<SyncId, [u8; 32]> {
    /// Drop every item with `timestamp < timestamp`. Returns the number removed.
    pub fn prune_before(&mut self, timestamp: u64) -> usize {
        let bound = SyncId {
            timestamp,
            hash: EMPTY_HASH,
        };
        let before = self.tree.len();
        let mut kept = Vec::new();
        for (tag, items) in self.tree.flatten_all() {
            let rest: Vec<_> = items.into_iter().filter(|id| *id >= bound).collect();
            if !rest.is_empty() {
                kept.push((tag, rest));
            }
        }
        self.tree.clear();
        self.tree.rebuild_from(kept);
        before - self.tree.len()
    }
}

impl<T, K> ReconcileSource for TaggedStore<T, K>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    type Item = Tagged<K, T>;
    type Bounds = RectBounds<K, T>;

    fn fingerprint(&self, bounds: Self::Bounds) -> T::Fingerprint {
        TaggedStore::fingerprint(self, bounds)
    }

    fn items(&self, bounds: Self::Bounds) -> Vec<Tagged<K, T>> {
        TaggedStore::items(self, bounds)
    }

    fn count(&self, bounds: Self::Bounds) -> usize {
        TaggedStore::count(self, bounds)
    }

    fn partition(&self, bounds: Self::Bounds, count: usize) -> Vec<Self::Bounds> {
        self.partition_rect(bounds, count)
    }

    fn config(&self) -> &ReconcileConfig {
        TaggedStore::config(self)
    }
}

fn partition_rect<T, K>(
    store: &TaggedStore<T, K>,
    bounds: RectBounds<K, T>,
    count: usize,
) -> Vec<RectBounds<K, T>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    if count < 2 {
        return Vec::new();
    }

    if bounds.tag.is_one() {
        return partition_one_tag(store, bounds, count);
    }

    let local = store.items(bounds.clone());
    if local.len() < 2 {
        return Vec::new();
    }

    let n_tags = distinct_count(local.iter().map(|p| &p.tag));
    let n_items = distinct_count(local.iter().map(|p| &p.item));
    if n_tags >= n_items {
        split_tag_axis(&bounds, &local, count)
    } else {
        split_item_axis(&bounds, &local, count)
    }
}

fn partition_one_tag<T, K>(
    store: &TaggedStore<T, K>,
    bounds: RectBounds<K, T>,
    count: usize,
) -> Vec<RectBounds<K, T>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    if let Some(parts) = T::partition_domain(bounds.item.clone(), count) {
        return parts
            .into_iter()
            .map(|item| RectBounds {
                tag: bounds.tag.clone(),
                item,
            })
            .collect();
    }
    let Bound::Included(tag) = &bounds.tag.start else {
        return Vec::new();
    };
    let n = store.count(bounds.clone());
    partition_by_nth(bounds.item.clone(), n, count, |k| {
        store
            .tree
            .nth_in_tag(tag, &bounds.item.a, &bounds.item.b, k)
            .cloned()
    })
    .into_iter()
    .map(|item| RectBounds {
        tag: bounds.tag.clone(),
        item,
    })
    .collect()
}

fn distinct_count<I, V>(iter: I) -> usize
where
    I: Iterator<Item = V>,
    V: Ord,
{
    iter.collect::<BTreeSet<_>>().len()
}

fn split_item_axis<K, T>(
    bounds: &RectBounds<K, T>,
    local: &[Tagged<K, T>],
    count: usize,
) -> Vec<RectBounds<K, T>>
where
    K: Clone + Ord,
    T: Clone + Ord,
{
    let items: Vec<T> = local.iter().map(|p| p.item.clone()).collect();
    let mut unique = items;
    unique.sort();
    unique.dedup();
    partition_by_items(bounds.item.clone(), &unique, count)
        .into_iter()
        .map(|item| RectBounds {
            tag: bounds.tag.clone(),
            item,
        })
        .collect()
}

fn split_tag_axis<K, T>(
    bounds: &RectBounds<K, T>,
    local: &[Tagged<K, T>],
    count: usize,
) -> Vec<RectBounds<K, T>>
where
    K: Clone + Ord,
    T: Clone + Ord,
{
    if local.is_empty() {
        return Vec::new();
    }
    let mut tags: Vec<K> = local.iter().map(|p| p.tag.clone()).collect();
    tags.sort();
    tags.dedup();
    if tags.len() < 2 {
        return split_item_axis(bounds, local, count);
    }

    let n = tags.len();
    let mut cuts = Vec::with_capacity(count + 1);
    cuts.push(0);
    for i in 1..count {
        let idx = n * i / count;
        if idx > *cuts.last().unwrap() && idx < n {
            cuts.push(idx);
        }
    }
    cuts.push(n);
    if cuts.len() < 3 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(cuts.len() - 1);
    for (part_i, w) in cuts.windows(2).enumerate() {
        let start = w[0];
        let end = w[1];
        let tag_start = if part_i == 0 {
            bounds.tag.start.clone()
        } else {
            Bound::Included(tags[start].clone())
        };
        let tag_end = if end == n {
            bounds.tag.end.clone()
        } else {
            Bound::Excluded(tags[end].clone())
        };
        out.push(RectBounds {
            tag: TagRange {
                start: tag_start,
                end: tag_end,
            },
            item: bounds.item.clone(),
        });
    }
    out
}

fn bound_ref<K>(b: &Bound<K>) -> Bound<&K> {
    match b {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(k) => Bound::Included(k),
        Bound::Excluded(k) => Bound::Excluded(k),
    }
}

fn ge_start<K: Ord>(k: &K, start: Bound<&K>) -> bool {
    match start {
        Bound::Unbounded => true,
        Bound::Included(a) => k >= a,
        Bound::Excluded(a) => k > a,
    }
}

fn lt_end<K: Ord>(k: &K, end: Bound<&K>) -> bool {
    match end {
        Bound::Unbounded => true,
        Bound::Included(b) => k <= b,
        Bound::Excluded(b) => k < b,
    }
}

fn tag_range_nonempty<K: Ord>(r: &TagRange<K>) -> bool {
    match (&r.start, &r.end) {
        (Bound::Unbounded, _) | (_, Bound::Unbounded) => true,
        (Bound::Included(a), Bound::Included(b)) => a <= b,
        (Bound::Included(a), Bound::Excluded(b)) => a < b,
        (Bound::Excluded(a), Bound::Included(b)) => a < b,
        (Bound::Excluded(a), Bound::Excluded(b)) => a < b,
    }
}

fn tag_spans_abut<K: Ord>(left: &TagRange<K>, right: &TagRange<K>) -> bool {
    match (&left.end, &right.start) {
        (Bound::Excluded(a), Bound::Included(b)) => a == b,
        (Bound::Included(a), Bound::Excluded(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ReconcileError;
    use crate::partition::partition_range;
    use crate::range::{ItemSet, Range, ReconcileMessage};
    use crate::session::{run_pair, Reconcile};
    use crate::source::SessionBounds;
    use crate::ReconcileConfig;

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

    impl ReconcileItem for u8 {
        type Fingerprint = u64;
        fn empty_fingerprint() -> u64 {
            0
        }
        fn accumulate(fp: &mut u64, item: &Self) {
            *fp ^= u64::from(*item);
        }
        fn combine(a: &u64, b: &u64) -> u64 {
            a ^ b
        }
    }

    fn store(points: &[(u8, u64)]) -> TaggedStore<Key, u8> {
        let mut s = TaggedStore::new(ReconcileConfig::default()).unwrap();
        for &(tag, v) in points {
            s.insert(tag, Key(v)).unwrap();
        }
        s
    }

    fn naive_fp(points: &[(u8, u64)], bounds: &RectBounds<u8, Key>) -> u64 {
        let mut fp = 0u64;
        for &(tag, v) in points {
            if bounds.tag.contains(&tag) && bounds.item.contains(&Key(v)) {
                fp ^= u64::from(tag);
                fp ^= v;
            }
        }
        fp
    }

    fn window() -> RangeBounds<Key> {
        RangeBounds::new(Key(0), Key(1_000)).unwrap()
    }

    #[test]
    fn rect_contains_tag_and_item() {
        let b = RectBounds::topic(1, window()).unwrap();
        assert!(b.contains(&Tagged::new(1, Key(1))));
        assert!(!b.contains(&Tagged::new(2, Key(1))));
        assert!(!b.contains(&Tagged::new(1, Key(2_000))));
    }

    #[test]
    fn merge_skip_abutting_item_axis() {
        let tag = TagRange::one(1u8);
        let mut a =
            RectBounds::new(tag.clone(), RangeBounds::new(Key(0), Key(10)).unwrap()).unwrap();
        let b = RectBounds::new(tag, RangeBounds::new(Key(10), Key(20)).unwrap()).unwrap();
        assert!(a.merge_skip(&b));
        assert_eq!(a.item, RangeBounds::new(Key(0), Key(20)).unwrap());
    }

    #[test]
    fn merge_skip_gap_item_axis() {
        let tag = TagRange::one(1u8);
        let mut a =
            RectBounds::new(tag.clone(), RangeBounds::new(Key(0), Key(10)).unwrap()).unwrap();
        let b = RectBounds::new(tag, RangeBounds::new(Key(20), Key(30)).unwrap()).unwrap();
        assert!(!a.merge_skip(&b));
        assert_eq!(a.item, RangeBounds::new(Key(0), Key(10)).unwrap());
    }

    #[test]
    fn merge_skip_abutting_tag_span() {
        let item = RangeBounds::new(Key(0), Key(10)).unwrap();
        let mut a = RectBounds::new(TagRange::interval(1, 3).unwrap(), item.clone()).unwrap();
        let b = RectBounds::new(TagRange::interval(3, 5).unwrap(), item).unwrap();
        assert!(a.merge_skip(&b));
        assert_eq!(a.tag, TagRange::interval(1, 5).unwrap());
    }

    #[test]
    fn merge_skip_gap_tag_span() {
        let item = RangeBounds::new(Key(0), Key(10)).unwrap();
        let mut a = RectBounds::new(TagRange::interval(1, 3).unwrap(), item.clone()).unwrap();
        let b = RectBounds::new(TagRange::interval(4, 5).unwrap(), item).unwrap();
        assert!(!a.merge_skip(&b));
        assert_eq!(a.tag, TagRange::interval(1, 3).unwrap());
    }

    #[test]
    fn item_outside_rect_is_rejected() {
        let alice = store(&[(1, 1)]);
        let s = Reconcile::respond(&alice);
        let bounds = RectBounds::topic(1, window()).unwrap();
        let msg = ReconcileMessage {
            ranges: vec![Range::item_set(
                bounds,
                ItemSet {
                    elements: vec![Tagged::new(9, Key(1))],
                    needed: Vec::new(),
                    reconciled: false,
                },
            )],
        };
        let err = s.step(msg).unwrap_err();
        assert_eq!(err, ReconcileError::ItemOutOfBounds);
    }

    #[test]
    fn insert_dedup_and_count() {
        let mut s = TaggedStore::<Key, u8>::new(ReconcileConfig::default()).unwrap();
        s.insert(1, Key(10)).unwrap();
        s.insert(2, Key(10)).unwrap();
        s.insert(1, Key(10)).unwrap();
        assert_eq!(s.len(), 2);
        let all = RectBounds::all_tags(window()).unwrap();
        assert_eq!(s.count(all.clone()), 2);
        let one = RectBounds::topic(1, window()).unwrap();
        assert_eq!(s.count(one), 1);
    }

    #[test]
    fn fingerprint_matches_naive() {
        let points = [(1u8, 10u64), (1, 20), (2, 10), (2, 30), (5, 15), (8, 40)];
        let s = store(&points);
        let cases = [
            RectBounds::all_tags(window()).unwrap(),
            RectBounds::topic(1, window()).unwrap(),
            RectBounds::topic(9, window()).unwrap(),
            RectBounds::new(
                TagRange::interval(2, 6).unwrap(),
                RangeBounds::new(Key(10), Key(20)).unwrap(),
            )
            .unwrap(),
            RectBounds::new(
                TagRange::interval(1, 9).unwrap(),
                RangeBounds::new(Key(0), Key(100)).unwrap(),
            )
            .unwrap(),
        ];
        for b in cases {
            assert_eq!(s.fingerprint(b.clone()), naive_fp(&points, &b));
            assert_eq!(s.count(b.clone()), {
                points
                    .iter()
                    .filter(|(t, v)| b.tag.contains(t) && b.item.contains(&Key(*v)))
                    .count()
            });
        }
    }

    #[test]
    fn same_item_two_tags_are_two_points() {
        let s = store(&[(1, 7), (2, 7)]);
        let all = RectBounds::all_tags(window()).unwrap();
        assert_eq!(s.count(all.clone()), 2);
        assert_ne!(s.fingerprint(all), 0);
    }

    #[test]
    fn exclusive_tag_outside_rectangle() {
        let alice = store(&[(1, 1), (9, 9)]);
        let bob = store(&[(1, 1)]);
        let bounds = RectBounds::topic(1, window()).unwrap();
        let (ar, br) = run_pair(&alice, &bob, bounds).unwrap();
        assert!(ar.to_send.is_empty() && ar.to_recv.is_empty());
        assert!(br.to_send.is_empty() && br.to_recv.is_empty());
    }

    #[test]
    fn two_d_session_complementary_diff() {
        let alice = store(&[(1, 1), (1, 2), (2, 3)]);
        let bob = store(&[(1, 1), (1, 4), (2, 3)]);
        let bounds = RectBounds::new(TagRange::interval(1, 3).unwrap(), window()).unwrap();
        let (ar, br) = run_pair(&alice, &bob, bounds).unwrap();
        assert_eq!(ar.to_send, vec![Tagged::new(1, Key(2))]);
        assert_eq!(ar.to_recv, vec![Tagged::new(1, Key(4))]);
        assert_eq!(ar.to_send, br.to_recv);
        assert_eq!(ar.to_recv, br.to_send);
    }

    #[test]
    fn two_d_session_above_threshold() {
        let cfg = ReconcileConfig {
            threshold: 2,
            partitions: 4,
            ..Default::default()
        };
        let mut alice = TaggedStore::new(cfg).unwrap();
        let mut bob = TaggedStore::new(cfg).unwrap();
        for t in 0..8u8 {
            for v in 0..8u64 {
                let key = Key(u64::from(t) * 10 + v);
                alice.insert(t, key.clone()).unwrap();
                if v % 2 == 0 {
                    bob.insert(t, key).unwrap();
                }
            }
        }
        let bounds = RectBounds::all_tags(window()).unwrap();
        let (ar, br) = run_pair(&alice, &bob, bounds).unwrap();
        assert_eq!(ar.to_send.len(), 32);
        assert!(ar.to_recv.is_empty());
        assert_eq!(ar.to_send, br.to_recv);
    }

    #[test]
    fn sequential_tags_rebuild() {
        let mut s = TaggedStore::<Key, u8>::new(ReconcileConfig::default()).unwrap();
        for t in 0..=40u8 {
            s.insert(t, Key(u64::from(t))).unwrap();
        }
        let all = RectBounds::all_tags(window()).unwrap();
        assert_eq!(s.count(all.clone()), 41);
        let mut pts = Vec::new();
        for t in 0..=40u8 {
            pts.push((t, u64::from(t)));
        }
        assert_eq!(s.fingerprint(all.clone()), naive_fp(&pts, &all));
    }

    fn sid(t: u64, h0: u8) -> SyncId {
        let mut hash = [0u8; 32];
        hash[0] = h0;
        SyncId::new(t, hash)
    }

    #[test]
    fn prune_before_drops_old_sync_ids() {
        let mut s = TaggedStore::<SyncId>::new(ReconcileConfig::default()).unwrap();
        let tag = [1u8; 32];
        s.insert(tag, sid(1, 1)).unwrap();
        s.insert(tag, sid(2, 2)).unwrap();
        s.insert([2u8; 32], sid(3, 3)).unwrap();
        assert_eq!(s.prune_before(2), 1);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn one_tag_partition_tiles_like_items() {
        let mut s = TaggedStore::<Key, u8>::new(ReconcileConfig::default()).unwrap();
        let tag = 1u8;
        let local: Vec<_> = (1..=8).map(|i| Key(i * 10)).collect();
        for k in &local {
            s.insert(tag, k.clone()).unwrap();
        }
        let item_bounds = RangeBounds::new(Key(0), Key(100)).unwrap();
        let bounds = RectBounds::topic(tag, item_bounds.clone()).unwrap();
        let parts = ReconcileSource::partition(&s, bounds, 4);
        let expect = partition_by_items(item_bounds, &local, 4);
        assert_eq!(parts.len(), expect.len());
        for (got, exp) in parts.iter().zip(expect.iter()) {
            assert_eq!(got.tag, TagRange::one(tag));
            assert_eq!(got.item, *exp);
        }
        assert_eq!(parts[0].item.b, Key(30));
        assert_eq!(parts[1].item.b, Key(50));
        assert_eq!(parts[2].item.b, Key(70));
        assert_eq!(parts[3].item.b, Key(100));
    }

    #[test]
    fn one_tag_syncid_ignores_hot_tail() {
        let cfg = ReconcileConfig {
            hot_tail: Some(100),
            partitions: 8,
            ..Default::default()
        };
        let s = TaggedStore::<SyncId>::new(cfg).unwrap();
        let item_bounds = RangeBounds::window(0, 1000).unwrap();
        let tag = [1u8; 32];
        let bounds = RectBounds::topic(tag, item_bounds).unwrap();
        let parts = ReconcileSource::partition(&s, bounds, 8);
        let expect = partition_range(item_bounds, 8);
        assert_eq!(parts.len(), expect.len());
        for (got, exp) in parts.iter().zip(expect.iter()) {
            assert_eq!(got.tag, TagRange::one(tag));
            assert_eq!(got.item, *exp);
        }
    }
}
