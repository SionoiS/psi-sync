//! 2-D range tree: outer scapegoat BST on tags, inner monoid trees on items.

use crate::item::ReconcileItem;
use crate::tree::MonoidTree;
use std::ops::Bound;

const ALPHA_INV: f64 = 1.0 / 0.65;

#[derive(Clone, Debug)]
pub(crate) struct YPoint<K, T> {
    pub item: T,
    pub tag: Option<K>,
}

impl<K: Ord, T: Ord> PartialEq for YPoint<K, T> {
    fn eq(&self, other: &Self) -> bool {
        self.item == other.item && self.tag == other.tag
    }
}
impl<K: Ord, T: Ord> Eq for YPoint<K, T> {}

impl<K: Ord, T: Ord> PartialOrd for YPoint<K, T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: Ord, T: Ord> Ord for YPoint<K, T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.item
            .cmp(&other.item)
            .then_with(|| self.tag.cmp(&other.tag))
    }
}

impl<K, T> ReconcileItem for YPoint<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    type Fingerprint = T::Fingerprint;

    fn empty_fingerprint() -> Self::Fingerprint {
        T::empty_fingerprint()
    }

    fn accumulate(fp: &mut Self::Fingerprint, item: &Self) {
        if let Some(tag) = &item.tag {
            K::accumulate(fp, tag);
        }
        T::accumulate(fp, &item.item);
    }

    fn combine(a: &Self::Fingerprint, b: &Self::Fingerprint) -> Self::Fingerprint {
        T::combine(a, b)
    }
}

pub(crate) struct Outer<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    tag: K,
    local: MonoidTree<YPoint<K, T>>,
    inner: MonoidTree<YPoint<K, T>>,
    left: Option<Box<Outer<K, T>>>,
    right: Option<Box<Outer<K, T>>>,
    min_tag: K,
    max_tag: K,
    n_points: usize,
    n_tags: usize,
    height: i8,
}

pub(crate) struct RangeTree<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    root: Option<Box<Outer<K, T>>>,
}

impl<K, T> Default for RangeTree<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    fn default() -> Self {
        Self { root: None }
    }
}

impl<K, T> RangeTree<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        self.root.as_ref().map(|n| n.n_points).unwrap_or(0)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn n_tags(&self) -> usize {
        self.root.as_ref().map(|n| n.n_tags).unwrap_or(0)
    }

    fn height(&self) -> i8 {
        self.root.as_ref().map(|n| n.height).unwrap_or(-1)
    }

    pub(crate) fn contains(&self, tag: &K, item: &T) -> bool {
        let yp = YPoint {
            item: item.clone(),
            tag: Some(tag.clone()),
        };
        self.contains_point(tag, &yp)
    }

    /// n-th item of `tag` in `[item_lo, item_hi)` (0-based).
    pub(crate) fn nth_in_tag(&self, tag: &K, item_lo: &T, item_hi: &T, n: usize) -> Option<&T> {
        let mut t = self.root.as_deref();
        while let Some(node) = t {
            match tag.cmp(&node.tag) {
                std::cmp::Ordering::Equal => {
                    let ylo = item_bound(item_lo);
                    let yhi = item_bound(item_hi);
                    return node.local.nth_in_range(&ylo, &yhi, n).map(|yp| &yp.item);
                }
                std::cmp::Ordering::Less => t = node.left.as_deref(),
                std::cmp::Ordering::Greater => t = node.right.as_deref(),
            }
        }
        None
    }

    pub(crate) fn insert(&mut self, tag: K, item: T) -> bool {
        let yp = YPoint {
            item,
            tag: Some(tag.clone()),
        };
        if self.contains_point(&tag, &yp) {
            return false;
        }
        self.root = insert_outer(self.root.take(), tag, yp);
        if self.height() > max_height(self.n_tags()) {
            self.rebuild();
        }
        true
    }

    /// Delete `(tag, item)`. Returns `true` if it was present.
    pub(crate) fn remove(&mut self, tag: &K, item: &T) -> bool {
        let yp = YPoint {
            item: item.clone(),
            tag: Some(tag.clone()),
        };
        let mut removed = false;
        self.root = remove_outer(self.root.take(), tag, &yp, &mut removed);
        if removed && self.height() > max_height(self.n_tags()) {
            self.rebuild();
        }
        removed
    }

    /// Drop every item strictly less than `bound`. Returns the number removed.
    pub(crate) fn remove_before(&mut self, bound: &T) -> usize {
        let before = self.len();
        let yp = item_bound(bound);
        self.root = prune_outer(self.root.take(), &yp);
        if self.height() > max_height(self.n_tags()) {
            self.rebuild();
        }
        before - self.len()
    }

    fn contains_point(&self, tag: &K, yp: &YPoint<K, T>) -> bool {
        let mut t = self.root.as_deref();
        while let Some(n) = t {
            match tag.cmp(&n.tag) {
                std::cmp::Ordering::Equal => return n.local.contains(yp),
                std::cmp::Ordering::Less => t = n.left.as_deref(),
                std::cmp::Ordering::Greater => t = n.right.as_deref(),
            }
        }
        false
    }

    pub(crate) fn fingerprint(
        &self,
        start: Bound<&K>,
        end: Bound<&K>,
        item_lo: &T,
        item_hi: &T,
    ) -> T::Fingerprint {
        let ylo = item_bound(item_lo);
        let yhi = item_bound(item_hi);
        query_fp(self.root.as_deref(), start, end, &ylo, &yhi)
    }

    pub(crate) fn count(
        &self,
        start: Bound<&K>,
        end: Bound<&K>,
        item_lo: &T,
        item_hi: &T,
    ) -> usize {
        let ylo = item_bound(item_lo);
        let yhi = item_bound(item_hi);
        query_count(self.root.as_deref(), start, end, &ylo, &yhi)
    }

    pub(crate) fn collect(
        &self,
        start: Bound<&K>,
        end: Bound<&K>,
        item_lo: &T,
        item_hi: &T,
    ) -> Vec<(K, T)> {
        let ylo = item_bound(item_lo);
        let yhi = item_bound(item_hi);
        let mut out = Vec::new();
        collect_items(self.root.as_deref(), start, end, &ylo, &yhi, &mut out);
        out
    }

    pub(crate) fn rebuild_from(&mut self, parts: Vec<(K, Vec<T>)>) {
        let prepared: Vec<(K, MonoidTree<YPoint<K, T>>)> = parts
            .into_iter()
            .map(|(tag, items)| {
                let yps: Vec<_> = items
                    .into_iter()
                    .map(|item| YPoint {
                        item,
                        tag: Some(tag.clone()),
                    })
                    .collect();
                (tag, MonoidTree::from_sorted(yps))
            })
            .collect();
        self.root = build_balanced(&prepared).0;
    }

    fn rebuild(&mut self) {
        let parts = flatten(self.root.take());
        self.root = build_balanced(&parts).0;
    }

    pub(crate) fn flatten_all(&self) -> Vec<(K, Vec<T>)> {
        let mut out = Vec::new();
        flatten_owned(self.root.as_deref(), &mut out);
        out
    }
}

fn item_bound<K, T: Clone>(item: &T) -> YPoint<K, T> {
    YPoint {
        item: item.clone(),
        tag: None,
    }
}

fn max_height(n_tags: usize) -> i8 {
    if n_tags <= 1 {
        return 0;
    }
    let h = (n_tags as f64).ln() / ALPHA_INV.ln();
    h.ceil().max(0.0) as i8
}

fn insert_outer<K, T>(
    node: Option<Box<Outer<K, T>>>,
    tag: K,
    yp: YPoint<K, T>,
) -> Option<Box<Outer<K, T>>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let Some(mut n) = node else {
        return Some(new_leaf(tag, yp));
    };
    match tag.cmp(&n.tag) {
        std::cmp::Ordering::Equal => {
            n.local.insert(yp.clone());
            n.inner.insert(yp);
            pull_up_outer(&mut n);
            Some(n)
        }
        std::cmp::Ordering::Less => {
            n.left = insert_outer(n.left.take(), tag, yp.clone());
            n.inner.insert(yp);
            pull_up_outer(&mut n);
            Some(n)
        }
        std::cmp::Ordering::Greater => {
            n.right = insert_outer(n.right.take(), tag, yp.clone());
            n.inner.insert(yp);
            pull_up_outer(&mut n);
            Some(n)
        }
    }
}

fn remove_outer<K, T>(
    node: Option<Box<Outer<K, T>>>,
    tag: &K,
    yp: &YPoint<K, T>,
    removed: &mut bool,
) -> Option<Box<Outer<K, T>>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let mut n = node?;
    match tag.cmp(&n.tag) {
        std::cmp::Ordering::Equal => {
            *removed = n.local.remove(yp);
            if *removed {
                n.inner.remove(yp);
            }
            if n.local.is_empty() {
                return join_outer(n.left.take(), n.right.take());
            }
            if *removed {
                pull_up_outer(&mut n);
            }
            Some(n)
        }
        std::cmp::Ordering::Less => {
            n.left = remove_outer(n.left.take(), tag, yp, removed);
            if *removed {
                n.inner.remove(yp);
                pull_up_outer(&mut n);
            }
            Some(n)
        }
        std::cmp::Ordering::Greater => {
            n.right = remove_outer(n.right.take(), tag, yp, removed);
            if *removed {
                n.inner.remove(yp);
                pull_up_outer(&mut n);
            }
            Some(n)
        }
    }
}

fn prune_outer<K, T>(
    node: Option<Box<Outer<K, T>>>,
    bound: &YPoint<K, T>,
) -> Option<Box<Outer<K, T>>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let mut n = node?;
    match n.inner.iter().next() {
        None => return join_outer(n.left.take(), n.right.take()),
        Some(yp) if yp >= bound => return Some(n),
        Some(_) => {}
    }
    n.left = prune_outer(n.left.take(), bound);
    n.right = prune_outer(n.right.take(), bound);
    n.local.remove_before(bound);
    n.inner.remove_before(bound);
    if n.local.is_empty() {
        return join_outer(n.left.take(), n.right.take());
    }
    pull_up_outer(&mut n);
    Some(n)
}

fn join_outer<K, T>(
    left: Option<Box<Outer<K, T>>>,
    right: Option<Box<Outer<K, T>>>,
) -> Option<Box<Outer<K, T>>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    match (left, right) {
        (None, r) => r,
        (l, None) => l,
        (l, r) => {
            let mut parts = flatten(l);
            parts.extend(flatten(r));
            build_balanced(&parts).0
        }
    }
}

fn new_leaf<K, T>(tag: K, yp: YPoint<K, T>) -> Box<Outer<K, T>>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let mut local = MonoidTree::new();
    let mut inner = MonoidTree::new();
    local.insert(yp.clone());
    inner.insert(yp);
    Box::new(Outer {
        min_tag: tag.clone(),
        max_tag: tag.clone(),
        tag,
        local,
        inner,
        left: None,
        right: None,
        n_points: 1,
        n_tags: 1,
        height: 0,
    })
}

fn pull_up_outer<K, T>(n: &mut Outer<K, T>)
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    n.n_points = n.local.len()
        + n.left.as_ref().map(|x| x.n_points).unwrap_or(0)
        + n.right.as_ref().map(|x| x.n_points).unwrap_or(0);
    n.n_tags = 1
        + n.left.as_ref().map(|x| x.n_tags).unwrap_or(0)
        + n.right.as_ref().map(|x| x.n_tags).unwrap_or(0);
    let lh = n.left.as_ref().map(|x| x.height).unwrap_or(-1);
    let rh = n.right.as_ref().map(|x| x.height).unwrap_or(-1);
    n.height = 1 + lh.max(rh);
    n.min_tag = n
        .left
        .as_ref()
        .map(|x| x.min_tag.clone())
        .unwrap_or_else(|| n.tag.clone());
    n.max_tag = n
        .right
        .as_ref()
        .map(|x| x.max_tag.clone())
        .unwrap_or_else(|| n.tag.clone());
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

pub(crate) fn tag_in_range<K: Ord>(k: &K, start: Bound<&K>, end: Bound<&K>) -> bool {
    ge_start(k, start) && lt_end(k, end)
}

fn bbox_disjoint<K: Ord>(min_t: &K, max_t: &K, start: Bound<&K>, end: Bound<&K>) -> bool {
    !ge_start(max_t, start) || !lt_end(min_t, end)
}

fn bbox_contained<K: Ord>(min_t: &K, max_t: &K, start: Bound<&K>, end: Bound<&K>) -> bool {
    tag_in_range(min_t, start, end) && tag_in_range(max_t, start, end)
}

fn query_fp<K, T>(
    n: Option<&Outer<K, T>>,
    start: Bound<&K>,
    end: Bound<&K>,
    ylo: &YPoint<K, T>,
    yhi: &YPoint<K, T>,
) -> T::Fingerprint
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let Some(n) = n else {
        return T::empty_fingerprint();
    };
    if bbox_disjoint(&n.min_tag, &n.max_tag, start, end) {
        return T::empty_fingerprint();
    }
    if bbox_contained(&n.min_tag, &n.max_tag, start, end) {
        return n.inner.aggregate_range(ylo, yhi);
    }
    let mut acc = query_fp(n.left.as_deref(), start, end, ylo, yhi);
    if tag_in_range(&n.tag, start, end) {
        acc = T::combine(&acc, &n.local.aggregate_range(ylo, yhi));
    }
    T::combine(&acc, &query_fp(n.right.as_deref(), start, end, ylo, yhi))
}

fn query_count<K, T>(
    n: Option<&Outer<K, T>>,
    start: Bound<&K>,
    end: Bound<&K>,
    ylo: &YPoint<K, T>,
    yhi: &YPoint<K, T>,
) -> usize
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let Some(n) = n else {
        return 0;
    };
    if bbox_disjoint(&n.min_tag, &n.max_tag, start, end) {
        return 0;
    }
    if bbox_contained(&n.min_tag, &n.max_tag, start, end) {
        return n.inner.count_range(ylo, yhi);
    }
    let mut acc = query_count(n.left.as_deref(), start, end, ylo, yhi);
    if tag_in_range(&n.tag, start, end) {
        acc += n.local.count_range(ylo, yhi);
    }
    acc + query_count(n.right.as_deref(), start, end, ylo, yhi)
}

fn collect_items<K, T>(
    n: Option<&Outer<K, T>>,
    start: Bound<&K>,
    end: Bound<&K>,
    ylo: &YPoint<K, T>,
    yhi: &YPoint<K, T>,
    out: &mut Vec<(K, T)>,
) where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let Some(n) = n else {
        return;
    };
    if bbox_disjoint(&n.min_tag, &n.max_tag, start, end) {
        return;
    }
    collect_items(n.left.as_deref(), start, end, ylo, yhi, out);
    if tag_in_range(&n.tag, start, end) {
        for yp in n.local.iter_range(ylo, yhi) {
            if let Some(tag) = yp.tag.clone() {
                out.push((tag, yp.item.clone()));
            }
        }
    }
    collect_items(n.right.as_deref(), start, end, ylo, yhi, out);
}

fn flatten<K, T>(node: Option<Box<Outer<K, T>>>) -> Vec<(K, MonoidTree<YPoint<K, T>>)>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let Some(n) = node else {
        return Vec::new();
    };
    let mut out = flatten(n.left);
    if !n.local.is_empty() {
        out.push((n.tag, n.local));
    }
    out.extend(flatten(n.right));
    out
}

fn flatten_owned<K, T>(n: Option<&Outer<K, T>>, out: &mut Vec<(K, Vec<T>)>)
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    let Some(n) = n else {
        return;
    };
    flatten_owned(n.left.as_deref(), out);
    if !n.local.is_empty() {
        let items = n.local.iter().map(|yp| yp.item.clone()).collect();
        out.push((n.tag.clone(), items));
    }
    flatten_owned(n.right.as_deref(), out);
}

type BuiltOuter<K, T> = (Option<Box<Outer<K, T>>>, Vec<YPoint<K, T>>);

fn build_balanced<K, T>(tags: &[(K, MonoidTree<YPoint<K, T>>)]) -> BuiltOuter<K, T>
where
    K: ReconcileItem<Fingerprint = T::Fingerprint>,
    T: ReconcileItem,
{
    if tags.is_empty() {
        return (None, Vec::new());
    }
    let mid = tags.len() / 2;
    let (left, lpts) = build_balanced(&tags[..mid]);
    let mid_pts = tags[mid].1.collect();
    let (right, rpts) = build_balanced(&tags[mid + 1..]);
    let pts = merge_sorted(merge_sorted(lpts, mid_pts), rpts);
    let inner = MonoidTree::from_sorted(pts.clone());
    let mut node = Box::new(Outer {
        tag: tags[mid].0.clone(),
        local: tags[mid].1.clone(),
        inner,
        left,
        right,
        min_tag: tags[mid].0.clone(),
        max_tag: tags[mid].0.clone(),
        n_points: 0,
        n_tags: 0,
        height: 0,
    });
    pull_up_outer(&mut node);
    (Some(node), pts)
}

fn merge_sorted<T: Ord>(a: Vec<T>, b: Vec<T>) -> Vec<T> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let mut ia = a.into_iter();
    let mut ib = b.into_iter();
    let mut na = ia.next();
    let mut nb = ib.next();
    loop {
        match (na, nb) {
            (Some(x), Some(y)) => {
                if x <= y {
                    out.push(x);
                    na = ia.next();
                    nb = Some(y);
                } else {
                    out.push(y);
                    nb = ib.next();
                    na = Some(x);
                }
            }
            (Some(x), None) => {
                out.push(x);
                out.extend(ia);
                break;
            }
            (None, Some(y)) => {
                out.push(y);
                out.extend(ib);
                break;
            }
            (None, None) => break,
        }
    }
    out
}
