//! 1-D monoid-labeled AVL tree (Meyer, Algorithm 1).
//!
//! Each vertex stores `lift_f` of its subtree and the subtree size. Range
//! fingerprints and counts are path aggregations; insert/delete recompute
//! labels along the rotation path.

use crate::item::ReconcileItem;

pub(crate) struct Node<T: ReconcileItem> {
    pub(crate) value: T,
    left: Option<Box<Node<T>>>,
    right: Option<Box<Node<T>>>,
    height: i8,
    size: usize,
    label: T::Fingerprint,
}

pub(crate) struct MonoidTree<T: ReconcileItem> {
    root: Option<Box<Node<T>>>,
}

impl<T: ReconcileItem> Default for MonoidTree<T> {
    fn default() -> Self {
        Self { root: None }
    }
}

impl<T: ReconcileItem> MonoidTree<T> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        size(&self.root)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    pub(crate) fn contains(&self, value: &T) -> bool {
        let mut t = self.root.as_deref();
        while let Some(n) = t {
            match value.cmp(&n.value) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => t = n.left.as_deref(),
                std::cmp::Ordering::Greater => t = n.right.as_deref(),
            }
        }
        false
    }

    /// Insert `value`. Returns `false` if it was already present.
    pub(crate) fn insert(&mut self, value: T) -> bool {
        let mut inserted = false;
        self.root = insert_node(self.root.take(), value, &mut inserted);
        inserted
    }

    /// Delete `value`. Returns `true` if it was present.
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, value: &T) -> bool {
        let mut removed = false;
        self.root = remove_node(self.root.take(), value, &mut removed);
        removed
    }

    /// Drop every item strictly less than `bound`. Returns the number removed.
    pub(crate) fn remove_before(&mut self, bound: &T) -> usize {
        let before = self.len();
        let (left, right) = split_node(self.root.take(), bound);
        drop(left);
        self.root = right;
        before - self.len()
    }

    /// Fingerprint of items in `[lo, hi)`.
    pub(crate) fn aggregate_range(&self, lo: &T, hi: &T) -> T::Fingerprint {
        if lo >= hi {
            return T::empty_fingerprint();
        }
        aggregate_range(self.root.as_deref(), lo, hi)
    }

    /// Number of items in `[lo, hi)`.
    pub(crate) fn count_range(&self, lo: &T, hi: &T) -> usize {
        if lo >= hi {
            return 0;
        }
        count_range(self.root.as_deref(), lo, hi)
    }

    /// In-order items in `[lo, hi)`.
    pub(crate) fn iter_range(&self, lo: &T, hi: &T) -> RangeIter<'_, T> {
        RangeIter::new(self.root.as_deref(), lo, hi)
    }

    /// Full in-order traversal.
    pub(crate) fn iter(&self) -> Inorder<'_, T> {
        Inorder::new(self.root.as_deref())
    }

    /// Collect items in order.
    pub(crate) fn collect(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }

    /// Build a balanced tree from sorted, unique items. `items` must be strictly increasing.
    pub(crate) fn from_sorted(items: Vec<T>) -> Self {
        Self {
            root: build_sorted(&items),
        }
    }

    #[cfg(test)]
    fn assert_invariants(&self) {
        assert_invariants(self.root.as_deref());
    }
}

impl<T: ReconcileItem> Clone for MonoidTree<T> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}

impl<T: ReconcileItem> Clone for Node<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            left: self.left.clone(),
            right: self.right.clone(),
            height: self.height,
            size: self.size,
            label: self.label.clone(),
        }
    }
}

impl<T: ReconcileItem + std::fmt::Debug> std::fmt::Debug for MonoidTree<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonoidTree")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

fn size<T: ReconcileItem>(n: &Option<Box<Node<T>>>) -> usize {
    n.as_ref().map(|x| x.size).unwrap_or(0)
}

fn height<T: ReconcileItem>(n: &Option<Box<Node<T>>>) -> i8 {
    n.as_ref().map(|x| x.height).unwrap_or(-1)
}

fn label<T: ReconcileItem>(n: &Option<Box<Node<T>>>) -> T::Fingerprint {
    n.as_ref()
        .map(|x| x.label.clone())
        .unwrap_or_else(T::empty_fingerprint)
}

fn pull_up<T: ReconcileItem>(n: &mut Node<T>) {
    n.height = 1 + height(&n.left).max(height(&n.right));
    n.size = 1 + size(&n.left) + size(&n.right);
    n.label = T::combine(
        &T::combine(&label(&n.left), &T::singleton(&n.value)),
        &label(&n.right),
    );
}

fn balance_factor<T: ReconcileItem>(n: &Node<T>) -> i8 {
    height(&n.left) - height(&n.right)
}

fn rotate_left<T: ReconcileItem>(mut n: Box<Node<T>>) -> Box<Node<T>> {
    let mut r = n
        .right
        .take()
        .expect("rotate_left on node with no right child");
    n.right = r.left.take();
    pull_up(&mut n);
    r.left = Some(n);
    pull_up(&mut r);
    r
}

fn rotate_right<T: ReconcileItem>(mut n: Box<Node<T>>) -> Box<Node<T>> {
    let mut l = n
        .left
        .take()
        .expect("rotate_right on node with no left child");
    n.left = l.right.take();
    pull_up(&mut n);
    l.right = Some(n);
    pull_up(&mut l);
    l
}

fn rebalance<T: ReconcileItem>(mut n: Box<Node<T>>) -> Box<Node<T>> {
    pull_up(&mut n);
    let bf = balance_factor(&n);
    if bf > 1 {
        if balance_factor(n.left.as_ref().unwrap()) < 0 {
            n.left = Some(rotate_left(n.left.take().unwrap()));
        }
        rotate_right(n)
    } else if bf < -1 {
        if balance_factor(n.right.as_ref().unwrap()) > 0 {
            n.right = Some(rotate_right(n.right.take().unwrap()));
        }
        rotate_left(n)
    } else {
        n
    }
}

fn insert_node<T: ReconcileItem>(
    node: Option<Box<Node<T>>>,
    value: T,
    inserted: &mut bool,
) -> Option<Box<Node<T>>> {
    let Some(mut n) = node else {
        *inserted = true;
        return Some(Box::new(Node {
            label: T::singleton(&value),
            value,
            left: None,
            right: None,
            height: 0,
            size: 1,
        }));
    };
    match value.cmp(&n.value) {
        std::cmp::Ordering::Equal => {
            n.value = value;
            Some(n)
        }
        std::cmp::Ordering::Less => {
            n.left = insert_node(n.left.take(), value, inserted);
            Some(rebalance(n))
        }
        std::cmp::Ordering::Greater => {
            n.right = insert_node(n.right.take(), value, inserted);
            Some(rebalance(n))
        }
    }
}

fn min_node<T: ReconcileItem>(n: &Node<T>) -> &Node<T> {
    let mut cur = n;
    while let Some(left) = cur.left.as_deref() {
        cur = left;
    }
    cur
}

fn remove_node<T: ReconcileItem>(
    node: Option<Box<Node<T>>>,
    value: &T,
    removed: &mut bool,
) -> Option<Box<Node<T>>> {
    let mut n = node?;
    match value.cmp(&n.value) {
        std::cmp::Ordering::Less => {
            n.left = remove_node(n.left.take(), value, removed);
            Some(rebalance(n))
        }
        std::cmp::Ordering::Greater => {
            n.right = remove_node(n.right.take(), value, removed);
            Some(rebalance(n))
        }
        std::cmp::Ordering::Equal => {
            *removed = true;
            match (n.left.take(), n.right.take()) {
                (None, right) => right,
                (left, None) => left,
                (left, Some(right)) => {
                    let succ = min_node(&right).value.clone();
                    let mut dummy = false;
                    let right = remove_node(Some(right), &succ, &mut dummy);
                    n.value = succ;
                    n.left = left;
                    n.right = right;
                    Some(rebalance(n))
                }
            }
        }
    }
}

fn build_sorted<T: ReconcileItem>(items: &[T]) -> Option<Box<Node<T>>> {
    if items.is_empty() {
        return None;
    }
    let mid = items.len() / 2;
    let mut n = Box::new(Node {
        value: items[mid].clone(),
        left: build_sorted(&items[..mid]),
        right: build_sorted(&items[mid + 1..]),
        height: 0,
        size: 0,
        label: T::empty_fingerprint(),
    });
    pull_up(&mut n);
    Some(n)
}

type Split<T> = (Option<Box<Node<T>>>, Option<Box<Node<T>>>);

/// Split into `(< key, >= key)`.
fn split_node<T: ReconcileItem>(node: Option<Box<Node<T>>>, key: &T) -> Split<T> {
    let Some(mut n) = node else {
        return (None, None);
    };
    if n.value.cmp(key) == std::cmp::Ordering::Less {
        let (rl, rr) = split_node(n.right.take(), key);
        n.right = rl;
        (Some(rebalance(n)), rr)
    } else {
        let (ll, lr) = split_node(n.left.take(), key);
        n.left = lr;
        (ll, Some(rebalance(n)))
    }
}

/// Highest node whose value lies in `[lo, hi)`, or `None`.
fn find_initial<'a, T: ReconcileItem>(
    mut t: Option<&'a Node<T>>,
    lo: &T,
    hi: &T,
) -> Option<&'a Node<T>> {
    while let Some(n) = t {
        if n.value < *lo {
            t = n.right.as_deref();
        } else if n.value >= *hi {
            t = n.left.as_deref();
        } else {
            return Some(n);
        }
    }
    None
}

/// Fingerprint of `{z in t | z >= lo}` (Algorithm 1 `AGGREGATE_LEFT`).
fn aggregate_left<T: ReconcileItem>(mut t: Option<&Node<T>>, lo: &T) -> T::Fingerprint {
    let mut acc = T::empty_fingerprint();
    while let Some(n) = t {
        if n.value < *lo {
            t = n.right.as_deref();
        } else if n.value == *lo {
            return T::combine(&T::combine(&T::singleton(&n.value), &label(&n.right)), &acc);
        } else {
            acc = T::combine(&T::combine(&T::singleton(&n.value), &label(&n.right)), &acc);
            t = n.left.as_deref();
        }
    }
    acc
}

/// Fingerprint of `{z in t | z < hi}` (Algorithm 1 `AGGREGATE_RIGHT`).
fn aggregate_right<T: ReconcileItem>(mut t: Option<&Node<T>>, hi: &T) -> T::Fingerprint {
    let mut acc = T::empty_fingerprint();
    while let Some(n) = t {
        if n.value >= *hi {
            if n.value == *hi {
                return T::combine(&acc, &label(&n.left));
            }
            t = n.left.as_deref();
        } else {
            acc = T::combine(&acc, &T::combine(&label(&n.left), &T::singleton(&n.value)));
            t = n.right.as_deref();
        }
    }
    acc
}

fn aggregate_range<T: ReconcileItem>(t: Option<&Node<T>>, lo: &T, hi: &T) -> T::Fingerprint {
    let Some(init) = find_initial(t, lo, hi) else {
        return T::empty_fingerprint();
    };
    let left = aggregate_left(init.left.as_deref(), lo);
    let right = aggregate_right(init.right.as_deref(), hi);
    T::combine(&T::combine(&left, &T::singleton(&init.value)), &right)
}

fn count_left<T: ReconcileItem>(mut t: Option<&Node<T>>, lo: &T) -> usize {
    let mut acc = 0usize;
    while let Some(n) = t {
        if n.value < *lo {
            t = n.right.as_deref();
        } else if n.value == *lo {
            return 1 + size(&n.right) + acc;
        } else {
            acc += 1 + size(&n.right);
            t = n.left.as_deref();
        }
    }
    acc
}

fn count_right<T: ReconcileItem>(mut t: Option<&Node<T>>, hi: &T) -> usize {
    let mut acc = 0usize;
    while let Some(n) = t {
        if n.value >= *hi {
            if n.value == *hi {
                return acc + size(&n.left);
            }
            t = n.left.as_deref();
        } else {
            acc += size(&n.left) + 1;
            t = n.right.as_deref();
        }
    }
    acc
}

fn count_range<T: ReconcileItem>(t: Option<&Node<T>>, lo: &T, hi: &T) -> usize {
    let Some(init) = find_initial(t, lo, hi) else {
        return 0;
    };
    count_left(init.left.as_deref(), lo) + 1 + count_right(init.right.as_deref(), hi)
}

pub struct RangeIter<'a, T: ReconcileItem> {
    stack: Vec<&'a Node<T>>,
    hi: T,
}

impl<'a, T: ReconcileItem> RangeIter<'a, T> {
    fn new(root: Option<&'a Node<T>>, lo: &T, hi: &T) -> Self {
        let mut iter = Self {
            stack: Vec::new(),
            hi: hi.clone(),
        };
        iter.push_left(root, lo);
        iter
    }

    fn push_left(&mut self, mut n: Option<&'a Node<T>>, lo: &T) {
        while let Some(cur) = n {
            if cur.value < *lo {
                n = cur.right.as_deref();
            } else {
                self.stack.push(cur);
                n = cur.left.as_deref();
            }
        }
    }
}

impl<'a, T: ReconcileItem> Iterator for RangeIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.stack.pop()?;
        if n.value >= self.hi {
            self.stack.clear();
            return None;
        }
        self.push_left_unbounded(n.right.as_deref());
        Some(&n.value)
    }
}

impl<'a, T: ReconcileItem> RangeIter<'a, T> {
    fn push_left_unbounded(&mut self, mut n: Option<&'a Node<T>>) {
        while let Some(cur) = n {
            self.stack.push(cur);
            n = cur.left.as_deref();
        }
    }
}

pub(crate) struct Inorder<'a, T: ReconcileItem> {
    stack: Vec<&'a Node<T>>,
}

impl<'a, T: ReconcileItem> Inorder<'a, T> {
    fn new(root: Option<&'a Node<T>>) -> Self {
        let mut iter = Self { stack: Vec::new() };
        iter.push_left(root);
        iter
    }

    fn push_left(&mut self, mut n: Option<&'a Node<T>>) {
        while let Some(cur) = n {
            self.stack.push(cur);
            n = cur.left.as_deref();
        }
    }
}

impl<'a, T: ReconcileItem> Iterator for Inorder<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.stack.pop()?;
        self.push_left(n.right.as_deref());
        Some(&n.value)
    }
}

#[cfg(test)]
fn assert_invariants<T: ReconcileItem>(n: Option<&Node<T>>) {
    let Some(n) = n else {
        return;
    };
    assert_eq!(n.size, 1 + size(&n.left) + size(&n.right));
    assert_eq!(n.height, 1 + height(&n.left).max(height(&n.right)));
    let bf = height(&n.left) - height(&n.right);
    assert!(bf.abs() <= 1, "unbalanced AVL node");
    if let Some(l) = n.left.as_deref() {
        assert!(l.value < n.value);
    }
    if let Some(r) = n.right.as_deref() {
        assert!(r.value > n.value);
    }
    let expect = T::combine(
        &T::combine(&label(&n.left), &T::singleton(&n.value)),
        &label(&n.right),
    );
    assert_eq!(n.label, expect);
    assert_invariants(n.left.as_deref());
    assert_invariants(n.right.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::xor_into;
    use crate::id::SyncId;

    fn sid(t: u64, h0: u8) -> SyncId {
        let mut hash = [0u8; 32];
        hash[0] = h0;
        SyncId::new(t, hash)
    }

    fn naive_fp(items: &[SyncId], lo: &SyncId, hi: &SyncId) -> [u8; 32] {
        let mut fp = [0u8; 32];
        for id in items {
            if id >= lo && id < hi {
                xor_into(&mut fp, &id.hash);
            }
        }
        fp
    }

    #[test]
    fn insert_orders_dedups_and_balances() {
        let mut t = MonoidTree::new();
        assert!(t.insert(sid(2, 1)));
        assert!(t.insert(sid(1, 1)));
        assert!(!t.insert(sid(2, 1)));
        assert!(t.insert(sid(3, 1)));
        assert_eq!(t.len(), 3);
        t.assert_invariants();
        let all: Vec<_> = t.iter_range(&sid(0, 0), &sid(10, 0)).cloned().collect();
        assert_eq!(all, vec![sid(1, 1), sid(2, 1), sid(3, 1)]);
    }

    #[test]
    fn fingerprint_matches_naive_scan() {
        let mut t = MonoidTree::new();
        let mut items = Vec::new();
        for i in 0..32u8 {
            let id = sid(u64::from(i), i.wrapping_mul(7));
            t.insert(id);
            items.push(id);
        }
        t.assert_invariants();
        let cases = [
            (sid(0, 0), sid(32, 0)),
            (sid(5, 0), sid(20, 0)),
            (sid(0, 0), sid(1, 0)),
            (sid(31, 0), sid(32, 0)),
            (sid(8, 0), sid(8, 1)),
            (sid(100, 0), sid(200, 0)),
        ];
        for (lo, hi) in cases {
            assert_eq!(t.aggregate_range(&lo, &hi), naive_fp(&items, &lo, &hi));
            let k = items.iter().filter(|id| **id >= lo && **id < hi).count();
            assert_eq!(t.count_range(&lo, &hi), k);
        }
    }

    #[test]
    fn empty_range_is_neutral() {
        let mut t = MonoidTree::new();
        t.insert(sid(1, 1));
        let lo = sid(5, 0);
        let hi = sid(5, 1);
        assert_eq!(t.aggregate_range(&lo, &hi), [0u8; 32]);
        assert_eq!(t.count_range(&lo, &hi), 0);
        assert!(t.iter_range(&lo, &hi).next().is_none());
    }

    #[test]
    fn remove_and_remove_before() {
        let mut t = MonoidTree::new();
        for i in 1..=8u8 {
            t.insert(sid(u64::from(i), i));
        }
        assert!(t.remove(&sid(4, 4)));
        assert!(!t.remove(&sid(4, 4)));
        t.assert_invariants();
        assert_eq!(t.len(), 7);

        let n = t.remove_before(&sid(3, 0));
        assert_eq!(n, 2);
        t.assert_invariants();
        let left: Vec<_> = t.iter_range(&sid(0, 0), &sid(10, 0)).cloned().collect();
        assert_eq!(
            left,
            vec![sid(3, 3), sid(5, 5), sid(6, 6), sid(7, 7), sid(8, 8)]
        );
    }

    #[test]
    fn figure_style_skips_fully_contained_subtree() {
        // Paper Fig. 4 analogue: range that includes a right-child label
        // without visiting that child's descendants individually.
        let mut t = MonoidTree::new();
        let keys = [1u8, 2, 4, 6, 7, 8, 9, 10, 11, 12, 14, 16];
        for k in keys {
            t.insert(sid(u64::from(k), k));
        }
        t.assert_invariants();
        let lo = sid(2, 0);
        let hi = sid(13, 0);
        let got = t.aggregate_range(&lo, &hi);
        let items: Vec<_> = keys.iter().map(|&k| sid(u64::from(k), k)).collect();
        assert_eq!(got, naive_fp(&items, &lo, &hi));
        assert_eq!(t.count_range(&lo, &hi), 9);
    }

    #[test]
    fn sequential_insert_stays_balanced() {
        let mut t = MonoidTree::new();
        for i in 0..200u64 {
            t.insert(sid(i, (i % 251) as u8));
        }
        t.assert_invariants();
        assert_eq!(t.len(), 200);
        assert_eq!(t.count_range(&sid(0, 0), &sid(200, 0)), 200);
    }
}
