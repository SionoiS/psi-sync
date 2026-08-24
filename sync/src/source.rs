//! Store interface used by the reconciliation session.

use crate::config::ReconcileConfig;
use crate::item::ReconcileItem;

/// Bounds that can appear on a [`crate::Range`].
pub trait SessionBounds: Clone + PartialEq + Eq + std::fmt::Debug {
    /// Item type this span can contain.
    type Item;

    /// True if the span is non-empty (strictly increasing / covering).
    fn is_valid(&self) -> bool;

    /// Absorb `next` into `self` when both are consecutive Skip ranges.
    /// Returns whether the merge happened.
    fn merge_skip(&mut self, next: &Self) -> bool;

    /// True if `item` lies in this span.
    fn contains(&self, item: &Self::Item) -> bool;
}

/// Local set a reconciliation session reads from.
pub trait ReconcileSource {
    /// Set element type.
    type Item: ReconcileItem;
    /// Range descriptor (1-D interval or 2-D rectangle).
    type Bounds: SessionBounds<Item = Self::Item>;

    /// Fingerprint of items in `bounds`.
    fn fingerprint(&self, bounds: Self::Bounds) -> <Self::Item as ReconcileItem>::Fingerprint;

    /// Fingerprints of consecutive `bounds` (partition order).
    ///
    /// Default loops [`Self::fingerprint`]. Stores that can cover sorted
    /// disjoint intervals in one walk should override.
    fn fingerprints(
        &self,
        bounds: &[Self::Bounds],
    ) -> Vec<<Self::Item as ReconcileItem>::Fingerprint> {
        bounds
            .iter()
            .cloned()
            .map(|b| self.fingerprint(b))
            .collect()
    }

    /// Fingerprint and count of each consecutive bound (partition order).
    ///
    /// Default loops [`Self::fingerprint`] and [`Self::count`]. Override to
    /// fill both in one walk.
    fn fingerprint_counts(
        &self,
        bounds: &[Self::Bounds],
    ) -> Vec<(<Self::Item as ReconcileItem>::Fingerprint, usize)> {
        bounds
            .iter()
            .cloned()
            .map(|b| (self.fingerprint(b.clone()), self.count(b)))
            .collect()
    }

    /// Items in `bounds`, in `Item` order.
    fn items(&self, bounds: Self::Bounds) -> Vec<Self::Item>;

    /// Number of items in `bounds`.
    fn count(&self, bounds: Self::Bounds) -> usize;

    /// Counts of consecutive `bounds` (partition order).
    ///
    /// Default loops [`Self::count`].
    fn counts(&self, bounds: &[Self::Bounds]) -> Vec<usize> {
        bounds.iter().cloned().map(|b| self.count(b)).collect()
    }

    /// Covering split of `bounds` into subranges.
    ///
    /// Recency-biased [`crate::SyncId`] splits on [`crate::ReconcileStore`] may
    /// return one cold prefix plus `count` hot slices. Return fewer than two
    /// parts to force an item-set fallback.
    fn partition(&self, bounds: Self::Bounds, count: usize) -> Vec<Self::Bounds>;

    /// Session tunables.
    fn config(&self) -> &ReconcileConfig;
}
