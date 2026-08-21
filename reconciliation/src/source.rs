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

    /// Items in `bounds`, in `Item` order.
    fn items(&self, bounds: Self::Bounds) -> Vec<Self::Item>;

    /// Number of items in `bounds`.
    fn count(&self, bounds: Self::Bounds) -> usize;

    /// Covering split of `bounds` into subranges.
    ///
    /// Recency-biased [`crate::SyncId`] splits on [`crate::ReconcileStore`] may
    /// return one cold prefix plus `count` hot slices. Return fewer than two
    /// parts to force an item-set fallback.
    fn partition(&self, bounds: Self::Bounds, count: usize) -> Vec<Self::Bounds>;

    /// Session tunables.
    fn config(&self) -> &ReconcileConfig;
}
