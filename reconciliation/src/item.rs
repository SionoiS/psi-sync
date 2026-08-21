//! Elements of a reconcilable set.

use crate::bounds::RangeBounds;
use crate::fingerprint::xor_into;
use crate::id::SyncId;
use crate::partition::{partition_by_items, partition_range};
use std::fmt::Debug;

/// Element of a reconcilable set.
///
/// [`Ord`] is the only requirement on the *set*: ranges are `[a, b)` and
/// item lists are merge-walked in that order. [`Self::Fingerprint`] is how
/// the protocol tests range equality without listing items; it is not
/// implied by the order.
///
/// [`Self::combine`] must be associative with [`Self::empty_fingerprint`] as
/// identity so subtree labels in a monoid tree are independent of shape.
/// Multidimensional stores also require commutativity: a 2-D covering
/// combines inner-tree labels across tags, and there is no single in-order
/// of the plane.
pub trait ReconcileItem: Clone + Ord + Debug {
    /// Compact digest of a range. Equal fingerprints mean the two ranges
    /// are treated as containing the same items (collisions are possible).
    type Fingerprint: Clone + Eq + Debug;

    /// Fingerprint of an empty range.
    fn empty_fingerprint() -> Self::Fingerprint;

    /// Fold `item` into a range digest.
    fn accumulate(fp: &mut Self::Fingerprint, item: &Self);

    /// Associative combination of two range fingerprints.
    fn combine(a: &Self::Fingerprint, b: &Self::Fingerprint) -> Self::Fingerprint;

    /// Fingerprint of a singleton `{item}`.
    fn singleton(item: &Self) -> Self::Fingerprint {
        let mut fp = Self::empty_fingerprint();
        Self::accumulate(&mut fp, item);
        fp
    }

    /// Split `[bounds.a, bounds.b)` into at most `count` subranges.
    ///
    /// The default uses [`Self::partition_domain`] when present, otherwise
    /// `local` item values as cut points. Types with a splittable domain
    /// (such as [`SyncId`]) override [`Self::partition_domain`].
    ///
    /// Return fewer than two parts to force an item-set fallback.
    fn partition(
        bounds: RangeBounds<Self>,
        local: &[Self],
        count: usize,
    ) -> Vec<RangeBounds<Self>> {
        if let Some(parts) = Self::partition_domain(bounds.clone(), count) {
            parts
        } else {
            partition_by_items(bounds, local, count)
        }
    }

    /// Domain split of `bounds` (e.g. time/hash). `None` uses item-index cuts.
    fn partition_domain(
        _bounds: RangeBounds<Self>,
        _count: usize,
    ) -> Option<Vec<RangeBounds<Self>>> {
        None
    }
}

impl ReconcileItem for SyncId {
    type Fingerprint = [u8; 32];

    fn empty_fingerprint() -> Self::Fingerprint {
        [0u8; 32]
    }

    fn accumulate(fp: &mut Self::Fingerprint, item: &Self) {
        xor_into(fp, &item.hash);
    }

    fn combine(a: &Self::Fingerprint, b: &Self::Fingerprint) -> Self::Fingerprint {
        let mut out = *a;
        xor_into(&mut out, b);
        out
    }

    fn partition_domain(bounds: RangeBounds<Self>, count: usize) -> Option<Vec<RangeBounds<Self>>> {
        Some(partition_range(bounds, count))
    }
}
