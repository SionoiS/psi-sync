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
pub trait ReconcileItem: Clone + Ord {
    /// Compact digest of a range. Equal fingerprints mean the two ranges
    /// are treated as containing the same items (collisions are possible).
    type Fingerprint: Clone + Eq + Debug;

    /// Fingerprint of an empty range.
    fn empty_fingerprint() -> Self::Fingerprint;

    /// Fold `item` into a range digest.
    fn accumulate(fp: &mut Self::Fingerprint, item: &Self);

    /// Split `[bounds.a, bounds.b)` into at most `count` subranges.
    ///
    /// The default uses `local` item values as cut points, which needs only
    /// [`Ord`]. Types with a splittable domain (such as [`SyncId`]) may
    /// override this.
    ///
    /// Return fewer than two parts to force an item-set fallback.
    fn partition(
        bounds: RangeBounds<Self>,
        local: &[Self],
        count: usize,
    ) -> Vec<RangeBounds<Self>> {
        partition_by_items(bounds, local, count)
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

    fn partition(
        bounds: RangeBounds<Self>,
        _local: &[Self],
        count: usize,
    ) -> Vec<RangeBounds<Self>> {
        partition_range(bounds, count)
    }
}
