//! Inclusive–exclusive range bounds (LIP-182 `RangeBounds`).

use crate::error::{ReconcileError, Result};
use crate::id::SyncId;

/// A half-open interval: `a` inclusive, `b` exclusive.
///
/// The lower bound MUST be strictly smaller than the upper bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeBounds<T = SyncId> {
    /// Inclusive lower bound.
    pub a: T,
    /// Exclusive upper bound.
    pub b: T,
}

impl<T: Copy> Copy for RangeBounds<T> {}

impl<T: Ord> RangeBounds<T> {
    /// Construct bounds, rejecting `!(a < b)`.
    pub fn new(a: T, b: T) -> Result<Self> {
        if a < b {
            Ok(Self { a, b })
        } else {
            Err(ReconcileError::InvalidBounds)
        }
    }

    /// True if `a <= id < b`.
    pub fn contains(&self, id: &T) -> bool {
        &self.a <= id && id < &self.b
    }
}

impl RangeBounds<SyncId> {
    /// Time window `[min_at(start), min_at(end))`.
    pub fn window(start: u64, end: u64) -> Result<Self> {
        Self::new(SyncId::min_at(start), SyncId::min_at(end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SyncId;

    #[test]
    fn rejects_equal_and_reversed() {
        let x = SyncId::min_at(10);
        assert_eq!(RangeBounds::new(x, x), Err(ReconcileError::InvalidBounds));
        assert_eq!(
            RangeBounds::new(SyncId::min_at(11), SyncId::min_at(10)),
            Err(ReconcileError::InvalidBounds)
        );
    }

    #[test]
    fn contains_inclusive_a_exclusive_b() {
        let bounds = RangeBounds::window(10, 20).unwrap();
        assert!(bounds.contains(&SyncId::min_at(10)));
        assert!(bounds.contains(&SyncId::new(19, [0xff; 32])));
        assert!(!bounds.contains(&SyncId::min_at(20)));
        assert!(!bounds.contains(&SyncId::min_at(9)));
    }

    #[test]
    fn generic_ord_bounds() {
        assert_eq!(
            RangeBounds::new(3u64, 3u64),
            Err(ReconcileError::InvalidBounds)
        );
        let bounds = RangeBounds::new(3u64, 10u64).unwrap();
        assert!(bounds.contains(&3));
        assert!(bounds.contains(&9));
        assert!(!bounds.contains(&10));
        assert!(!bounds.contains(&2));
    }
}
