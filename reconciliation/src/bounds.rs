//! Inclusive–exclusive range bounds (LIP-182 `RangeBounds`).

use crate::error::{ReconcileError, Result};
use crate::id::SyncId;

/// A half-open interval of [`SyncId`]s: `a` inclusive, `b` exclusive.
///
/// The lower bound MUST be strictly smaller than the upper bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeBounds {
    /// Inclusive lower bound.
    pub a: SyncId,
    /// Exclusive upper bound.
    pub b: SyncId,
}

impl RangeBounds {
    /// Construct bounds, rejecting `!(a < b)`.
    pub fn new(a: SyncId, b: SyncId) -> Result<Self> {
        if a < b {
            Ok(Self { a, b })
        } else {
            Err(ReconcileError::InvalidBounds)
        }
    }

    /// Time window `[min_at(start), min_at(end))`.
    pub fn window(start: u64, end: u64) -> Result<Self> {
        Self::new(SyncId::min_at(start), SyncId::min_at(end))
    }

    /// True if `a <= id < b`.
    pub fn contains(&self, id: &SyncId) -> bool {
        self.a <= *id && *id < self.b
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
}
