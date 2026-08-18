//! Range and message types.

use crate::bounds::RangeBounds;
use crate::id::SyncId;

/// Full listing of [`SyncId`]s in a range, plus the two-phase handshake flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSet {
    /// Items in the range, sorted.
    pub elements: Vec<SyncId>,
    /// `false` on first send; `true` when replying so the peer can finish.
    pub reconciled: bool,
}

/// One interval in a reconciliation message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Range {
    /// Already processed; no payload.
    Skip { bounds: RangeBounds },
    /// XOR fingerprint of hashes in `bounds`.
    Fingerprint {
        bounds: RangeBounds,
        fingerprint: [u8; 32],
    },
    /// Explicit item list for a small range.
    Items { bounds: RangeBounds, set: ItemSet },
}

impl Range {
    pub(crate) fn skip(bounds: RangeBounds) -> Self {
        Self::Skip { bounds }
    }

    pub(crate) fn fingerprint(bounds: RangeBounds, fingerprint: [u8; 32]) -> Self {
        Self::Fingerprint {
            bounds,
            fingerprint,
        }
    }

    pub(crate) fn item_set(bounds: RangeBounds, set: ItemSet) -> Self {
        Self::Items { bounds, set }
    }

    pub(crate) fn bounds(&self) -> RangeBounds {
        match *self {
            Self::Skip { bounds }
            | Self::Fingerprint { bounds, .. }
            | Self::Items { bounds, .. } => bounds,
        }
    }

    pub(crate) fn is_skip(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }
}

/// One reconciliation message.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReconcileMessage {
    /// Ranges in partition order. Empty means the session is closing.
    pub ranges: Vec<Range>,
}

impl ReconcileMessage {
    /// Empty closer.
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    /// True if there are no ranges left to process.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Merge adjacent Skip ranges into one spanning Skip.
pub(crate) fn merge_skips(ranges: Vec<Range>) -> Vec<Range> {
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for r in ranges {
        if let Range::Skip { bounds } = r {
            if let Some(Range::Skip { bounds: last }) = out.last_mut() {
                last.b = bounds.b;
                continue;
            }
            out.push(Range::Skip { bounds });
        } else {
            out.push(r);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SyncId;

    #[test]
    fn merge_adjacent_skips() {
        let a = RangeBounds::window(0, 10).unwrap();
        let b = RangeBounds::window(10, 20).unwrap();
        let c = RangeBounds::window(20, 30).unwrap();
        let merged = merge_skips(vec![
            Range::skip(a),
            Range::skip(b),
            Range::fingerprint(c, [1u8; 32]),
        ]);
        assert_eq!(merged.len(), 2);
        assert!(merged[0].is_skip());
        assert_eq!(merged[0].bounds().a, SyncId::min_at(0));
        assert_eq!(merged[0].bounds().b, SyncId::min_at(20));
        assert!(matches!(merged[1], Range::Fingerprint { .. }));
    }
}
