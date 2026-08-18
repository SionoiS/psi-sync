//! LIP-182 range / payload types.

use crate::bounds::RangeBounds;
use crate::error::{ReconcileError, Result};
use crate::id::SyncId;

/// How a range is represented on the wire (LIP-182 `RangeType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RangeType {
    /// Already processed; `content` is empty.
    Skip = 0,
    /// `content` is a 32-byte XOR fingerprint.
    Fingerprint = 1,
    /// `content` is an [`ItemSet`].
    ItemSet = 2,
}

impl RangeType {
    /// Decode a single type byte.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Skip),
            1 => Ok(Self::Fingerprint),
            2 => Ok(Self::ItemSet),
            _ => Err(ReconcileError::CodecError(format!(
                "invalid range type {v}"
            ))),
        }
    }
}

/// Full listing of [`SyncId`]s in a range, plus the two-phase handshake flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSet {
    /// Items in the range, sorted.
    pub elements: Vec<SyncId>,
    /// `false` on first send; `true` when replying so the peer can finish.
    pub reconciled: bool,
}

/// Payload attached to a [`Range`], matching `kind`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeContent {
    /// [`RangeType::Skip`].
    None,
    /// [`RangeType::Fingerprint`].
    Fingerprint([u8; 32]),
    /// [`RangeType::ItemSet`].
    Items(ItemSet),
}

/// One interval in a reconciliation payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// Inclusive–exclusive bounds.
    pub bounds: RangeBounds,
    /// Discriminant.
    pub kind: RangeType,
    /// Content; must match `kind`.
    pub content: RangeContent,
}

impl Range {
    /// Skip range (no content).
    pub fn skip(bounds: RangeBounds) -> Self {
        Self {
            bounds,
            kind: RangeType::Skip,
            content: RangeContent::None,
        }
    }

    /// Fingerprint range.
    pub fn fingerprint(bounds: RangeBounds, fp: [u8; 32]) -> Self {
        Self {
            bounds,
            kind: RangeType::Fingerprint,
            content: RangeContent::Fingerprint(fp),
        }
    }

    /// Item-set range.
    pub fn item_set(bounds: RangeBounds, set: ItemSet) -> Self {
        Self {
            bounds,
            kind: RangeType::ItemSet,
            content: RangeContent::Items(set),
        }
    }

    /// Reject a `kind` / `content` mismatch or `!(a < b)`.
    pub fn validate(&self) -> Result<()> {
        if self.bounds.a >= self.bounds.b {
            return Err(ReconcileError::InvalidBounds);
        }
        match (&self.kind, &self.content) {
            (RangeType::Skip, RangeContent::None)
            | (RangeType::Fingerprint, RangeContent::Fingerprint(_))
            | (RangeType::ItemSet, RangeContent::Items(_)) => Ok(()),
            _ => Err(ReconcileError::PayloadMismatch),
        }
    }
}

/// Cluster / shard filter carried on every payload (LIP-182).
///
/// An empty `shards` list means “all shards”.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SyncScope {
    /// Cluster identifier.
    pub cluster: u64,
    /// Supported shards; empty = all.
    pub shards: Vec<u64>,
}

impl SyncScope {
    /// Unrestricted scope (`cluster = 0`, all shards).
    pub fn any() -> Self {
        Self::default()
    }

    /// True if the two scopes may sync.
    ///
    /// Cluster must match. If both shard lists are non-empty they must
    /// intersect. An empty list is treated as “all shards”.
    pub fn compatible(&self, other: &Self) -> bool {
        if self.cluster != other.cluster {
            return false;
        }
        if self.shards.is_empty() || other.shards.is_empty() {
            return true;
        }
        self.shards.iter().any(|s| other.shards.contains(s))
    }
}

/// One reconciliation message (LIP-182 `RangesData`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangesData {
    /// Sender cluster / shards.
    pub scope: SyncScope,
    /// Ranges in partition order.
    pub ranges: Vec<Range>,
}

impl RangesData {
    /// Payload with no ranges (session terminator).
    pub fn empty(scope: SyncScope) -> Self {
        Self {
            scope,
            ranges: Vec::new(),
        }
    }

    /// True if there are no ranges left to process.
    pub fn is_terminal(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Validate every range.
    pub fn validate(&self) -> Result<()> {
        for r in &self.ranges {
            r.validate()?;
        }
        Ok(())
    }
}

/// Merge adjacent Skip ranges into one spanning Skip.
pub fn merge_skips(ranges: Vec<Range>) -> Vec<Range> {
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for r in ranges {
        if r.kind == RangeType::Skip {
            if let Some(last) = out.last_mut() {
                if last.kind == RangeType::Skip {
                    last.bounds.b = r.bounds.b;
                    continue;
                }
            }
        }
        out.push(r);
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
        assert_eq!(merged[0].kind, RangeType::Skip);
        assert_eq!(merged[0].bounds.a, SyncId::min_at(0));
        assert_eq!(merged[0].bounds.b, SyncId::min_at(20));
        assert_eq!(merged[1].kind, RangeType::Fingerprint);
    }

    #[test]
    fn validate_mismatch() {
        let r = Range {
            bounds: RangeBounds::window(0, 1).unwrap(),
            kind: RangeType::Skip,
            content: RangeContent::Fingerprint([0; 32]),
        };
        assert_eq!(r.validate(), Err(ReconcileError::PayloadMismatch));
    }
}
