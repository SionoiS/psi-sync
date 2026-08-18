//! `SyncId` — the totally ordered item identifier (LIP-182).

/// All-zero hash. Used as the lower-bound hash of a time cut.
pub const EMPTY_HASH: [u8; 32] = [0u8; 32];

/// All-ones hash. Used as an inclusive-max hash when needed.
pub const FULL_HASH: [u8; 32] = [0xffu8; 32];

/// Item identifier: an ordering key and a 32-byte hash.
///
/// Ordered by timestamp first, then hash. The timestamp unit is the caller's;
/// it is only used to split time intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncId {
    /// Ordering key (caller-defined unit).
    pub timestamp: u64,
    /// 32-byte item hash supplied by the caller.
    pub hash: [u8; 32],
}

impl SyncId {
    /// Construct a `SyncId`.
    pub fn new(timestamp: u64, hash: [u8; 32]) -> Self {
        Self { timestamp, hash }
    }

    /// Lower corner of a time cut: `(timestamp, 0x00…00)`.
    pub fn min_at(timestamp: u64) -> Self {
        Self {
            timestamp,
            hash: EMPTY_HASH,
        }
    }

    /// Upper corner of a time cut: `(timestamp, 0xff…ff)`.
    pub fn max_at(timestamp: u64) -> Self {
        Self {
            timestamp,
            hash: FULL_HASH,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_time_then_hash() {
        let a = SyncId::new(1, [1u8; 32]);
        let b = SyncId::new(2, [0u8; 32]);
        let c = SyncId::new(1, [2u8; 32]);
        assert!(a < b);
        assert!(a < c);
        assert!(c < b);
    }
}
