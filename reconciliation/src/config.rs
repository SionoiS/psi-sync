//! Implementation parameters (not LIP MUST values).

use crate::error::{ReconcileError, Result};

/// Defaults used by Nwaku / the LIP implementation notes.
pub const DEFAULT_THRESHOLD: usize = 100;
pub const DEFAULT_PARTITIONS: usize = 8;
pub const DEFAULT_MAX_ITEMS: usize = 1_048_576;
pub const DEFAULT_MAX_ROUNDS: usize = 64;

/// Tunables for store size and the fingerprint / item-set trade-off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileConfig {
    /// Send an item set instead of partitioning when a range has at most this
    /// many local items.
    pub threshold: usize,
    /// Equal-time fanout of a large fingerprint mismatch. When [`Self::hot_tail`]
    /// is set this is the hot-window split, not the total part count.
    pub partitions: usize,
    /// Maximum distinct items in a store.
    pub max_items: usize,
    /// Maximum `step` calls in one session.
    pub max_rounds: usize,
    /// Recency window (time units) used by [`crate::ReconcileStore`] of
    /// [`crate::SyncId`]. [`crate::TaggedStore`] ignores it. `None` keeps
    /// equal-time partitioning.
    ///
    /// A still-too-large mismatch re-applies the cut relative to that range's
    /// `b` (peels `w` time units from the end each round). Recent-suffix diffs
    /// Skip the cold fingerprint in one round. A hole far behind `b` may take
    /// about `span / w` rounds, bounded by [`Self::max_rounds`].
    pub hot_tail: Option<u64>,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            partitions: DEFAULT_PARTITIONS,
            max_items: DEFAULT_MAX_ITEMS,
            max_rounds: DEFAULT_MAX_ROUNDS,
            hot_tail: None,
        }
    }
}

impl ReconcileConfig {
    /// Reject `partitions < 2`, zero threshold, zero caps, `hot_tail = Some(0)`.
    pub fn validate(&self) -> Result<()> {
        if self.partitions < 2 {
            return Err(ReconcileError::InvalidConfig(
                "partitions must be at least 2",
            ));
        }
        if self.threshold == 0 {
            return Err(ReconcileError::InvalidConfig(
                "threshold must be greater than 0",
            ));
        }
        if self.max_items == 0 {
            return Err(ReconcileError::InvalidConfig(
                "max_items must be greater than 0",
            ));
        }
        if self.max_rounds == 0 {
            return Err(ReconcileError::InvalidConfig(
                "max_rounds must be greater than 0",
            ));
        }
        if self.hot_tail == Some(0) {
            return Err(ReconcileError::InvalidConfig(
                "hot_tail must be greater than 0",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        ReconcileConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_bad_partitions() {
        let c = ReconcileConfig {
            partitions: 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReconcileError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_zero_hot_tail() {
        let c = ReconcileConfig {
            hot_tail: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReconcileError::InvalidConfig(_))
        ));
    }
}
