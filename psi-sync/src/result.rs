//! Session result: per-topic message-ID diffs.

use sync::SyncId;

/// Symmetric difference accumulated for one shared topic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopicDiff {
    /// [`psi::hash_bytes`] of the topic.
    pub topic_hash: [u8; 32],
    /// Present locally, missing remotely.
    pub to_send: Vec<SyncId>,
    /// Present remotely, missing locally.
    pub to_recv: Vec<SyncId>,
}

/// Outcome of a completed [`crate::TopicSync`] session.
///
/// One entry per shared topic, in lexicographic PSI-hash order. The crate
/// does not insert `to_recv` into the local stores — same boundary as
/// `sync`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncResult {
    /// Per-topic diffs. Empty if the topic intersection was empty.
    pub topics: Vec<TopicDiff>,
}

impl SyncResult {
    /// Number of shared topics that were reconciled.
    pub fn len(&self) -> usize {
        self.topics.len()
    }

    /// True if no topics were shared (or both stores were empty).
    pub fn is_empty(&self) -> bool {
        self.topics.is_empty()
    }
}
