//! Per-topic [`ReconcileStore`] map keyed by [`psi::hash_bytes`].

use crate::error::{Result, TopicSyncError};
use psi::{hash_bytes, MAX_ITEMS};
use std::collections::HashMap;
use sync::ReconcileStore;

struct TopicEntry {
    topic: Vec<u8>,
    store: ReconcileStore,
}

/// Caller-owned map from topic bytes to a per-topic message-ID store.
///
/// Each topic has its own [`ReconcileStore`]. Mixing topics in one store
/// would leak identifiers from subscriptions the peer does not share.
///
/// [`TopicSync`](crate::TopicSync) borrows this map for the session lifetime.
#[derive(Default)]
pub struct TopicStores {
    inner: HashMap<[u8; 32], TopicEntry>,
}

impl TopicStores {
    /// Empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `topic`. Duplicate topic bytes collapse (the first store is
    /// kept). Errors if the number of distinct topics would exceed
    /// [`MAX_ITEMS`].
    pub fn insert(&mut self, topic: Vec<u8>, store: ReconcileStore) -> Result<()> {
        let hash = hash_bytes(&topic);
        if self.inner.contains_key(&hash) {
            return Ok(());
        }
        if self.inner.len() >= MAX_ITEMS {
            return Err(TopicSyncError::TooManyTopics {
                size: self.inner.len() + 1,
                max: MAX_ITEMS,
            });
        }
        self.inner.insert(hash, TopicEntry { topic, store });
        Ok(())
    }

    /// Number of distinct topics.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no topics are stored.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Store for `topic` bytes, if present.
    pub fn get(&self, topic: &[u8]) -> Option<&ReconcileStore> {
        self.get_by_hash(&hash_bytes(topic))
    }

    /// Mutable store for `topic` bytes, if present.
    pub fn get_mut(&mut self, topic: &[u8]) -> Option<&mut ReconcileStore> {
        self.inner
            .get_mut(&hash_bytes(topic))
            .map(|entry| &mut entry.store)
    }

    /// Store for a PSI topic hash, if present.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&ReconcileStore> {
        self.inner.get(hash).map(|entry| &entry.store)
    }

    /// Original topic bytes for a PSI hash, if present.
    pub fn topic_bytes(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.inner.get(hash).map(|entry| entry.topic.as_slice())
    }

    /// Topic byte strings for [`psi::PsiProtocol::new`].
    pub fn psi_items(&self) -> Vec<Vec<u8>> {
        self.inner
            .values()
            .map(|entry| entry.topic.clone())
            .collect()
    }
}

impl std::fmt::Debug for TopicStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicStores")
            .field("len", &self.inner.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync::{ReconcileConfig, ReconcileStore, SyncId};

    fn empty_store() -> ReconcileStore {
        ReconcileStore::new(ReconcileConfig::default()).unwrap()
    }

    #[test]
    fn insert_get_and_hash() {
        let mut map = TopicStores::new();
        let mut store = empty_store();
        store.insert(SyncId::new(1, [1u8; 32])).unwrap();
        map.insert(b"alpha".to_vec(), store).unwrap();

        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        assert_eq!(map.get(b"alpha").unwrap().len(), 1);
        assert_eq!(map.get_by_hash(&hash_bytes(b"alpha")).unwrap().len(), 1);
        assert_eq!(
            map.topic_bytes(&hash_bytes(b"alpha")),
            Some(b"alpha".as_slice())
        );
        assert!(map.get(b"missing").is_none());
        assert_eq!(map.psi_items(), vec![b"alpha".to_vec()]);
    }

    #[test]
    fn duplicate_topic_keeps_first() {
        let mut map = TopicStores::new();
        let mut first = empty_store();
        first.insert(SyncId::new(1, [1u8; 32])).unwrap();
        map.insert(b"t".to_vec(), first).unwrap();
        map.insert(b"t".to_vec(), empty_store()).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(b"t").unwrap().len(), 1);
    }

    #[test]
    fn get_mut_inserts_into_store() {
        let mut map = TopicStores::new();
        map.insert(b"t".to_vec(), empty_store()).unwrap();
        map.get_mut(b"t")
            .unwrap()
            .insert(SyncId::new(2, [2u8; 32]))
            .unwrap();
        assert_eq!(map.get(b"t").unwrap().len(), 1);
    }
}
