//! Per-topic [`ReconcileStore`] map keyed by [`psi::hash_bytes`].

use crate::error::{Result, TopicSyncError};
use psi::{hash_bytes, HashedItems, MAX_ITEMS};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use sync::ReconcileStore;

struct TopicEntry {
    topic: Vec<u8>,
    store: ReconcileStore,
}

struct Inner {
    map: HashMap<[u8; 32], TopicEntry>,
    hashed: HashedItems,
}

/// Caller-owned map from topic bytes to a per-topic message-ID store.
///
/// Each topic has its own [`ReconcileStore`]. Mixing topics in one store
/// would leak identifiers from subscriptions the peer does not share.
///
/// [`Clone`] is a live alias. Inserts into a topic store (and new topics)
/// are visible to overlapping [`crate::TopicSync`] sessions. PSI still
/// captures the topic set at `initiate` / `respond`.
#[derive(Clone)]
pub struct TopicStores {
    inner: Arc<RwLock<Inner>>,
}

impl Default for TopicStores {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                map: HashMap::new(),
                hashed: HashedItems::default(),
            })),
        }
    }
}

impl TopicStores {
    /// Empty map.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().expect("topic stores lock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().expect("topic stores lock poisoned")
    }

    /// Insert `topic`. Duplicate topic bytes collapse (the first store is
    /// kept). Errors if the number of distinct topics would exceed
    /// [`MAX_ITEMS`].
    pub fn insert(&self, topic: Vec<u8>, store: ReconcileStore) -> Result<()> {
        let hash = hash_bytes(&topic);
        let mut inner = self.write();
        if inner.map.contains_key(&hash) {
            return Ok(());
        }
        if inner.map.len() >= MAX_ITEMS {
            return Err(TopicSyncError::TooManyTopics {
                size: inner.map.len() + 1,
                max: MAX_ITEMS,
            });
        }
        inner.hashed.insert(&topic)?;
        inner.map.insert(hash, TopicEntry { topic, store });
        Ok(())
    }

    /// Number of distinct topics.
    pub fn len(&self) -> usize {
        self.read().map.len()
    }

    /// True if no topics are stored.
    pub fn is_empty(&self) -> bool {
        self.read().map.is_empty()
    }

    /// Live handle to the store for `topic` bytes, if present.
    pub fn get(&self, topic: &[u8]) -> Option<ReconcileStore> {
        self.get_by_hash(&hash_bytes(topic))
    }

    /// Live handle to the store for a PSI topic hash, if present.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<ReconcileStore> {
        self.read().map.get(hash).map(|entry| entry.store.clone())
    }

    /// Original topic bytes for a PSI hash, if present.
    pub fn topic_bytes(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.read().map.get(hash).map(|entry| entry.topic.clone())
    }

    /// Snapshot of the hash-to-curve cache at this instant.
    pub fn hashed(&self) -> HashedItems {
        self.read().hashed.clone()
    }
}

impl std::fmt::Debug for TopicStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicStores")
            .field("len", &self.len())
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
        let map = TopicStores::new();
        let store = empty_store();
        store.insert(SyncId::new(1, [1u8; 32])).unwrap();
        map.insert(b"alpha".to_vec(), store).unwrap();

        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        assert_eq!(map.get(b"alpha").unwrap().len(), 1);
        assert_eq!(map.get_by_hash(&hash_bytes(b"alpha")).unwrap().len(), 1);
        assert_eq!(
            map.topic_bytes(&hash_bytes(b"alpha")).as_deref(),
            Some(b"alpha".as_slice())
        );
        assert!(map.get(b"missing").is_none());
        assert_eq!(map.hashed().len(), 1);
    }

    #[test]
    fn duplicate_topic_keeps_first() {
        let map = TopicStores::new();
        let first = empty_store();
        first.insert(SyncId::new(1, [1u8; 32])).unwrap();
        map.insert(b"t".to_vec(), first).unwrap();
        map.insert(b"t".to_vec(), empty_store()).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(b"t").unwrap().len(), 1);
    }

    #[test]
    fn get_inserts_into_shared_store() {
        let map = TopicStores::new();
        map.insert(b"t".to_vec(), empty_store()).unwrap();
        map.get(b"t")
            .unwrap()
            .insert(SyncId::new(2, [2u8; 32]))
            .unwrap();
        assert_eq!(map.get(b"t").unwrap().len(), 1);
    }
}
