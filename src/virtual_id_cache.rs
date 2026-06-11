//! Per-DID VirtualID cache. Detects rotations and signals re-attestation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVid {
    pub vid_hex: String,
    pub observed_at: DateTime<Utc>,
    /// What input changed last time we saw a rotation. Diagnostic only.
    pub last_rotation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VidObservation {
    /// First time we've ever seen this DID. Cache it.
    FirstSeen,
    /// Same VID as last time. Session continues.
    Unchanged,
    /// Different VID for the same DID. Force re-attestation.
    Rotated { previous: String },
}

#[derive(Clone)]
pub struct VirtualIdCache {
    inner: Arc<RwLock<HashMap<String, CachedVid>>>,
}

impl VirtualIdCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Observe a fresh evidence's VirtualID for a peer DID. Returns the
    /// classification and updates the cache atomically.
    pub async fn observe(&self, peer_did: &str, new_vid_hex: &str) -> VidObservation {
        self.observe_sync(peer_did, new_vid_hex)
    }

    pub fn observe_sync(&self, peer_did: &str, new_vid_hex: &str) -> VidObservation {
        let mut cache = self.inner.write().expect("VID cache poisoned");
        match cache.get(peer_did) {
            None => {
                cache.insert(
                    peer_did.to_string(),
                    CachedVid {
                        vid_hex: new_vid_hex.to_string(),
                        observed_at: Utc::now(),
                        last_rotation_reason: None,
                    },
                );
                VidObservation::FirstSeen
            }
            Some(prev) if prev.vid_hex == new_vid_hex => VidObservation::Unchanged,
            Some(prev) => {
                let previous = prev.vid_hex.clone();
                cache.insert(
                    peer_did.to_string(),
                    CachedVid {
                        vid_hex: new_vid_hex.to_string(),
                        observed_at: Utc::now(),
                        last_rotation_reason: Some("input changed".into()),
                    },
                );
                VidObservation::Rotated { previous }
            }
        }
    }

    pub async fn current_for(&self, peer_did: &str) -> Option<CachedVid> {
        self.current_for_sync(peer_did)
    }

    pub fn current_for_sync(&self, peer_did: &str) -> Option<CachedVid> {
        self.inner
            .read()
            .expect("VID cache poisoned")
            .get(peer_did)
            .cloned()
    }

    pub async fn forget(&self, peer_did: &str) {
        self.inner
            .write()
            .expect("VID cache poisoned")
            .remove(peer_did);
    }

    pub async fn clear(&self) {
        self.clear_sync();
    }

    pub fn clear_sync(&self) {
        self.inner.write().expect("VID cache poisoned").clear();
    }

    pub async fn snapshot(&self) -> HashMap<String, CachedVid> {
        self.snapshot_sync()
    }

    pub fn snapshot_sync(&self) -> HashMap<String, CachedVid> {
        self.inner.read().expect("VID cache poisoned").clone()
    }
}

impl Default for VirtualIdCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vid_cache_classifies_first_unchanged_and_rotated() {
        let cache = VirtualIdCache::new();
        assert_eq!(
            cache.observe_sync("did:guardian:a", "vid-1"),
            VidObservation::FirstSeen
        );
        assert_eq!(
            cache.observe_sync("did:guardian:a", "vid-1"),
            VidObservation::Unchanged
        );
        assert_eq!(
            cache.observe_sync("did:guardian:a", "vid-2"),
            VidObservation::Rotated {
                previous: "vid-1".to_string()
            }
        );
    }
}
