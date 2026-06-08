//! Simple in-memory TTL cache for the DID resolver.

use crate::did::document::DidDocument;
use crate::did::resolver::ResolutionSource;
use crate::did::Did;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Clone)]
pub struct CacheEntry {
    pub doc: DidDocument,
    pub fetched_at: SystemTime,
    pub source: ResolutionSource,
}

pub struct ResolverCache {
    entries: HashMap<String, CacheEntry>,
}

impl ResolverCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn get_fresh(&self, did: &Did, ttl: Duration) -> Option<CacheEntry> {
        let entry = self.entries.get(did.as_str())?;
        let age = SystemTime::now()
            .duration_since(entry.fetched_at)
            .unwrap_or(Duration::from_secs(u64::MAX));
        if age < ttl {
            Some(entry.clone())
        } else {
            None
        }
    }

    pub fn put(&mut self, did: Did, entry: CacheEntry) {
        self.entries.insert(did.as_str().to_string(), entry);
    }

    pub fn invalidate(&mut self, did: &Did) {
        self.entries.remove(did.as_str());
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ResolverCache {
    fn default() -> Self {
        Self::new()
    }
}
