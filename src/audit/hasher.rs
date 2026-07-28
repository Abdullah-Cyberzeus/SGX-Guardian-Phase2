//! Tamper-evident hash chaining for audit logs.

use sha2::{Digest, Sha256};

/// Represents a running audit hash chain.
#[derive(Debug, Clone)]
pub struct AuditHashChain {
    last_hash: String,
}
impl Default for AuditHashChain {
    /// Create a new hash chain with a fixed genesis hash.
    fn default() -> Self {
        Self {
            last_hash: "GENESIS".to_string(),
        }
    }
}
impl AuditHashChain {
    pub fn new() -> Self {
        Self::default()
    }
    /// Returns the current last hash.
    #[allow(dead_code)]
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
    /// Forcefully set the last hash (used for recovery on startup).
    pub fn set_last_hash(&mut self, hash: String) {
        self.last_hash = hash;
    }

    /// Computes the next hash from previous hash + event payload.
    pub fn next_hash(&mut self, payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.last_hash.as_bytes());
        hasher.update(payload.as_bytes());

        let result = format!("{:x}", hasher.finalize());
        self.last_hash = result.clone();
        result
    }
}
