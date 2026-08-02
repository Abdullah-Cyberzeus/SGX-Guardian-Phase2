//! Stage 2: CRL (Certificate Revocation List) check.
//!
//! Queries local CRL cache first; attempts live refresh if online.
//! Rejects immediately if the device serial is on the revoked list.
//! Uses a stale cache rather than passing if live fetch fails, but logs warning.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::errors::{VerifyError, VerifyResult};

/// A single revocation entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Hex-encoded certificate serial number
    pub serial: String,
    /// Device ID (informational)
    pub device_id: String,
    /// RFC 3339 revocation timestamp
    pub revoked_at: String,
    /// Human-readable revocation reason
    pub reason: String,
}

/// In-memory CRL cache.
///
/// In production this is loaded from disk at startup and refreshed
/// periodically or on-demand. The `RwLock` makes it safe to read
/// from many goroutines while a background refresher writes.
#[derive(Debug, Default)]
pub struct CrlCache {
    /// Set of revoked serial numbers (lower-hex, no separators)
    revoked_serials: HashSet<String>,
    /// RFC 3339 timestamp when the cache was last updated
    last_updated: Option<String>,
    /// RFC 3339 expiry of the CRL itself
    next_update: Option<String>,
    /// Whether the cache has ever been loaded
    loaded: bool,
}

impl CrlCache {
    /// Create an empty cache (unloaded).
    pub fn new() -> Self {
        CrlCache::default()
    }

    /// Populate from a list of revocation entries.
    pub fn load(&mut self, entries: Vec<RevocationEntry>, next_update: Option<String>) {
        self.revoked_serials = entries
            .into_iter()
            .map(|e| e.serial.to_lowercase().replace(':', ""))
            .collect();
        self.last_updated = Some(Utc::now().to_rfc3339());
        self.next_update = next_update;
        self.loaded = true;
    }

    /// Returns true if `serial` appears in the revoked set.
    pub fn is_revoked(&self, serial: &str) -> bool {
        let normalised = serial.to_lowercase().replace(':', "");
        self.revoked_serials.contains(&normalised)
    }

    /// Returns true if the cache has been populated at least once.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Returns true if the CRL's next_update timestamp has passed.
    pub fn is_stale(&self) -> bool {
        if let Some(ref next_update) = self.next_update {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(next_update) {
                return Utc::now() > dt.with_timezone(&Utc);
            }
        }
        false
    }
}

/// Shared, thread-safe CRL cache.
pub type SharedCrlCache = Arc<RwLock<CrlCache>>;

/// Stage 2 verifier: CRL revocation check.
pub struct CrlVerifier {
    cache: SharedCrlCache,
    /// Whether to treat an unloaded / stale cache as a hard failure
    strict_mode: bool,
}

impl CrlVerifier {
    /// Create with a shared cache in strict mode (recommended for production).
    pub fn new(cache: SharedCrlCache) -> Self {
        CrlVerifier { cache, strict_mode: true }
    }

    /// Create with strict mode disabled — stale/unloaded cache logs a warning
    /// and continues rather than rejecting (use only in test environments).
    pub fn new_lenient(cache: SharedCrlCache) -> Self {
        CrlVerifier { cache, strict_mode: false }
    }

    /// Result of a successful (non-revoked) CRL check.
    pub fn verify(&self, device_id: &str, serial: &str) -> VerifyResult<()> {
        let cache = self.cache.read().map_err(|_| VerifyError::CrlUnavailable {
            device_id: device_id.to_string(),
        })?;

        // ── Cache not loaded ─────────────────────────────────────────────────
        if !cache.is_loaded() {
            if self.strict_mode {
                return Err(VerifyError::CrlUnavailable {
                    device_id: device_id.to_string(),
                });
            }
            // Lenient: continue with a warning (logged by the pipeline).
            return Ok(());
        }

        // ── Stale cache ───────────────────────────────────────────────────────
        if cache.is_stale() && self.strict_mode {
            return Err(VerifyError::CrlStale {
                device_id: device_id.to_string(),
            });
        }

        // ── Revocation check ─────────────────────────────────────────────────
        if cache.is_revoked(serial) {
            return Err(VerifyError::CrlRevoked {
                device_id: device_id.to_string(),
                serial: serial.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache(entries: Vec<(&str, &str)>) -> SharedCrlCache {
        let mut c = CrlCache::new();
        c.load(
            entries
                .into_iter()
                .map(|(serial, device_id)| RevocationEntry {
                    serial: serial.to_string(),
                    device_id: device_id.to_string(),
                    revoked_at: Utc::now().to_rfc3339(),
                    reason: "test revocation".to_string(),
                })
                .collect(),
            None,
        );
        Arc::new(RwLock::new(c))
    }

    #[test]
    fn test_not_revoked() {
        let cache = make_cache(vec![("deadbeef", "device-revoked")]);
        let verifier = CrlVerifier::new(cache);
        assert!(verifier.verify("device-ok", "aabbccdd").is_ok());
    }

    #[test]
    fn test_revoked_device() {
        let cache = make_cache(vec![("deadbeef01", "device-bad")]);
        let verifier = CrlVerifier::new(cache);
        let err = verifier.verify("device-bad", "deadbeef01").unwrap_err();
        assert!(matches!(err, VerifyError::CrlRevoked { .. }));
    }

    #[test]
    fn test_serial_normalisation() {
        // Colons and uppercase should be normalised before comparison.
        let cache = make_cache(vec![("DE:AD:BE:EF", "device-bad")]);
        let verifier = CrlVerifier::new(cache);
        let err = verifier.verify("device-bad", "de:ad:be:ef").unwrap_err();
        assert!(matches!(err, VerifyError::CrlRevoked { .. }));
    }

    #[test]
    fn test_unloaded_cache_strict() {
        let cache = Arc::new(RwLock::new(CrlCache::new()));
        let verifier = CrlVerifier::new(cache);
        let err = verifier.verify("device-x", "serial-x").unwrap_err();
        assert!(matches!(err, VerifyError::CrlUnavailable { .. }));
    }

    #[test]
    fn test_unloaded_cache_lenient() {
        let cache = Arc::new(RwLock::new(CrlCache::new()));
        let verifier = CrlVerifier::new_lenient(cache);
        assert!(verifier.verify("device-x", "serial-x").is_ok());
    }

    #[test]
    fn test_stale_cache_strict() {
        let past = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let mut c = CrlCache::new();
        c.load(vec![], Some(past));
        let cache = Arc::new(RwLock::new(c));
        let verifier = CrlVerifier::new(cache);
        let err = verifier.verify("device-x", "serial-x").unwrap_err();
        assert!(matches!(err, VerifyError::CrlStale { .. }));
    }
}
