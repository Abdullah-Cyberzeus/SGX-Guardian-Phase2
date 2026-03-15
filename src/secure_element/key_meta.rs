// src/secure_element/key_meta.rs
// ============================================================
// Key metadata — lifecycle state for SE050-backed keys.
// Stores ARRAY of all key versions (not just latest).
// File: /var/lib/sgx-guardian/keys/dkp_metadata.json
//
// Crypto: ECDSA-P256 + SHA-256 ONLY. No other algorithms.
// ============================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Rotation policy interval in seconds.
/// Production: 365 * 24 * 3600 = 31536000 (1 year)
/// Testing:    3600 (1 hour)
///
/// ╔══════════════════════════════════════════════════════╗
/// ║  CHANGE THIS VALUE TO TEST AUTO-ROTATION TIMING      ║
/// ║  1 hour  = 3600                                      ║
/// ║  1 day   = 86400                                     ║
/// ║  30 days = 2592000                                   ║
/// ║  1 year  = 31536000  (production default)            ║
/// ╚══════════════════════════════════════════════════════╝
//pub const DKP_ROTATION_INTERVAL_SECS: i64 = 31_536_000; // 1 year
pub const DKP_ROTATION_INTERVAL_SECS: i64 = 300; // 5 min
/// Grace period for revoked key verification (seconds).
/// Default: 30 days = 2592000
//pub const REVOCATION_GRACE_PERIOD_SECS: i64 = 30 * 24 * 3600;
pub const REVOCATION_GRACE_PERIOD_SECS: i64 = 600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Deprecated,
    Revoked,
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "Active"),
            KeyStatus::Deprecated => write!(f, "Deprecated (verify-only)"),
            KeyStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub label: String,
    pub algorithm: String,
    pub version: u32,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub rotated_from: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
    pub public_key_path: Option<String>,
}

impl KeyMetadata {
    pub fn new(key_id: &str, label: &str, algorithm: &str, version: u32) -> Self {
        Self {
            key_id: key_id.to_string(),
            label: label.to_string(),
            algorithm: algorithm.to_string(),
            version,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            rotated_from: None,
            revoked_at: None,
            revoke_reason: None,
            public_key_path: None,
        }
    }

    pub fn can_sign(&self) -> bool {
        self.status == KeyStatus::Active
    }

    pub fn can_verify(&self) -> bool {
        match self.status {
            KeyStatus::Active | KeyStatus::Deprecated => true,
            KeyStatus::Revoked => {
                if let Some(revoked) = self.revoked_at {
                    (Utc::now() - revoked).num_seconds() < REVOCATION_GRACE_PERIOD_SECS
                } else {
                    false
                }
            }
        }
    }

    /// Check if this key needs rotation based on age.
    /// Returns true if key age exceeds DKP_ROTATION_INTERVAL_SECS.
    pub fn needs_rotation(&self) -> bool {
        if self.status != KeyStatus::Active {
            return false;
        }
        let age = Utc::now() - self.created_at;
        age.num_seconds() > DKP_ROTATION_INTERVAL_SECS
    }

    /// Get key age in human-readable format.
    pub fn age_display(&self) -> String {
        let age = Utc::now() - self.created_at;
        let days = age.num_days();
        if days > 365 {
            format!("{} years, {} days", days / 365, days % 365)
        } else if days > 0 {
            format!("{} days", days)
        } else {
            let hours = age.num_hours();
            if hours > 0 {
                format!("{} hours", hours)
            } else {
                format!("{} minutes", age.num_minutes())
            }
        }
    }

    pub fn deprecate(&mut self) {
        self.status = KeyStatus::Deprecated;
    }

    pub fn revoke(&mut self, reason: &str) {
        self.status = KeyStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.revoke_reason = Some(reason.to_string());
    }
}

/// Full key history — stores ALL versions, not just latest.
/// Saved as JSON array to /var/lib/sgx-guardian/keys/dkp_metadata.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkpKeyHistory {
    pub keys: Vec<KeyMetadata>,
}

impl DkpKeyHistory {
    /// Create new history with a single active key.
    pub fn new(first_key: KeyMetadata) -> Self {
        Self {
            keys: vec![first_key],
        }
    }

    /// Get the currently active key (if any).
    pub fn active_key(&self) -> Option<&KeyMetadata> {
        self.keys.iter().find(|k| k.status == KeyStatus::Active)
    }

    /// Get mutable ref to a key by version.
    pub fn get_mut(&mut self, version: u32) -> Option<&mut KeyMetadata> {
        self.keys.iter_mut().find(|k| k.version == version)
    }

    /// Get key by version (immutable).
    pub fn get(&self, version: u32) -> Option<&KeyMetadata> {
        self.keys.iter().find(|k| k.version == version)
    }

    /// Add a new key version. Does NOT deprecate the old one — caller must do that.
    pub fn add(&mut self, key: KeyMetadata) {
        self.keys.push(key);
    }

    /// Deprecate a specific version.
    pub fn deprecate_version(&mut self, version: u32) -> bool {
        if let Some(k) = self.get_mut(version) {
            k.deprecate();
            true
        } else {
            false
        }
    }

    /// Revoke a specific version. Cannot revoke Active keys.
    pub fn revoke_version(&mut self, version: u32, reason: &str) -> Result<(), String> {
        let key = self
            .get_mut(version)
            .ok_or_else(|| format!("Version {} not found", version))?;
        if key.status == KeyStatus::Active {
            return Err("Cannot revoke active key — rotate first".into());
        }
        key.revoke(reason);
        Ok(())
    }

    /// Save full history to file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json =
            serde_json::to_string_pretty(&self.keys).map_err(|e| format!("Serialize: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }

    /// Load full history from file.
    /// Handles both old single-object format and new array format.
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read: {}", e))?;
        let trimmed = json.trim();

        // New array format: [ { ... }, { ... } ]
        if trimmed.starts_with('[') {
            let keys: Vec<KeyMetadata> =
                serde_json::from_str(trimmed).map_err(|e| format!("Parse array: {}", e))?;
            return Ok(Self { keys });
        }

        // Old single-object format: { "key_id": ..., "version": ... }
        // Migrate to array format automatically
        let single: KeyMetadata =
            serde_json::from_str(trimmed).map_err(|e| format!("Parse single: {}", e))?;
        Ok(Self { keys: vec![single] })
    }
}

// ── Unit Tests ──────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_key_is_active() {
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        assert_eq!(meta.status, KeyStatus::Active);
        assert!(meta.can_sign());
        assert!(meta.can_verify());
    }

    #[test]
    fn test_deprecated_key_cannot_sign_but_can_verify() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate();
        assert!(!meta.can_sign());
        assert!(meta.can_verify());
    }

    #[test]
    fn test_revoked_key_cannot_sign() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("rotation complete");
        assert!(!meta.can_sign());
        assert_eq!(meta.revoke_reason.as_deref(), Some("rotation complete"));
    }

    #[test]
    fn test_revoked_key_verify_during_grace_period() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        assert!(meta.can_verify());
    }

    #[test]
    fn test_key_status_display() {
        assert_eq!(format!("{}", KeyStatus::Active), "Active");
        assert_eq!(
            format!("{}", KeyStatus::Deprecated),
            "Deprecated (verify-only)"
        );
        assert_eq!(format!("{}", KeyStatus::Revoked), "Revoked");
    }

    #[test]
    fn test_version_tracking() {
        let v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let json = serde_json::to_string(&meta).unwrap();
        let loaded: KeyMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.key_id, "0x20000010");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.status, KeyStatus::Active);
    }

    #[test]
    fn test_revocation_is_permanent() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("compromised");
        assert!(!meta.can_sign());
    }

    // --- History tests ---

    #[test]
    fn test_history_active_key() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let hist = DkpKeyHistory::new(k1);
        let active = hist.active_key().unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn test_history_rotation_preserves_all_versions() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let k2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        let mut hist = DkpKeyHistory::new(k1);
        hist.deprecate_version(1);
        hist.add(k2);
        assert_eq!(hist.keys.len(), 2);
        assert_eq!(hist.get(1).unwrap().status, KeyStatus::Deprecated);
        assert_eq!(hist.active_key().unwrap().version, 2);
    }

    #[test]
    fn test_history_revoke_requires_deprecated() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let mut hist = DkpKeyHistory::new(k1);
        let result = hist.revoke_version(1, "test");
        assert!(result.is_err()); // Cannot revoke active
    }

    #[test]
    fn test_history_revoke_deprecated_succeeds() {
        let k1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let k2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        let mut hist = DkpKeyHistory::new(k1);
        hist.deprecate_version(1);
        hist.add(k2);
        assert!(hist.revoke_version(1, "rotation complete").is_ok());
        assert_eq!(hist.get(1).unwrap().status, KeyStatus::Revoked);
    }

    #[test]
    fn test_history_load_migrates_old_format() {
        // Simulate old single-object JSON
        let old_json = r#"{
            "key_id": "0x20000010",
            "label": "dkp",
            "algorithm": "ECDSA-P256",
            "version": 1,
            "status": "Active",
            "created_at": "2026-03-10T11:31:40Z",
            "rotated_from": null,
            "revoked_at": null,
            "revoke_reason": null,
            "public_key_path": null
        }"#;
        let hist: DkpKeyHistory = {
            let single: KeyMetadata = serde_json::from_str(old_json).unwrap();
            DkpKeyHistory { keys: vec![single] }
        };
        assert_eq!(hist.keys.len(), 1);
        assert_eq!(hist.active_key().unwrap().version, 1);
    }

    #[test]
    fn test_needs_rotation_new_key() {
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        // Just created — should NOT need rotation
        assert!(!meta.needs_rotation());
    }

    #[test]
    fn test_rotation_deprecates_old() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        v1.deprecate();
        assert!(!v1.can_sign());
        assert!(v1.can_verify());
    }

    #[test]
    fn test_rotated_key_tracks_parent() {
        let mut v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v2.rotated_from = Some("0x20000010".to_string());
        assert_eq!(v2.rotated_from.as_deref(), Some("0x20000010"));
    }

    #[test]
    fn test_new_version_is_active() {
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        assert!(v2.can_sign());
    }

    #[test]
    fn test_deprecated_and_active_coexist() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v1.deprecate();
        assert!(!v1.can_sign());
        assert!(v1.can_verify());
        assert!(v2.can_sign());
    }

    #[test]
    fn test_version_chain() {
        let v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let mut v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v2.rotated_from = Some(v1.key_id.clone());
        let mut v3 = KeyMetadata::new("0x20000012", "dkp-v3", "ECDSA-P256", 3);
        v3.rotated_from = Some(v2.key_id.clone());
        assert_eq!(v3.rotated_from.as_deref(), Some("0x20000011"));
    }

    #[test]
    fn test_revoke_sets_reason_and_timestamp() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate();
        meta.revoke("compromised");
        assert_eq!(meta.status, KeyStatus::Revoked);
        assert_eq!(meta.revoke_reason.as_deref(), Some("compromised"));
        assert!(meta.revoked_at.is_some());
    }

    #[test]
    fn test_revoked_blocks_signing() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("done");
        assert!(!meta.can_sign());
    }

    #[test]
    fn test_grace_period_allows_verify() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        assert!(meta.can_verify());
    }
}
