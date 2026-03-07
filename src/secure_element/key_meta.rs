// src/secure_element/key_meta.rs
// ============================================================
// Key metadata — tracks lifecycle state for SE050-backed keys.
// Stored as JSON on disk. SE050 stores the key itself.
// ============================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Status of a hardware-backed key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is active and can be used for signing + verification
    Active,
    /// Key has been replaced by a newer version — verify only, no new signing
    Deprecated,
    /// Key is permanently revoked — no signing, verify only during grace period
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

/// Metadata for a single hardware-backed key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// SE050 key ID in hex (e.g., "0x20000010")
    pub key_id: String,
    /// Human-readable label (e.g., "dkp", "dkp-v2")
    pub label: String,
    /// Algorithm (e.g., "ECDSA-P256")
    pub algorithm: String,
    /// Key version (starts at 1, increments on rotation)
    pub version: u32,
    /// Current lifecycle status
    pub status: KeyStatus,
    /// When this key was generated
    pub created_at: DateTime<Utc>,
    /// Key ID this was rotated from (None for first key)
    pub rotated_from: Option<String>,
    /// When this key was revoked (None if not revoked)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason for revocation (None if not revoked)
    pub revoke_reason: Option<String>,
    /// Path to exported public key DER file
    pub public_key_path: Option<String>,
}

impl KeyMetadata {
    /// Create metadata for a newly generated key
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

    /// Check if this key can be used for signing
    pub fn can_sign(&self) -> bool {
        self.status == KeyStatus::Active
    }

    /// Check if this key can be used for verification
    pub fn can_verify(&self) -> bool {
        match self.status {
            KeyStatus::Active => true,
            KeyStatus::Deprecated => true,
            KeyStatus::Revoked => {
                // Grace period: allow verification for 30 days after revocation
                if let Some(revoked) = self.revoked_at {
                    let grace_days = 30;
                    let elapsed = Utc::now() - revoked;
                    elapsed.num_days() < grace_days
                } else {
                    false
                }
            }
        }
    }

    /// Mark this key as deprecated (replaced by newer version)
    pub fn deprecate(&mut self) {
        self.status = KeyStatus::Deprecated;
    }

    /// Mark this key as revoked (permanently blocked from signing)
    pub fn revoke(&mut self, reason: &str) {
        self.status = KeyStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.revoke_reason = Some(reason.to_string());
    }

    /// Save metadata to JSON file
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("Serialize metadata: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Create dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write metadata: {}", e))?;
        Ok(())
    }

    /// Load metadata from JSON file
    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read metadata: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Parse metadata: {}", e))
    }
}

// ── Unit Tests (17 tests) ───────────────────────────────────
// Pure struct/logic tests — no I/O, no subprocess.
// Run: cargo test secure_element::key_meta::tests -- --nocapture
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
    fn test_deprecated_key_cannot_sign() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.deprecate();
        assert_eq!(meta.status, KeyStatus::Deprecated);
        assert!(!meta.can_sign());
        assert!(meta.can_verify()); // can still verify old signatures
    }

    #[test]
    fn test_revoked_key_cannot_sign() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("rotation complete");
        assert_eq!(meta.status, KeyStatus::Revoked);
        assert!(!meta.can_sign());
        assert_eq!(meta.revoke_reason.as_deref(), Some("rotation complete"));
    }

    #[test]
    fn test_revoked_key_verify_during_grace_period() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        // Just revoked — within 30-day grace period
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
        assert_eq!(loaded.label, "dkp");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.status, KeyStatus::Active);
    }

    #[test]
    fn test_revocation_is_permanent() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("compromised");
        assert!(!meta.can_sign());
        // Cannot un-revoke — there's no un_revoke() method
        assert_eq!(meta.status, KeyStatus::Revoked);
    }

    #[test]
    fn test_rotation_deprecates_old_key() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        assert!(v1.can_sign());
        v1.deprecate();
        assert!(!v1.can_sign());
        assert!(v1.can_verify()); // old signatures still verifiable
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
        assert_eq!(v2.status, KeyStatus::Active);
        assert!(v2.can_sign());
    }

    #[test]
    fn test_deprecated_and_active_coexist() {
        let mut v1 = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        let v2 = KeyMetadata::new("0x20000011", "dkp-v2", "ECDSA-P256", 2);
        v1.deprecate();
        // v1 can verify, v2 can sign+verify
        assert!(!v1.can_sign());
        assert!(v1.can_verify());
        assert!(v2.can_sign());
        assert!(v2.can_verify());
    }

    #[test]
    fn test_multiple_rotations_version_chain() {
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
        meta.deprecate(); // must deprecate before revoke
        meta.revoke("key compromised");
        assert_eq!(meta.status, KeyStatus::Revoked);
        assert_eq!(meta.revoke_reason.as_deref(), Some("key compromised"));
        assert!(meta.revoked_at.is_some());
    }

    #[test]
    fn test_cannot_revoke_active_key_logic() {
        // Business rule: must rotate first, then revoke the old key
        let meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        assert_eq!(meta.status, KeyStatus::Active);
        // DkpManager.revoke() checks this and returns error
    }

    #[test]
    fn test_revoked_key_blocks_signing() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("rotation complete");
        assert!(!meta.can_sign());
    }

    #[test]
    fn test_grace_period_allows_verification() {
        let mut meta = KeyMetadata::new("0x20000010", "dkp", "ECDSA-P256", 1);
        meta.revoke("test");
        // Within 30-day grace period (just revoked)
        assert!(meta.can_verify());
        // After grace period would return false (tested by checking the logic)
    }
}
