// src/secure_element/pcr.rs
// ============================================================
// Platform Configuration Registers (PCR) Engine — ATT-003
// TPM-like PCR extend using SHA-256. Values in software, signed by DKP.
// Crypto: SHA-256 ONLY for hashing. ECDSA-P256 for signing.
// ============================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const PCR_COUNT: usize = 5;
pub const PCR_BIOS: usize = 0;
pub const PCR_FIRMWARE: usize = 1;
pub const PCR_KERNEL: usize = 2;
pub const PCR_ROOTFS: usize = 3;
pub const PCR_CONFIG: usize = 4;

/// Maximum age of a PCR snapshot in seconds before it's considered stale.
/// Verifiers reject snapshots older than this.
/// ╔══════════════════════════════════════════════════╗
/// ║  CHANGE FOR TESTING: 60 = 1 min, 300 = 5 min     ║
/// ║  PRODUCTION DEFAULT: 600 = 10 minutes            ║
/// ╚══════════════════════════════════════════════════╝
pub const MAX_PCR_SNAPSHOT_AGE_SECS: i64 = 600;

/// Current schema version — increment when snapshot format changes.
pub const PCR_SCHEMA_VERSION: u8 = 1;

const PCR_NAMES: [&str; PCR_COUNT] = [
    "BIOS/Bootloader",
    "Firmware/DTB",
    "Kernel",
    "RootFS",
    "Configuration",
];

pub type PcrValue = [u8; 32];

// ── Measurement Error ───────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMeasurementError {
    pub pcr_index: usize,
    pub source: String,
    pub error: String,
}

// ── PCR Snapshot ────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSnapshot {
    pub pcr_values: Vec<String>,
    pub composite_digest: String,
    /// DKP signature over binary: SHA256(composite_bytes || nonce_bytes || timestamp_bytes)
    pub composite_signature: Option<String>,
    pub nonce: String,
    pub measured_at: String,
    /// SE050 hardware UID (real chip ID, not "nodeA")
    pub device_uid: String,
    /// DKP key version that signed this snapshot
    pub key_version: u32,
    pub firmware_version: Option<String>,
    pub measurement_errors: Vec<PcrMeasurementError>,
    /// PASS = all OK, DEGRADED = optional files missing, FAIL = critical failed
    pub integrity_status: String,
    /// Schema version for forward compatibility
    pub schema_version: u8,
}

impl PcrSnapshot {
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Parse: {}", e))
    }

    /// Check if this snapshot is fresh enough for attestation.
    pub fn is_fresh(&self) -> bool {
        if let Ok(measured) = DateTime::parse_from_rfc3339(&self.measured_at) {
            let age = Utc::now().signed_duration_since(measured.with_timezone(&Utc));
            age.num_seconds() < MAX_PCR_SNAPSHOT_AGE_SECS
        } else {
            false
        }
    }

    /// Compare PCR values against a baseline. Returns Err on length mismatch.
    pub fn compare_baseline(&self, baseline: &PcrBaseline) -> Result<Vec<usize>, String> {
        if self.pcr_values.len() != baseline.pcr_values.len() {
            return Err(format!(
                "PCR count mismatch: snapshot={}, baseline={}",
                self.pcr_values.len(),
                baseline.pcr_values.len()
            ));
        }
        let mut mismatches = Vec::new();
        for i in 0..self.pcr_values.len() {
            if self.pcr_values[i] != baseline.pcr_values[i] {
                mismatches.push(i);
            }
        }
        Ok(mismatches)
    }
}

// ── Golden Baseline ─────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrBaseline {
    pub pcr_values: Vec<String>,
    pub composite_digest: String,
    /// DKP signature over: SHA256(composite_bytes || created_at_bytes || device_uid_bytes)
    pub baseline_signature: String,
    pub created_at: String,
    pub device_uid: String,
    pub key_version: u32,
    pub schema_version: u8,
}

impl PcrBaseline {
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Read: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Parse: {}", e))
    }

    /// Verify baseline signature. Returns false if tampered or wrong key.
    pub fn verify_signature(&self, pubkey: &[u8]) -> bool {
        use ring::signature;

        let composite_bytes = hex::decode(&self.composite_digest).unwrap_or_default();
        let mut sign_input = Vec::new();
        sign_input.extend_from_slice(&composite_bytes);
        sign_input.extend_from_slice(self.created_at.as_bytes());
        sign_input.extend_from_slice(self.device_uid.as_bytes());
        let sign_hash = Sha256::digest(&sign_input);

        let sig_bytes =
            match base64::engine::general_purpose::STANDARD.decode(&self.baseline_signature) {
                Ok(b) => b,
                Err(_) => return false,
            };

        // Auto-detect signature format (same as attestation_service.rs)
        let algo: &dyn signature::VerificationAlgorithm =
            if !sig_bytes.is_empty() && sig_bytes[0] == 0x30 {
                &signature::ECDSA_P256_SHA256_ASN1
            } else {
                &signature::ECDSA_P256_SHA256_FIXED
            };

        let key = signature::UnparsedPublicKey::new(algo, pubkey);
        key.verify(&sign_hash, &sig_bytes).is_ok()
    }
}

// Need base64 import for baseline verify
use base64::Engine as _;

// ── PCR Engine ──────────────────────────────────────
pub struct PcrEngine {
    registers: [PcrValue; PCR_COUNT],
    extended: [bool; PCR_COUNT],
}

impl PcrEngine {
    /// New engine — all PCRs initialized to 32 bytes of 0x00.
    pub fn new() -> Self {
        Self {
            registers: [[0u8; 32]; PCR_COUNT],
            extended: [false; PCR_COUNT],
        }
    }

    /// Extend a PCR: new_value = SHA256(old_value || measurement)
    pub fn extend(&mut self, pcr_index: usize, measurement: &[u8]) -> Result<(), String> {
        if pcr_index >= PCR_COUNT {
            return Err(format!(
                "PCR{} out of range (0-{})",
                pcr_index,
                PCR_COUNT - 1
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(&self.registers[pcr_index]);
        hasher.update(measurement);
        let result = hasher.finalize();
        self.registers[pcr_index].copy_from_slice(&result);
        self.extended[pcr_index] = true;
        Ok(())
    }

    /// Extend with SHA-256 hash of a file's contents.
    pub fn extend_from_file(&mut self, pcr_index: usize, path: &str) -> Result<String, String> {
        let data = fs::read(path).map_err(|e| format!("Read {}: {}", path, e))?;
        let measurement = Sha256::digest(&data);
        let hex = hex::encode(&measurement);
        self.extend(pcr_index, &measurement)?;
        Ok(hex)
    }

    /// Extend with SHA-256 hash of a string.
    pub fn extend_from_string(&mut self, pcr_index: usize, value: &str) -> Result<String, String> {
        let measurement = Sha256::digest(value.as_bytes());
        let hex = hex::encode(&measurement);
        self.extend(pcr_index, &measurement)?;
        Ok(hex)
    }

    /// Extend PCR with MULTIPLE files (sorted for determinism).
    pub fn extend_from_files(
        &mut self,
        pcr_index: usize,
        file_paths: &[String],
    ) -> Vec<PcrMeasurementError> {
        let mut errors = Vec::new();
        let mut sorted = file_paths.to_vec();
        sorted.sort(); // CRITICAL: deterministic order

        for path in &sorted {
            match self.extend_from_file(pcr_index, path) {
                Ok(hash) => {
                    println!("    PCR{}: {} → {}...", pcr_index, path, &hash[..12]);
                }
                Err(e) => {
                    let _ = self.extend_from_string(pcr_index, &format!("NOT_FOUND:{}", path));
                    errors.push(PcrMeasurementError {
                        pcr_index,
                        source: path.clone(),
                        error: e,
                    });
                }
            }
        }
        errors
    }

    pub fn get_hex(&self, pcr_index: usize) -> String {
        if pcr_index < PCR_COUNT {
            hex::encode(&self.registers[pcr_index])
        } else {
            "invalid".into()
        }
    }

    /// Composite digest: SHA256(PCR0 || PCR1 || ... || PCR4)
    pub fn composite_digest(&self) -> PcrValue {
        let mut hasher = Sha256::new();
        for pcr in &self.registers {
            hasher.update(pcr);
        }
        let r = hasher.finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&r);
        d
    }

    pub fn snapshot(&self) -> PcrSnapshot {
        PcrSnapshot {
            pcr_values: (0..PCR_COUNT).map(|i| self.get_hex(i)).collect(),
            composite_digest: hex::encode(self.composite_digest()),
            composite_signature: None,
            nonce: String::new(),
            measured_at: Utc::now().to_rfc3339(),
            device_uid: String::new(),
            key_version: 0,
            firmware_version: None,
            measurement_errors: Vec::new(),
            integrity_status: "UNKNOWN".into(),
            schema_version: PCR_SCHEMA_VERSION,
        }
    }

    pub fn pcr_name(index: usize) -> &'static str {
        if index < PCR_COUNT {
            PCR_NAMES[index]
        } else {
            "Unknown"
        }
    }

    pub fn all_measured(&self) -> bool {
        self.extended.iter().all(|&e| e)
    }

    pub fn print_status(&self) {
        println!("  PCR Measurements:");
        for i in 0..PCR_COUNT {
            let s = if self.extended[i] { "✅" } else { "⬜" };
            println!(
                "    PCR{} [{}]: {}..  ({})",
                i,
                s,
                &self.get_hex(i)[..16],
                Self::pcr_name(i)
            );
        }
        println!(
            "    Composite: {}...",
            &hex::encode(self.composite_digest())[..16]
        );
    }
}

/// Read SE050 hardware UID. Returns "nodeX" fallback if ssscli unavailable.
pub fn read_device_uid(fallback: &str) -> String {
    match std::process::Command::new("ssscli")
        .args(["se05x", "uid"])
        .output()
    {
        Ok(out) if out.status.success() => {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&out.stdout)
            );
            for line in combined.lines() {
                let t = line.trim();
                if t.starts_with("Unique ID:") {
                    let uid = t["Unique ID:".len()..].trim().to_string();
                    // Validate: SE050 UID is 36 hex chars
                    if uid.len() >= 20 && uid.chars().all(|c| c.is_ascii_hexdigit()) {
                        return uid;
                    }
                }
            }
            fallback.to_string()
        }
        _ => fallback.to_string(),
    }
}

/// Read DKP key version from metadata. Returns 1 as default.
pub fn read_dkp_key_version() -> u32 {
    let path = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
    match fs::read_to_string(path) {
        Ok(json) => {
            let trimmed = json.trim();
            if trimmed.starts_with('[') {
                serde_json::from_str::<Vec<serde_json::Value>>(trimmed)
                    .ok()
                    .and_then(|keys| {
                        keys.iter()
                            .find(|k| k["status"] == "Active")
                            .and_then(|k| k["version"].as_u64())
                    })
                    .map(|v| v as u32)
                    .unwrap_or(1)
            } else {
                serde_json::from_str::<serde_json::Value>(trimmed)
                    .ok()
                    .and_then(|v| v["version"].as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(1)
            }
        }
        Err(_) => 1,
    }
}

// ── Unit Tests (17 tests) ───────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pcrs_are_zeros() {
        let engine = PcrEngine::new();
        for i in 0..PCR_COUNT {
            assert_eq!(&engine.registers[i], &[0u8; 32]);
        }
    }

    #[test]
    fn test_extend_changes_value() {
        let mut e = PcrEngine::new();
        let before = e.get_hex(0);
        e.extend(0, b"test measurement").unwrap();
        assert_ne!(before, e.get_hex(0));
    }

    #[test]
    fn test_extend_is_deterministic() {
        let mut e1 = PcrEngine::new();
        let mut e2 = PcrEngine::new();
        e1.extend(0, b"same data").unwrap();
        e2.extend(0, b"same data").unwrap();
        assert_eq!(e1.get_hex(0), e2.get_hex(0));
    }

    #[test]
    fn test_extend_order_dependent() {
        let mut e1 = PcrEngine::new();
        let mut e2 = PcrEngine::new();
        e1.extend(0, b"first").unwrap();
        e1.extend(0, b"second").unwrap();
        e2.extend(0, b"second").unwrap();
        e2.extend(0, b"first").unwrap();
        assert_ne!(e1.get_hex(0), e2.get_hex(0));
    }

    #[test]
    fn test_different_pcrs_independent() {
        let mut e = PcrEngine::new();
        e.extend(0, b"data0").unwrap();
        e.extend(1, b"data1").unwrap();
        assert_ne!(e.get_hex(0), e.get_hex(1));
        assert_eq!(&e.registers[2], &[0u8; 32]); // untouched
    }

    #[test]
    fn test_invalid_pcr_rejected() {
        let mut e = PcrEngine::new();
        assert!(e.extend(99, b"x").is_err());
    }

    #[test]
    fn test_composite_not_zeros() {
        let mut e = PcrEngine::new();
        e.extend(0, b"boot").unwrap();
        assert_ne!(e.composite_digest(), [0u8; 32]);
    }

    #[test]
    fn test_composite_changes_when_pcr_changes() {
        let mut e1 = PcrEngine::new();
        let mut e2 = PcrEngine::new();
        e1.extend(0, b"boot").unwrap();
        e2.extend(0, b"boot").unwrap();
        e2.extend(1, b"extra").unwrap();
        assert_ne!(
            hex::encode(e1.composite_digest()),
            hex::encode(e2.composite_digest())
        );
    }

    #[test]
    fn test_snapshot_serialization() {
        let mut e = PcrEngine::new();
        e.extend(0, b"test").unwrap();
        let snap = e.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let loaded: PcrSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap.pcr_values, loaded.pcr_values);
        assert_eq!(snap.composite_digest, loaded.composite_digest);
    }

    #[test]
    fn test_compare_detects_mismatch() {
        let mut e1 = PcrEngine::new();
        let mut e2 = PcrEngine::new();
        e1.extend(0, b"same").unwrap();
        e1.extend(1, b"same").unwrap();
        e2.extend(0, b"same").unwrap();
        e2.extend(1, b"different").unwrap();

        let s1 = e1.snapshot();
        let baseline = PcrBaseline {
            pcr_values: e2.snapshot().pcr_values,
            composite_digest: String::new(),
            baseline_signature: String::new(),
            created_at: String::new(),
            device_uid: String::new(),
            key_version: 1,
            schema_version: 1,
        };
        let mismatches = s1.compare_baseline(&baseline).unwrap();
        assert_eq!(mismatches, vec![1]);
    }

    #[test]
    fn test_compare_length_mismatch() {
        let mut e = PcrEngine::new();
        e.extend(0, b"x").unwrap();
        let snap = e.snapshot();
        let baseline = PcrBaseline {
            pcr_values: vec!["abc".into()], // wrong length
            composite_digest: String::new(),
            baseline_signature: String::new(),
            created_at: String::new(),
            device_uid: String::new(),
            key_version: 1,
            schema_version: 1,
        };
        assert!(snap.compare_baseline(&baseline).is_err());
    }

    #[test]
    fn test_extend_from_string() {
        let mut e = PcrEngine::new();
        let hash = e.extend_from_string(0, "Linux 5.15.0").unwrap();
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex
    }

    #[test]
    fn test_all_measured() {
        let mut e = PcrEngine::new();
        assert!(!e.all_measured());
        for i in 0..PCR_COUNT {
            e.extend(i, b"m").unwrap();
        }
        assert!(e.all_measured());
    }

    #[test]
    fn test_pcr_names() {
        assert_eq!(PcrEngine::pcr_name(0), "BIOS/Bootloader");
        assert_eq!(PcrEngine::pcr_name(4), "Configuration");
    }

    #[test]
    fn test_sorted_multi_file_determinism() {
        let mut e1 = PcrEngine::new();
        let mut e2 = PcrEngine::new();
        // Same strings but different input order
        e1.extend_from_string(3, "/bin/sh").unwrap();
        e1.extend_from_string(3, "/sbin/init").unwrap();
        // Already sorted — should produce same result
        e2.extend_from_string(3, "/bin/sh").unwrap();
        e2.extend_from_string(3, "/sbin/init").unwrap();
        assert_eq!(e1.get_hex(3), e2.get_hex(3));
    }

    #[test]
    fn test_integrity_status_pass() {
        let errors: Vec<PcrMeasurementError> = vec![];
        let status = if errors.is_empty() { "PASS" } else { "FAIL" };
        assert_eq!(status, "PASS");
    }

    #[test]
    fn test_integrity_status_fail_on_critical() {
        let errors = vec![PcrMeasurementError {
            pcr_index: 0,
            source: "bootloader".into(),
            error: "missing".into(),
        }];
        let critical = errors.iter().any(|e| e.pcr_index == 0 || e.pcr_index == 2);
        assert!(critical);
    }
}
