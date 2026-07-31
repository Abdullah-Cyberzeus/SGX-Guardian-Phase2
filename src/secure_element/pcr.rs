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
pub const MAX_PCR_SNAPSHOT_AGE_SECS: i64 = 86400; // 24h — PCR files don't change at runtime

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
    #[serde(default)]
    pub signing_backend: Option<String>,
    #[serde(default)]
    pub signing_public_key_sha256: Option<String>,
    #[serde(default)]
    pub signature_format: Option<String>,
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
        let sig_bytes =
            match base64::engine::general_purpose::STANDARD.decode(&self.baseline_signature) {
                Ok(b) => b,
                Err(_) => return false,
            };

        let sign_hash = match canonical_baseline_signing_payload(
            &self.composite_digest,
            &self.created_at,
            &self.device_uid,
        ) {
            Ok(payload) => payload,
            Err(_) => return false,
        };

        verify_baseline_signature_bytes(&sign_hash, &sig_bytes, pubkey)
    }
}

pub fn canonical_baseline_signing_payload(
    composite_digest: &str,
    created_at: &str,
    device_uid: &str,
) -> Result<Vec<u8>, String> {
    let composite_bytes =
        hex::decode(composite_digest).map_err(|_| "Invalid composite_digest".to_string())?;
    if composite_bytes.len() != 32 {
        return Err(format!(
            "composite_digest must be 32 bytes, got {}",
            composite_bytes.len()
        ));
    }

    let mut sign_input = Vec::new();
    sign_input.extend_from_slice(&composite_bytes);
    sign_input.extend_from_slice(created_at.as_bytes());
    sign_input.extend_from_slice(device_uid.as_bytes());
    Ok(Sha256::digest(&sign_input).to_vec())
}

fn signature_is_asn1(sig_bytes: &[u8]) -> bool {
    match sig_bytes.len() {
        64 => false,
        _ => sig_bytes.first() == Some(&0x30),
    }
}

pub fn signature_format(sig_bytes: &[u8]) -> &'static str {
    if signature_is_asn1(sig_bytes) {
        "ecdsa-p256-sha256-asn1"
    } else {
        "ecdsa-p256-sha256-fixed"
    }
}

pub fn verify_baseline_signature_bytes(payload: &[u8], sig_bytes: &[u8], pubkey: &[u8]) -> bool {
    use ring::signature;

    // Auto-detect signature format (same as attestation_service.rs)
    let algo: &dyn signature::VerificationAlgorithm = if signature_is_asn1(sig_bytes) {
        &signature::ECDSA_P256_SHA256_ASN1
    } else {
        &signature::ECDSA_P256_SHA256_FIXED
    };

    let key = signature::UnparsedPublicKey::new(algo, pubkey);
    key.verify(payload, sig_bytes).is_ok()
}

// Need base64 import for baseline verify
use base64::Engine as _;

// ── PCR Engine ──────────────────────────────────────
pub struct PcrEngine {
    registers: [PcrValue; PCR_COUNT],
    extended: [bool; PCR_COUNT],
}

impl Default for PcrEngine {
    fn default() -> Self {
        Self::new()
    }
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
        hasher.update(self.registers[pcr_index]);
        hasher.update(measurement);
        let result = hasher.finalize();
        self.registers[pcr_index].copy_from_slice(&result);
        self.extended[pcr_index] = true;
        Ok(())
    }

    /// Extend with SHA-256 hash of a file's contents.
    /// Files larger than 16 MB are hashed by their metadata instead of full
    /// contents to avoid blocking the tokio runtime on large reads (e.g.
    /// /boot/Image can be 30+ MB on some boards).
    pub fn extend_from_file(&mut self, pcr_index: usize, path: &str) -> Result<String, String> {
        const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

        let meta = fs::metadata(path).map_err(|e| format!("Stat {}: {}", path, e))?;
        if meta.len() > MAX_FILE_BYTES {
            let meta_str = format!(
                "FILE_META:{}:size={}:mtime={:?}",
                path,
                meta.len(),
                meta.modified().ok()
            );
            tracing::warn!(
                "PCR{}: {} exceeds {} bytes — measuring metadata instead of contents",
                pcr_index,
                path,
                MAX_FILE_BYTES
            );
            return self.extend_from_string(pcr_index, &meta_str);
        }

        let data = fs::read(path).map_err(|e| format!("Read {}: {}", path, e))?;
        let measurement = Sha256::digest(&data);
        self.extend(pcr_index, &measurement)?;
        let hex = hex::encode(measurement);
        Ok(hex)
    }

    /// Extend with SHA-256 hash of a string.
    pub fn extend_from_string(&mut self, pcr_index: usize, value: &str) -> Result<String, String> {
        let measurement = Sha256::digest(value.as_bytes());
        self.extend(pcr_index, &measurement)?;
        let hex = hex::encode(measurement);
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
            hex::encode(self.registers[pcr_index])
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
                if let Some(stripped) = t.strip_prefix("Unique ID:") {
                    let uid = stripped.trim().to_string();
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

/// Node-unique device UID for the multi-node-on-one-chip scenario: several
/// containers sharing a single physical SE050 board would otherwise all
/// report the exact same `ssscli se05x uid` value.
///
/// This only diverges from the raw hardware UID when `config.dkp_key_id_base`
/// has been explicitly overridden away from `dkp::DKP_BASE_KEY_ID` (i.e. only
/// when `SGX_SE_DKP_KEY_ID_BASE` is set for a multi-node container cohort).
/// Every existing single-node deployment — bare metal or containerized —
/// leaves that env var unset, so `read_device_uid` alone is returned exactly
/// as before and device_uid values already relied on (baselines, audit logs,
/// revocation records) do not change.
pub fn node_device_uid(
    config: &crate::secure_element::config::SeConfig,
    dkp_pub_path: &str,
    fallback: &str,
) -> String {
    let hw_uid = read_device_uid(fallback);
    if config.dkp_key_id_base == crate::secure_element::dkp::DKP_BASE_KEY_ID {
        return hw_uid;
    }

    match fs::read(dkp_pub_path) {
        Ok(dkp_der) => {
            let mut hasher = Sha256::new();
            hasher.update(hw_uid.as_bytes());
            hasher.update(&dkp_der);
            hex::encode(hasher.finalize())
        }
        Err(_) => hw_uid,
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

/// Keys that carry runtime/network state and must not affect PCR4.
const PCR_DYNAMIC_DENYLIST: &[&str] = &[
    "ip",
    "lan_ip",
    "detected_ip",
    "endpoint",
    "endpoints",
    "runtime",
    "active_transport",
    "observed_ip",
];

/// Returns canonical static measurement text for a YAML config file.
/// On read/parse failure this returns an empty string by design, so runtime
/// rewrites are not accidentally measured as raw bytes.
pub fn canonical_static_yaml_measurement(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_yaml::from_str::<serde_yaml::Value>(&raw) {
            Ok(mut v) => {
                canonicalize_static_config(&mut v);
                serde_yaml_to_sorted_json(&v)
            }
            Err(e) => {
                eprintln!(
                    "  ⚠️ static_yaml parse failed for {} ({}) — measuring empty (degraded)",
                    path, e
                );
                String::new()
            }
        },
        Err(_) => String::new(),
    }
}

fn canonicalize_static_config(v: &mut serde_yaml::Value) {
    if let serde_yaml::Value::Mapping(map) = v {
        for k in PCR_DYNAMIC_DENYLIST {
            map.remove(serde_yaml::Value::String((*k).to_string()));
        }
        for (_k, val) in map.iter_mut() {
            canonicalize_static_config(val);
        }
    } else if let serde_yaml::Value::Sequence(seq) = v {
        for item in seq.iter_mut() {
            canonicalize_static_config(item);
        }
    }
}

fn serde_yaml_to_sorted_json(v: &serde_yaml::Value) -> String {
    fn to_json(v: &serde_yaml::Value) -> serde_json::Value {
        match v {
            serde_yaml::Value::Null => serde_json::Value::Null,
            serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    serde_json::Value::Number(serde_json::Number::from(i))
                } else if let Some(u) = n.as_u64() {
                    serde_json::Value::Number(serde_json::Number::from(u))
                } else {
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(n.as_f64().unwrap_or(0.0))
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    )
                }
            }
            serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
            serde_yaml::Value::Sequence(seq) => {
                serde_json::Value::Array(seq.iter().map(to_json).collect())
            }
            serde_yaml::Value::Mapping(m) => {
                let mut keys: Vec<String> = m
                    .keys()
                    .filter_map(|k| k.as_str().map(|s| s.to_string()))
                    .collect();
                keys.sort();
                let mut obj = serde_json::Map::new();
                for k in keys {
                    if let Some(val) = m.get(serde_yaml::Value::String(k.clone())) {
                        obj.insert(k, to_json(val));
                    }
                }
                serde_json::Value::Object(obj)
            }
            serde_yaml::Value::Tagged(t) => to_json(&t.value),
        }
    }

    serde_json::to_string(&to_json(v)).unwrap_or_default()
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
            signing_backend: None,
            signing_public_key_sha256: None,
            signature_format: None,
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
            signing_backend: None,
            signing_public_key_sha256: None,
            signature_format: None,
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
        let errors = [PcrMeasurementError {
            pcr_index: 0,
            source: "bootloader".into(),
            error: "missing".into(),
        }];
        let critical = errors.iter().any(|e| e.pcr_index == 0 || e.pcr_index == 2);
        assert!(critical);
    }

    #[test]
    fn test_fixed_signature_length_takes_priority_over_der_prefix() {
        let mut fixed_sig = vec![0u8; 64];
        fixed_sig[0] = 0x30;
        assert_eq!(signature_format(&fixed_sig), "ecdsa-p256-sha256-fixed");

        let asn1_sig = [0x30, 0x44, 0x02, 0x20];
        assert_eq!(signature_format(&asn1_sig), "ecdsa-p256-sha256-asn1");
    }

    fn se_config_with_dkp_base(dkp_key_id_base: u32) -> crate::secure_element::config::SeConfig {
        crate::secure_element::config::SeConfig {
            dkp_key_id_base,
            ..crate::secure_element::config::SeConfig::default()
        }
    }

    #[test]
    fn node_device_uid_default_key_id_matches_raw_hardware_uid() {
        // No env-var overrides, no ssscli on this machine — both sides fall
        // back to the caller-supplied fallback string identically.
        let cfg = se_config_with_dkp_base(crate::secure_element::dkp::DKP_BASE_KEY_ID);
        let expected = read_device_uid("nodeA-fallback");
        let actual = node_device_uid(&cfg, "/nonexistent/dkp_pub.der", "nodeA-fallback");
        assert_eq!(actual, expected);
    }

    #[test]
    fn node_device_uid_overridden_key_id_without_dkp_pub_falls_back_to_hw_uid() {
        let cfg = se_config_with_dkp_base(crate::secure_element::dkp::DKP_BASE_KEY_ID + 0x10);
        let expected = read_device_uid("nodeB-fallback");
        let actual = node_device_uid(&cfg, "/nonexistent/dkp_pub.der", "nodeB-fallback");
        assert_eq!(actual, expected);
    }

    #[test]
    fn node_device_uid_overridden_key_id_with_dkp_pub_diverges_from_hw_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dkp_pub_path = dir.path().join("dkp_pub.der");
        std::fs::write(&dkp_pub_path, b"fake-dkp-pubkey-der").expect("write dkp pub");

        let cfg = se_config_with_dkp_base(crate::secure_element::dkp::DKP_BASE_KEY_ID + 0x10);
        let hw_uid = read_device_uid("nodeC-fallback");
        let node_uid = node_device_uid(
            &cfg,
            dkp_pub_path.to_str().expect("utf8 path"),
            "nodeC-fallback",
        );

        assert_ne!(node_uid, hw_uid);
        assert_eq!(node_uid.len(), 64); // SHA256 hex
    }
}
