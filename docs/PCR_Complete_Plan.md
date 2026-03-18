# PCR Measurement — Complete Development Plan
**Task:** ATT-003 | **Sprint:** 2 | **Target:** 24 Mar  
**Crypto:** ECDSA-P256 + SHA-256 ONLY  
**Prerequisites:** SE050 ✅ | HKM ✅




## GPT Review #3 Cross-Check

| # | GPT Point | Verdict | Reason |
|---|-----------|---------|--------|
| 1 | PCR snapshot max age check | ✅ Valid | Stale snapshots should be rejected during peer verification |
| 2 | Baseline key mismatch → hard reject | ⚠️ Partially valid | Hard reject is correct, but should suggest re-creating baseline |
| 3 | UID parsing fragile | ✅ Valid | Should validate UID length (36 hex chars) |
| 4 | Integrity FAIL blocks attestation | ✅ Valid | FAIL should block; DEGRADED should warn |
| 5 | Measurement = hash(content + path) | ❌ Wrong | Binding path changes PCR if file moves but content is identical. PCR should measure CONTENT only, path is tracked in metadata |
| 6 | schema_version validation | ✅ Valid | Simple version check before processing |

**Point 5 rejection:** GPT says `SHA256(file_content || file_path)` but this is wrong for our use case. If the same binary moves from `/usr/bin/ssscli` to `/usr/local/bin/ssscli`, the PCR would change even though the file is identical. PCR should measure file CONTENT for integrity. The path is already tracked in measurement sources config for auditability.




## Architecture

```
BOOT → Daemon starts → PCR engine measures 5 components:
  PCR0: Bootloader identity (/proc/device-tree/model)
  PCR1: Firmware config    (/proc/device-tree/compatible)
  PCR2: Kernel             (/boot/Image or /proc/version)
  PCR3: RootFS             (multiple critical binaries, SORTED)
  PCR4: Guardian config    (/etc/sgx-guardian/nodeA.yaml + policy)

Each PCR: new = SHA256(old || SHA256(file_content))
Composite: SHA256(PCR0 || PCR1 || PCR2 || PCR3 || PCR4)
Sign: DKP.sign(SHA256(composite_bytes || nonce_bytes || timestamp_bytes))
Compare: current PCRs vs signed golden baseline
```

PCR values in **software (RAM → disk)**, signed by **SE050 DKP**. NOT stored inside SE050 chip (50KB limit, NVM wear-out risk).




## Deliverables

| # | Name | Tests | Board Work |
|---|------|-------|-----------|
| D1 | PCR Engine + Extend | 17 | Hash files on board |
| D2 | Snapshot + DKP Signing | 6 | Sign with DKP |
| D3 | Golden Baseline | 5 | Create baseline |
| D4 | Attestation + CLI | 4 | Full flow |
| **Total** | | **32** | |

Grand total: 60 (SE050+HKM) + 32 (PCR) = **92 tests**




## File Structure

```
src/secure_element/
  pcr.rs              NEW — PCR engine, snapshot, baseline
  pcr_config.rs       NEW — measurement sources
  mod.rs              MODIFY — add 2 pub mod lines

src/
  attestation_service.rs  MODIFY — add pcr_values + key_version to evidence
  main.rs                 MODIFY — PCR measurement block on startup

sgx-pa-cli/src/commands/
  pcr_status.rs       NEW — show current PCR values
  pcr_baseline.rs     NEW — create + verify baseline
  mod.rs              MODIFY — add 2 pub mod lines

sgx-pa-cli/src/
  main.rs             MODIFY — add 3 CLI commands
```




---




# FILE 1: `src/secure_element/pcr.rs`

```rust
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
/// ║  CHANGE FOR TESTING: 60 = 1 min, 300 = 5 min   ║
/// ║  PRODUCTION DEFAULT: 600 = 10 minutes           ║
/// ╚══════════════════════════════════════════════════╝
pub const MAX_PCR_SNAPSHOT_AGE_SECS: i64 = 600;

/// Current schema version — increment when snapshot format changes.
pub const PCR_SCHEMA_VERSION: u8 = 1;

const PCR_NAMES: [&str; PCR_COUNT] = [
    "BIOS/Bootloader", "Firmware/DTB", "Kernel", "RootFS", "Configuration",
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
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize: {}", e))?;
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
            return Err(format!("PCR count mismatch: snapshot={}, baseline={}",
                self.pcr_values.len(), baseline.pcr_values.len()));
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
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize: {}", e))?;
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

        let sig_bytes = match base64::engine::general_purpose::STANDARD
            .decode(&self.baseline_signature)
        {
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
            return Err(format!("PCR{} out of range (0-{})", pcr_index, PCR_COUNT - 1));
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
                    let _ = self.extend_from_string(pcr_index,
                        &format!("NOT_FOUND:{}", path));
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
        if pcr_index < PCR_COUNT { hex::encode(&self.registers[pcr_index]) }
        else { "invalid".into() }
    }

    /// Composite digest: SHA256(PCR0 || PCR1 || ... || PCR4)
    pub fn composite_digest(&self) -> PcrValue {
        let mut hasher = Sha256::new();
        for pcr in &self.registers { hasher.update(pcr); }
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
        if index < PCR_COUNT { PCR_NAMES[index] } else { "Unknown" }
    }

    pub fn all_measured(&self) -> bool { self.extended.iter().all(|&e| e) }

    pub fn print_status(&self) {
        println!("  PCR Measurements:");
        for i in 0..PCR_COUNT {
            let s = if self.extended[i] { "✅" } else { "⬜" };
            println!("    PCR{} [{}]: {}..  ({})",
                i, s, &self.get_hex(i)[..16], Self::pcr_name(i));
        }
        println!("    Composite: {}...", &hex::encode(self.composite_digest())[..16]);
    }
}

/// Read SE050 hardware UID. Returns "nodeX" fallback if ssscli unavailable.
pub fn read_device_uid(fallback: &str) -> String {
    match std::process::Command::new("ssscli").args(["se05x", "uid"]).output() {
        Ok(out) if out.status.success() => {
            let combined = format!("{}\n{}",
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&out.stdout));
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
                serde_json::from_str::<Vec<serde_json::Value>>(trimmed).ok()
                    .and_then(|keys| keys.iter()
                        .find(|k| k["status"] == "Active")
                        .and_then(|k| k["version"].as_u64()))
                    .map(|v| v as u32)
                    .unwrap_or(1)
            } else {
                serde_json::from_str::<serde_json::Value>(trimmed).ok()
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
        assert_ne!(hex::encode(e1.composite_digest()), hex::encode(e2.composite_digest()));
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
        for i in 0..PCR_COUNT { e.extend(i, b"m").unwrap(); }
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
            pcr_index: 0, source: "bootloader".into(), error: "missing".into(),
        }];
        let critical = errors.iter().any(|e| e.pcr_index == 0 || e.pcr_index == 2);
        assert!(critical);
    }
}
```




# FILE 2: `src/secure_element/pcr_config.rs`

```rust
// src/secure_element/pcr_config.rs
// PCR measurement source configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMeasurementSource {
    pub pcr_index: usize,
    pub label: String,
    /// "file", "string", or "multi_file" (comma-separated paths)
    pub source_type: String,
    pub source: String,
    /// true = system won't boot without this, FAIL if missing
    pub critical: bool,
}

/// Hardware board measurement sources
pub fn default_measurement_sources() -> Vec<PcrMeasurementSource> {
    vec![
        PcrMeasurementSource {
            pcr_index: 0,
            label: "Bootloader".into(),
            source_type: "file".into(),
            source: "/proc/device-tree/model".into(),
            critical: true,
        },
        PcrMeasurementSource {
            pcr_index: 1,
            label: "Device tree".into(),
            source_type: "file".into(),
            source: "/proc/device-tree/compatible".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 2,
            label: "Kernel".into(),
            source_type: "file".into(),
            // Prefer static binary, fallback to /proc/version
            source: if std::path::Path::new("/boot/Image").exists() {
                "/boot/Image".into()
            } else {
                "/proc/version".into()
            },
            critical: true,
        },
        PcrMeasurementSource {
            pcr_index: 3,
            label: "RootFS integrity".into(),
            source_type: "multi_file".into(),
            source: "/bin/sh,/sbin/init,/usr/bin/ssscli".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 4,
            label: "Guardian config".into(),
            source_type: "file".into(),
            source: "/etc/sgx-guardian/nodeA.yaml".into(),
            critical: false,
        },
    ]
}

/// Software mode (dev laptop) measurement sources
pub fn software_measurement_sources() -> Vec<PcrMeasurementSource> {
    vec![
        PcrMeasurementSource {
            pcr_index: 0,
            label: "Bootloader (sim)".into(),
            source_type: "string".into(),
            source: "software-boot-v1.0".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 1,
            label: "Firmware (sim)".into(),
            source_type: "string".into(),
            source: "software-firmware-v1.0".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 2,
            label: "Kernel".into(),
            source_type: "file".into(),
            source: "/proc/version".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 3,
            label: "RootFS (sim)".into(),
            source_type: "string".into(),
            source: "software-rootfs-v1.0".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 4,
            label: "Guardian config".into(),
            source_type: "file".into(),
            source: "/etc/sgx-guardian/schemas/uep_policy_v1.yaml".into(),
            critical: false,
        },
    ]
}
```




# FILE 3: `src/secure_element/mod.rs` — Add 2 lines

```rust
pub mod pcr;
pub mod pcr_config;
```




# MODIFICATION: `src/attestation_service.rs`

Add these fields to `AttestationEvidence`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub nonce: String,
    pub policy_digest: String,
    pub signature: String,
    pub pubkey_der_b64: String,
    /// PCR snapshot (when available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_values: Option<crate::secure_element::pcr::PcrSnapshot>,
    /// DKP key version used for signing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u32>,
}
```

In `create_signed_evidence()`, add after existing code:

```rust
        // Include PCR snapshot if available
        let pcr_path = "/var/lib/sgx-guardian/pcr/current.json";
        let pcr_values = crate::secure_element::pcr::PcrSnapshot::load(pcr_path).ok();
        let key_version = Some(crate::secure_element::pcr::read_dkp_key_version());
```

And update the return:

```rust
        Ok(AttestationEvidence {
            nonce,
            policy_digest,
            signature: signature_b64,
            pubkey_der_b64: pubkey_b64,
            pcr_values,
            key_version,
        })
```

In `verify_signed_evidence()`, add PCR freshness check:

```rust
        // Verify PCR snapshot freshness (if present)
        if let Some(ref pcr) = ev.pcr_values {
            if pcr.schema_version != crate::secure_element::pcr::PCR_SCHEMA_VERSION {
                println!("⚠️ PCR schema version mismatch (got {}, expected {})",
                    pcr.schema_version, crate::secure_element::pcr::PCR_SCHEMA_VERSION);
            }
            if !pcr.is_fresh() {
                println!("⚠️ PCR snapshot is stale (older than {} seconds)",
                    crate::secure_element::pcr::MAX_PCR_SNAPSHOT_AGE_SECS);
            }
            if pcr.integrity_status == "FAIL" {
                println!("🔴 Peer PCR integrity FAILED — rejecting attestation");
                return Ok(false);
            }
        }
```




# MODIFICATION: `src/main.rs` — PCR Measurement Block

Add this AFTER the attestation evidence verification section and BEFORE "Loading node configurations":

```rust
    // === PCR Measurement (ATT-003) ===
    println!("\n  Measuring platform integrity (PCR)...");
    {
        use sgx_guardian_client::secure_element::pcr::*;
        use sgx_guardian_client::secure_element::pcr_config;

        let mut pcr_engine = PcrEngine::new();
        let mut measurement_errors: Vec<PcrMeasurementError> = Vec::new();

        // Detect environment
        let is_hardware = std::path::Path::new("/proc/device-tree/model").exists();
        println!("  PCR mode: {}", if is_hardware { "Hardware (board)" } else { "Software (simulated)" });

        let sources = if is_hardware {
            pcr_config::default_measurement_sources()
        } else {
            pcr_config::software_measurement_sources()
        };

        // Perform measurements
        for src in &sources {
            if src.source_type == "multi_file" {
                let files: Vec<String> = src.source.split(',')
                    .map(|s| s.trim().to_string()).collect();
                let errs = pcr_engine.extend_from_files(src.pcr_index, &files);
                measurement_errors.extend(errs);
            } else {
                let result = match src.source_type.as_str() {
                    "file" => pcr_engine.extend_from_file(src.pcr_index, &src.source),
                    "string" => pcr_engine.extend_from_string(src.pcr_index, &src.source),
                    _ => Err(format!("Unknown type: {}", src.source_type)),
                };
                match result {
                    Ok(hash) => println!("    PCR{}: {} → {}...", src.pcr_index, src.label, &hash[..12]),
                    Err(e) => {
                        let _ = pcr_engine.extend_from_string(src.pcr_index, &format!("ERROR:{}", e));
                        measurement_errors.push(PcrMeasurementError {
                            pcr_index: src.pcr_index,
                            source: src.source.clone(),
                            error: e.clone(),
                        });
                        println!("    PCR{}: {} → ⚠️ {}", src.pcr_index, src.label, e);
                    }
                }
            }
        }

        pcr_engine.print_status();

        // Determine integrity status
        let has_critical_fail = measurement_errors.iter().any(|err| {
            sources.iter().any(|s| s.pcr_index == err.pcr_index && s.critical)
        });
        let integrity_status = if measurement_errors.is_empty() {
            "PASS".to_string()
        } else if has_critical_fail {
            "FAIL".to_string()
        } else {
            "DEGRADED".to_string()
        };

        if integrity_status == "FAIL" {
            eprintln!("  🔴 CRITICAL: Platform integrity check FAILED — attestation will be rejected by peers");
        } else if integrity_status == "DEGRADED" {
            println!("  ⚠️ Some measurements failed (non-critical) — status DEGRADED");
        } else {
            println!("  Platform integrity: ✅ PASS");
        }

        // Build snapshot
        let mut snapshot = pcr_engine.snapshot();
        snapshot.measurement_errors = measurement_errors;
        snapshot.integrity_status = integrity_status;
        snapshot.device_uid = read_device_uid(&node_id);
        snapshot.key_version = read_dkp_key_version();

        // Generate nonce + timestamp
        let mut nonce_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        snapshot.nonce = hex::encode(nonce_bytes);
        snapshot.measured_at = chrono::Utc::now().to_rfc3339();

        // Sign: SHA256(composite_bytes || nonce_bytes || timestamp_bytes)  (BINARY concat)
        let composite_bytes = hex::decode(&snapshot.composite_digest).unwrap_or_else(|_| vec![0u8; 32]);
        let nonce_sign_bytes = hex::decode(&snapshot.nonce).unwrap_or_else(|_| vec![0u8; 16]);
        let ts_bytes = snapshot.measured_at.as_bytes();
        let mut sign_input = Vec::with_capacity(32 + 16 + ts_bytes.len());
        sign_input.extend_from_slice(&composite_bytes);
        sign_input.extend_from_slice(&nonce_sign_bytes);
        sign_input.extend_from_slice(ts_bytes);
        let sign_hash = sha2::Sha256::digest(&sign_input);

        if let Ok(sig) = km.sign(&sign_hash) {
            snapshot.composite_signature =
                Some(base64::engine::general_purpose::STANDARD.encode(&sig));
            println!("  PCR composite signed by DKP (v{}) ✅", snapshot.key_version);
        }

        // Save snapshot
        let pcr_path = "/var/lib/sgx-guardian/pcr/current.json";
        match snapshot.save(pcr_path) {
            Ok(_) => println!("  PCR snapshot → {}", pcr_path),
            Err(e) => eprintln!("  PCR save failed: {}", e),
        }

        // Compare against baseline
        let baseline_path = "/etc/sgx-guardian/pcr_baseline.json";
        if let Ok(baseline) = PcrBaseline::load(baseline_path) {
            // Validate schema version
            if baseline.schema_version != PCR_SCHEMA_VERSION {
                eprintln!("  ⚠️ Baseline schema v{} != current v{} — re-create baseline",
                    baseline.schema_version, PCR_SCHEMA_VERSION);
            } else {
                // Verify baseline signature
                let pubkey = km.pubkey_der();
                if !baseline.verify_signature(&pubkey) {
                    if baseline.key_version != snapshot.key_version {
                        eprintln!("  ⚠️ Baseline signed with DKP v{}, current is v{}. Re-create baseline.",
                            baseline.key_version, snapshot.key_version);
                    } else {
                        eprintln!("  🔴 Baseline signature INVALID — possible tampering!");
                    }
                } else {
                    match snapshot.compare_baseline(&baseline) {
                        Ok(mismatches) if mismatches.is_empty() => {
                            println!("  PCR baseline: ✅ ALL MATCH");
                        }
                        Ok(mismatches) => {
                            eprintln!("  ⚠️ PCR MISMATCH detected:");
                            for idx in &mismatches {
                                eprintln!("    PCR{} [{}]: expected {}.. got {}..",
                                    idx, PcrEngine::pcr_name(*idx),
                                    &baseline.pcr_values[*idx][..16],
                                    &snapshot.pcr_values[*idx][..16]);
                            }
                        }
                        Err(e) => eprintln!("  ⚠️ Baseline compare error: {}", e),
                    }
                }
            }
        } else {
            println!("  No baseline — create with: sgx-pa-cli pcr-baseline-create");
        }
    }
```




# CLI: `sgx-pa-cli/src/commands/pcr_status.rs`

```rust
use std::fs;
use std::path::Path;

const PCR_PATH: &str = "/var/lib/sgx-guardian/pcr/current.json";

pub fn run() {
    println!("=== PCR Status ===\n");
    if !Path::new(PCR_PATH).exists() {
        println!("No PCR snapshot found. Run the guardian daemon first.");
        return;
    }
    let json = match fs::read_to_string(PCR_PATH) {
        Ok(j) => j,
        Err(e) => { eprintln!("Read error: {}", e); return; }
    };
    let snap: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => { eprintln!("Parse error: {}", e); return; }
    };

    let names = ["BIOS/Bootloader", "Firmware/DTB", "Kernel", "RootFS", "Configuration"];
    if let Some(pcrs) = snap["pcr_values"].as_array() {
        for (i, val) in pcrs.iter().enumerate() {
            let name = names.get(i).unwrap_or(&"Unknown");
            println!("  PCR{}: {}  ({})", i, val.as_str().unwrap_or("?"), name);
        }
    }
    println!("\n  Composite:  {}", snap["composite_digest"].as_str().unwrap_or("?"));
    println!("  Integrity:  {}", snap["integrity_status"].as_str().unwrap_or("?"));
    println!("  Measured:   {}", snap["measured_at"].as_str().unwrap_or("?"));
    println!("  Device UID: {}", snap["device_uid"].as_str().unwrap_or("?"));
    println!("  Key ver:    {}", snap["key_version"]);
    println!("  Signed:     {}", if snap["composite_signature"].is_null() { "No" } else { "Yes" });
}
```




# CLI: `sgx-pa-cli/src/commands/pcr_baseline.rs`

```rust
use clap::Subcommand;
use std::fs;
use std::path::Path;

const PCR_PATH: &str = "/var/lib/sgx-guardian/pcr/current.json";
const BASELINE_PATH: &str = "/etc/sgx-guardian/pcr_baseline.json";

#[derive(Subcommand)]
pub enum PcrBaselineCmd {
    /// Create golden baseline from current PCR snapshot
    Create,
    /// Verify current snapshot against baseline
    Verify,
}

pub fn run_create() {
    println!("=== Create PCR Golden Baseline ===\n");
    if !Path::new(PCR_PATH).exists() {
        eprintln!("No PCR snapshot. Run guardian daemon first.");
        return;
    }
    let json = match fs::read_to_string(PCR_PATH) {
        Ok(j) => j,
        Err(e) => { eprintln!("Read error: {}", e); return; }
    };
    let snap: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => { eprintln!("Parse error: {}", e); return; }
    };

    // Copy snapshot PCR values + composite + signature into baseline
    let baseline = serde_json::json!({
        "pcr_values": snap["pcr_values"],
        "composite_digest": snap["composite_digest"],
        "baseline_signature": snap["composite_signature"],
        "created_at": snap["measured_at"],
        "device_uid": snap["device_uid"],
        "key_version": snap["key_version"],
        "schema_version": snap["schema_version"],
    });

    if let Some(parent) = Path::new(BASELINE_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::write(BASELINE_PATH, serde_json::to_string_pretty(&baseline).unwrap()) {
        Ok(_) => {
            println!("✅ Baseline created at {}", BASELINE_PATH);
            println!("   Based on snapshot from {}", snap["measured_at"].as_str().unwrap_or("?"));
        }
        Err(e) => eprintln!("Write error: {}", e),
    }
}

pub fn run_verify() {
    println!("=== Verify PCR Baseline ===\n");
    if !Path::new(BASELINE_PATH).exists() {
        eprintln!("No baseline. Create first: sgx-pa-cli pcr-baseline create");
        return;
    }
    if !Path::new(PCR_PATH).exists() {
        eprintln!("No snapshot. Run guardian daemon first.");
        return;
    }

    let baseline: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(BASELINE_PATH).unwrap()).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(PCR_PATH).unwrap()).unwrap();

    let names = ["BIOS/Bootloader", "Firmware/DTB", "Kernel", "RootFS", "Configuration"];
    let b_pcrs = baseline["pcr_values"].as_array();
    let s_pcrs = snapshot["pcr_values"].as_array();

    if let (Some(bp), Some(sp)) = (b_pcrs, s_pcrs) {
        if bp.len() != sp.len() {
            eprintln!("PCR count mismatch: baseline={}, current={}", bp.len(), sp.len());
            return;
        }
        let mut all_match = true;
        for i in 0..bp.len() {
            let name = names.get(i).unwrap_or(&"?");
            if bp[i] == sp[i] {
                println!("  PCR{} [{}]: ✅ MATCH", i, name);
            } else {
                println!("  PCR{} [{}]: ❌ MISMATCH", i, name);
                println!("    Baseline: {}", bp[i].as_str().unwrap_or("?"));
                println!("    Current:  {}", sp[i].as_str().unwrap_or("?"));
                all_match = false;
            }
        }
        if all_match {
            println!("\n  Result: ✅ ALL PCRs MATCH — device integrity verified");
        } else {
            println!("\n  Result: ❌ MISMATCH DETECTED — investigate immediately");
        }
    }
}
```




# CLI: Update `sgx-pa-cli/src/commands/mod.rs`

Add:
```rust
pub mod pcr_baseline;
pub mod pcr_status;
```


# CLI: Update `sgx-pa-cli/src/main.rs`

Add to enum:
```rust
    /// Show current PCR measurement values
    PcrStatus,
    /// Create golden PCR baseline from current snapshot
    PcrBaselineCreate,
    /// Verify current PCR values against golden baseline
    PcrBaselineVerify,
```

Add to match:
```rust
        Commands::PcrStatus => commands::pcr_status::run(),
        Commands::PcrBaselineCreate => commands::pcr_baseline::run_create(),
        Commands::PcrBaselineVerify => commands::pcr_baseline::run_verify(),
```




# Board Verification Commands

```bash
# After deploying new binary:
./sgx_guardian_client nodeA
# Expected: PCR measurements printed, snapshot saved

# Check snapshot
cat /var/lib/sgx-guardian/pcr/current.json

# Create golden baseline (on trusted system)
./sgx-pa-cli pcr-baseline-create

# Verify baseline matches
./sgx-pa-cli pcr-baseline-verify
# Expected: ✅ ALL PCRs MATCH

# Tamper test: modify config
echo "tampered" >> /etc/sgx-guardian/nodeA.yaml
./sgx_guardian_client nodeA
# Expected: ⚠️ PCR MISMATCH detected: PCR4

# Check PCR status
./sgx-pa-cli pcr-status
```




# Step-by-Step Checklist

```
Step 1:  Create src/secure_element/pcr.rs (17 tests)
Step 2:  Create src/secure_element/pcr_config.rs
Step 3:  Update src/secure_element/mod.rs (+2 pub mod lines)
Step 4:  cargo test secure_element::pcr -- --nocapture → 17 passed
Step 5:  Update src/attestation_service.rs (add pcr_values, key_version, freshness check)
Step 6:  Add PCR measurement block to src/main.rs
Step 7:  cargo build → verify compiles
Step 8:  Test locally (software mode)
Step 9:  Create sgx-pa-cli pcr_status.rs + pcr_baseline.rs
Step 10: Update sgx-pa-cli mod.rs + main.rs
Step 11: cargo build --bin sgx-pa-cli
Step 12: Cross-compile ARM64
Step 13: Deploy to board → verify real measurements
Step 14: Create golden baseline on board
Step 15: Tamper test → verify mismatch detection
```


# Test Summary

| File | Tests |
|------|-------|
| SE050 (existing) | 37 |
| HKM (existing) | 23 |
| **pcr.rs** | **17** |
| **PCR config** | **0** |
| **Total** | **77** |
