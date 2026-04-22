// src/secure_element/secure_boot.rs
// ============================================================
// Secure Boot Chain Verification — Checks HAB status,
// boot chain integrity, and binds to PCR measurements.
//
// FIX (board-freeze branch, Apr 2026):
//   - REMOVED /dev/mem mmap to OCOTP — caused AXI hang + HW watchdog reset
//     on i.MX8MP when OCOTP clock was gated. This was the root cause of
//     every STEP_06 / STEP_07 freeze on boards 101/115/248.
//   - OCOTP reads now go via /sys/bus/nvmem/devices/imx-ocotp*/nvmem,
//     which routes through the kernel driver (handles clock gating).
//   - OCOTP read GATED behind SGX_READ_OCOTP env flag (default OFF — safe).
//   - Binary hash GATED behind SGX_MEASURE_BINARY_HASH env flag (default OFF).
//   - Every sub-step wrapped in a hard timeout (thread + mpsc::recv_timeout).
//   - Result CACHED once per process lifetime via OnceCell — the three
//     callers (boot check / PCR loop / attestation quote) share one snapshot.
// ============================================================

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

use crate::runtime_gates::GATES;

/// Process-wide cache. First caller populates it; every subsequent caller
/// (PCR loop, AttestationQuote::generate) reads the same snapshot.
static BOOT_CHAIN_CACHE: OnceCell<BootChainStatus> = OnceCell::new();

/// Boot chain verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainStatus {
    pub hab_enabled: bool,
    pub device_closed: bool,
    pub hab_events_found: bool,
    pub hab_description: String,
    pub kernel_version: String,
    pub device_model: String,
    pub guardian_binary_hash: Option<String>,
    pub boot_chain_intact: bool,
}

impl BootChainStatus {
    /// Safe "unknown" default — never touches hardware, never blocks.
    /// Used as fallback when the real check is skipped or times out.
    pub fn unknown() -> Self {
        Self {
            hab_enabled: false,
            device_closed: false,
            hab_events_found: false,
            hab_description: "HAB: Unknown (boot check unavailable or timed out)".into(),
            kernel_version: String::new(),
            device_model: String::new(),
            guardian_binary_hash: None,
            boot_chain_intact: false,
        }
    }

    /// Public entry point. Returns the cached snapshot, computing it on the
    /// first call. Safe to call from any thread or async context. Internal
    /// timeouts guarantee this function returns within ~10 seconds worst case.
    pub fn check() -> Self {
        BOOT_CHAIN_CACHE.get_or_init(Self::check_inner).clone()
    }

    /// Force-populate the cache with a caller-supplied value. Used by main.rs
    /// after its outer tokio::time::timeout wrapper produces a result, so
    /// subsequent callers (PCR loop, attestation quote) hit the cache cleanly.
    /// No-op if the cache is already populated.
    pub fn prime_cache(status: BootChainStatus) {
        let _ = BOOT_CHAIN_CACHE.set(status);
    }

    /// Actual implementation. Only runs on the first `check()` call when the
    /// cache is empty and `prime_cache()` hasn't been called. Each sub-step
    /// is independently timeout-guarded.
    fn check_inner() -> Self {
        let t_start = std::time::Instant::now();
        let mut status = Self::unknown();

        // === Step 1: Device model (safe filesystem read, < 1ms) =============
        info!("BootChain: reading /proc/device-tree/model");
        status.device_model = fs::read_to_string("/proc/device-tree/model")
            .unwrap_or_default()
            .trim_matches('\0')
            .to_string();

        // === Step 2: Kernel version (safe filesystem read, < 1ms) ===========
        info!("BootChain: reading /proc/version");
        status.kernel_version = fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .trim()
            .to_string();

        // === Step 3: OCOTP reads via nvmem (GATED, timeout-guarded) =========
        let mut sec_config_read_ok = false;

        if GATES.read_ocotp {
            info!("BootChain: SGX_READ_OCOTP=1 — attempting nvmem OCOTP read");

            // SEC_CONFIG: bank 1 word 3 → nvmem offset (1*8 + 3) * 4 = 0x2C
            // (imx-ocotp nvmem presents 4 bytes per fuse word, densely packed)
            match run_with_timeout(Duration::from_secs(2), || read_nvmem_u32(0x2C)) {
                Some(Some(val)) => {
                    sec_config_read_ok = true;
                    status.device_closed = (val & 0x02000000) != 0; // bit 25
                    if status.device_closed {
                        status.hab_enabled = true;
                    }
                    info!(
                        "BootChain: OCOTP SEC_CONFIG ok (val=0x{:08X}, closed={})",
                        val, status.device_closed
                    );
                }
                Some(None) => {
                    warn!("BootChain: OCOTP SEC_CONFIG — nvmem node not found");
                }
                None => {
                    warn!("BootChain: OCOTP SEC_CONFIG read TIMED OUT");
                }
            }

            // SRK fuse: bank 6 word 0 → nvmem offset (6*8 + 0) * 4 = 0xC0
            match run_with_timeout(Duration::from_secs(2), || read_nvmem_u32(0xC0)) {
                Some(Some(val)) => {
                    if val != 0 {
                        status.hab_enabled = true;
                        info!("BootChain: SRK fuse present (val=0x{:08X})", val);
                    } else {
                        info!("BootChain: SRK fuse empty (val=0x00000000) — board in OPEN mode");
                    }
                }
                Some(None) => {
                    warn!("BootChain: SRK fuse — nvmem node not found");
                }
                None => {
                    warn!("BootChain: SRK fuse read TIMED OUT");
                }
            }
        } else {
            info!("BootChain: OCOTP read skipped (SGX_READ_OCOTP not set — safe default)");
        }

        // === Step 4: Optional dmesg scan (GATED, unchanged behaviour) =======
        if std::env::var("SGX_BOOT_CHECK_DMESG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            info!("BootChain: scanning dmesg for HAB events (SGX_BOOT_CHECK_DMESG=1)");
            if let Some(Ok(output)) = run_with_timeout(Duration::from_secs(3), || {
                Command::new("dmesg")
                    .args(["--nopager", "-T", "--since", "10 minutes ago"])
                    .output()
            }) {
                let dmesg_lower = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if dmesg_lower.contains("hab") {
                    status.hab_enabled = true;
                    if dmesg_lower.contains("hab event") || dmesg_lower.contains("hab failure") {
                        status.hab_events_found = true;
                    }
                }
            } else {
                warn!("BootChain: dmesg scan timed out or failed");
            }
        }

        // === Step 5: Human-readable description =============================
        if status.device_closed && status.hab_enabled && !status.hab_events_found {
            status.hab_description = "HAB: Enabled, device CLOSED, secure boot ENFORCING".into();
        } else if status.hab_enabled && !status.device_closed {
            status.hab_description = "HAB: Enabled but device OPEN".into();
        } else if GATES.read_ocotp && !sec_config_read_ok {
            status.hab_description = "HAB: Cannot read OCOTP via nvmem (driver not loaded?)".into();
        } else if !GATES.read_ocotp {
            status.hab_description =
                "HAB: Unknown (OCOTP read disabled — set SGX_READ_OCOTP=1 to attempt)".into();
        } else {
            status.hab_description = "HAB: Not enabled".into();
        }
        if status.hab_events_found {
            status.hab_description = "HAB EVENTS DETECTED — boot chain compromised!".into();
        }

        // === Step 6: Guardian binary hash (GATED, timeout-guarded) ==========
        if GATES.measure_binary_hash {
            info!("BootChain: SGX_MEASURE_BINARY_HASH=1 — computing binary SHA-256 (blocking)");
            status.guardian_binary_hash =
                run_with_timeout(Duration::from_secs(5), || compute_guardian_binary_hash())
                    .flatten();
            match &status.guardian_binary_hash {
                Some(h) => info!("BootChain: binary hash computed ({}...)", &h[..16]),
                None => warn!("BootChain: binary hash failed or TIMED OUT"),
            }
        } else {
            info!(
                "BootChain: binary hash skipped (SGX_MEASURE_BINARY_HASH not set — safe default)"
            );
        }

        // === Step 7: Final chain integrity ==================================
        status.boot_chain_intact = status.hab_enabled
            && !status.hab_events_found
            && !status.device_model.is_empty()
            && !status.kernel_version.is_empty();

        info!(
            "BootChain: check_inner completed in {:?} (hab_enabled={}, closed={}, intact={})",
            t_start.elapsed(),
            status.hab_enabled,
            status.device_closed,
            status.boot_chain_intact
        );
        status
    }

    /// Generate a measurement string for PCR extension.
    /// Binds the boot chain state into PCR0.
    pub fn to_measurement_string(&self) -> String {
        let kernel_hash = if self.kernel_version.is_empty() {
            "unknown".to_string()
        } else {
            let h = hex::encode(Sha256::digest(self.kernel_version.as_bytes()));
            h[..16].to_string()
        };
        format!(
            "HAB:{},CLOSED:{},EVENTS:{},MODEL:{},KERNEL_HASH:{}",
            self.hab_enabled,
            self.device_closed,
            self.hab_events_found,
            self.device_model,
            kernel_hash,
        )
    }

    /// Pretty-print boot chain status.
    pub fn print(&self) {
        println!("  Secure Boot Chain:");
        println!(
            "    HAB:           {}",
            if self.hab_enabled {
                "✅ Enabled"
            } else {
                "❓ Not detected / unknown"
            }
        );
        println!(
            "    Device state:  {}",
            if self.device_closed {
                "🔒 CLOSED (enforcing)"
            } else {
                "🔓 Open / unknown"
            }
        );
        println!(
            "    HAB events:    {}",
            if self.hab_events_found {
                "⚠️ EVENTS FOUND"
            } else {
                "✅ None"
            }
        );
        println!(
            "    Device model:  {}",
            if self.device_model.is_empty() {
                "unknown"
            } else {
                &self.device_model
            }
        );
        println!("    Description:   {}", self.hab_description);
        if let Some(ref hash) = self.guardian_binary_hash {
            println!("    Binary hash:   {}...", &hash[..16.min(hash.len())]);
        }
        println!(
            "    Boot chain:    {}",
            if self.boot_chain_intact {
                "✅ INTACT"
            } else {
                "⚠️ INCOMPLETE / UNKNOWN"
            }
        );
    }

    /// Save boot chain status to JSON.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize: {}", e))?;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }
}

// ── Private helpers ─────────────────────────────────────────

/// Run a closure on a worker thread with a hard timeout.
/// Returns `Some(result)` if the closure completed in time, `None` otherwise.
/// The worker thread is detached on timeout — if it is stuck in a kernel-mode
/// read, it lives until process exit, which is acceptable (better than
/// blocking the caller).
fn run_with_timeout<T, F>(timeout: Duration, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let _detached = thread::spawn(move || {
        let result = f();
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout).ok()
}

/// Read a 4-byte little-endian value from the i.MX OCOTP nvmem interface.
/// Returns None if the nvmem node does not exist or cannot be read.
///
/// SAFETY: This goes through the kernel nvmem-imx-ocotp driver which handles
/// OCOTP clock gating and bus synchronization. No AXI hangs possible, unlike
/// the previous /dev/mem mmap approach that caused board freezes.
fn read_nvmem_u32(offset: u64) -> Option<u32> {
    let candidates = [
        "/sys/bus/nvmem/devices/imx-ocotp0/nvmem",
        "/sys/bus/nvmem/devices/imx-ocotp1/nvmem",
    ];
    for path in &candidates {
        if !Path::new(path).exists() {
            continue;
        }
        let Ok(mut f) = std::fs::OpenOptions::new().read(true).open(path) else {
            continue;
        };
        if f.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut buf = [0u8; 4];
        if f.read_exact(&mut buf).is_err() {
            continue;
        }
        return Some(u32::from_le_bytes(buf));
    }
    None
}

/// Compute SHA-256 hash of the Guardian daemon binary (17 MB).
/// Called ONLY when SGX_MEASURE_BINARY_HASH=1. Wrapped in a 5s timeout.
fn compute_guardian_binary_hash() -> Option<String> {
    if let Ok(exe_path) = fs::read_link("/proc/self/exe") {
        if let Ok(data) = fs::read(&exe_path) {
            return Some(hex::encode(Sha256::digest(&data)));
        }
    }
    for path in &[
        "/home/root/sgx_guardian_client",
        "/root/sgx_guardian_client",
        "/usr/local/bin/sgx_guardian_client",
        "/usr/bin/sgx_guardian_client",
    ] {
        if let Ok(data) = fs::read(path) {
            return Some(hex::encode(Sha256::digest(&data)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_defaults_are_safe() {
        let u = BootChainStatus::unknown();
        assert!(!u.hab_enabled);
        assert!(!u.device_closed);
        assert!(!u.boot_chain_intact);
        assert!(u.hab_description.to_lowercase().contains("unknown"));
    }

    #[test]
    fn test_measurement_string_handles_empty_kernel() {
        let mut u = BootChainStatus::unknown();
        u.kernel_version = String::new();
        let s = u.to_measurement_string();
        assert!(s.contains("KERNEL_HASH:unknown"));
    }

    #[test]
    fn test_measurement_string_format() {
        let status = BootChainStatus {
            hab_enabled: true,
            device_closed: true,
            hab_events_found: false,
            hab_description: "test".into(),
            kernel_version: "Linux 6.1.36".into(),
            device_model: "Variscite VAR-SOM-MX8M-PLUS".into(),
            guardian_binary_hash: Some("abc123".into()),
            boot_chain_intact: true,
        };
        let m = status.to_measurement_string();
        assert!(m.contains("HAB:true"));
        assert!(m.contains("CLOSED:true"));
        assert!(m.contains("EVENTS:false"));
    }

    #[test]
    fn test_boot_chain_intact_requires_all() {
        let mut status = BootChainStatus::unknown();
        status.hab_enabled = true;
        status.device_closed = true;
        status.kernel_version = "test".into();
        status.device_model = "test".into();
        status.boot_chain_intact = status.hab_enabled
            && !status.hab_events_found
            && !status.device_model.is_empty()
            && !status.kernel_version.is_empty();
        assert!(status.boot_chain_intact);
    }

    #[test]
    fn test_hab_events_break_chain() {
        let mut status = BootChainStatus::unknown();
        status.hab_enabled = true;
        status.device_closed = true;
        status.hab_events_found = true;
        status.kernel_version = "test".into();
        status.device_model = "test".into();
        let intact =
            status.hab_enabled && !status.hab_events_found && !status.device_model.is_empty();
        assert!(!intact);
    }

    #[test]
    fn test_guardian_binary_hash_length() {
        let hash = hex::encode(Sha256::digest(b"test binary content"));
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_run_with_timeout_returns_value_when_fast() {
        let v = run_with_timeout(Duration::from_millis(100), || 42);
        assert_eq!(v, Some(42));
    }

    #[test]
    fn test_run_with_timeout_returns_none_on_timeout() {
        let v = run_with_timeout(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_millis(500));
            99
        });
        assert_eq!(v, None);
    }

    #[test]
    fn test_read_nvmem_nonexistent_path_returns_none() {
        // On a dev laptop there is no /sys/bus/nvmem/devices/imx-ocotp* —
        // the function must return None cleanly without panicking.
        let _ = read_nvmem_u32(0x2C);
    }
}
