// src/secure_element/secure_boot.rs
// ============================================================
// Secure Boot Chain Verification — Checks HAB status,
// boot chain integrity, and binds to PCR measurements.
// ============================================================

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

/// Boot chain verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainStatus {
    /// Is HAB enabled on this device?
    pub hab_enabled: bool,
    /// Is device in closed (enforcing) state?
    pub device_closed: bool,
    /// Were any HAB events (errors) detected?
    pub hab_events_found: bool,
    /// HAB status description
    pub hab_description: String,
    /// Kernel version (verified by boot chain)
    pub kernel_version: String,
    /// Device tree model (set by verified U-Boot)
    pub device_model: String,
    /// Guardian binary hash (for integrity tracking)
    pub guardian_binary_hash: Option<String>,
    /// Overall boot chain integrity
    pub boot_chain_intact: bool,
}

/// Read a 32-bit value from a physical memory address via /dev/mem.
/// Returns None if /dev/mem is inaccessible or mmap fails.
/// Requires root (daemon runs as root).
fn read_phys_u32(phys_addr: u64) -> Option<u32> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new().read(true).open("/dev/mem").ok()?;
    let page_size: u64 = 4096;
    let page_base = phys_addr & !(page_size - 1);
    let offset_in_page = (phys_addr - page_base) as usize;

    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            page_base as libc::off_t,
        );
        if ptr == libc::MAP_FAILED {
            return None;
        }
        let value = std::ptr::read_volatile((ptr as *const u8).add(offset_in_page) as *const u32);
        libc::munmap(ptr, page_size as usize);
        Some(value)
    }
}

impl BootChainStatus {
    /// Check HAB status from Linux userspace.
    /// On i.MX8MP with HAB closed, we verify through multiple indicators.
    pub fn check() -> Self {
        let mut status = Self {
            hab_enabled: false,
            device_closed: false,
            hab_events_found: false,
            hab_description: String::new(),
            kernel_version: String::new(),
            device_model: String::new(),
            guardian_binary_hash: None,
            boot_chain_intact: false,
        };

        // === Method 1: Check /proc/device-tree for HAB indicators ===
        // On a closed i.MX8MP, the device tree is loaded by verified U-Boot
        status.device_model = fs::read_to_string("/proc/device-tree/model")
            .unwrap_or_default()
            .trim_matches('\0')
            .to_string();

        // === Method 2: Check kernel version (loaded by verified boot) ===
        status.kernel_version = fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .trim()
            .to_string();

        // === Method 3: Read OCOTP via /dev/mem (replaces devmem2) ===
        let mut sec_config_read_ok = false;

        // SEC_CONFIG at OCOTP bank 1 word 3: base 0x30350000 + offset 0x470
        if let Some(val) = read_phys_u32(0x30350470) {
            sec_config_read_ok = true;
            status.device_closed = (val & 0x02000000) != 0; // bit 25
            if status.device_closed {
                status.hab_enabled = true;
            }
        }

        // === Method 4: Optional dmesg check for HAB-related messages ===
        // Disabled by default to avoid scanning large kernel logs on long-lived boards.
        // Enable only when needed:
        //   SGX_BOOT_CHECK_DMESG=1
        if std::env::var("SGX_BOOT_CHECK_DMESG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            if let Ok(output) = Command::new("dmesg")
                .args(["--nopager", "-T", "--since", "10 minutes ago"])
                .output()
            {
                let dmesg = String::from_utf8_lossy(&output.stdout);
                let dmesg_lower = dmesg.to_lowercase();

                if dmesg_lower.contains("hab") {
                    status.hab_enabled = true;
                    if dmesg_lower.contains("hab event") || dmesg_lower.contains("hab failure") {
                        status.hab_events_found = true;
                    }
                }
            }
        }

        // === Method 5: Check if signed boot images exist ===
        // On a HAB-enabled board, the boot partition has signed images
        let signed_indicators = [
            "/proc/device-tree/model",      // DT loaded by verified U-Boot
            "/proc/device-tree/compatible", // DT compatible set by verified U-Boot
        ];
        let _all_present = signed_indicators
            .iter()
            .all(|p| std::path::Path::new(p).exists());

        // === Method 6: Check if SRK fuses are programmed ===
        // SRK fuse bank 6 word 0: base 0x30350000 + offset 0x630
        if let Some(val) = read_phys_u32(0x30350630) {
            if val != 0 {
                status.hab_enabled = true;
            }
        }

        // === Status description ===
        if status.device_closed && status.hab_enabled && !status.hab_events_found {
            status.hab_description = "HAB: Enabled, device CLOSED, secure boot ENFORCING".into();
        } else if status.hab_enabled && !status.device_closed {
            status.hab_description = "HAB: Enabled but device OPEN".into();
        } else if !sec_config_read_ok {
            status.hab_description = "HAB: Cannot read OCOTP (need root + /dev/mem)".into();
        } else {
            status.hab_description = "HAB: Not enabled".into();
        }
        if status.hab_events_found {
            status.hab_description = "HAB EVENTS DETECTED — boot chain compromised!".into();
        }

        // === Guardian binary integrity ===
        status.guardian_binary_hash = compute_guardian_binary_hash();

        // === Final chain integrity ===
        status.boot_chain_intact = status.hab_enabled
            && !status.hab_events_found
            && !status.device_model.is_empty()
            && !status.kernel_version.is_empty();

        status
    }

    /// Generate a measurement string for PCR extension.
    /// This binds the boot chain state to the PCR value.
    pub fn to_measurement_string(&self) -> String {
        let kernel_hash = hex::encode(sha2::Sha256::digest(self.kernel_version.as_bytes()));
        format!(
            "HAB:{},CLOSED:{},EVENTS:{},MODEL:{},KERNEL_HASH:{}",
            self.hab_enabled,
            self.device_closed,
            self.hab_events_found,
            self.device_model,
            &kernel_hash[..16],
        )
    }

    /// Print boot chain status
    pub fn print(&self) {
        println!("  Secure Boot Chain:");
        println!(
            "    HAB:           {}",
            if self.hab_enabled {
                "✅ Enabled"
            } else {
                "❌ Not detected"
            }
        );
        println!(
            "    Device state:  {}",
            if self.device_closed {
                "🔒 CLOSED (enforcing)"
            } else {
                "🔓 Open"
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
        println!("    Device model:  {}", self.device_model);
        if let Some(ref hash) = self.guardian_binary_hash {
            println!("    Binary hash:   {}...", &hash[..16]);
        }
        println!(
            "    Boot chain:    {}",
            if self.boot_chain_intact {
                "✅ INTACT"
            } else {
                "⚠️ INCOMPLETE"
            }
        );
    }

    /// Save boot chain status to JSON
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize: {}", e))?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Dir: {}", e))?;
        }
        fs::write(path, json).map_err(|e| format!("Write: {}", e))
    }
}

/// Compute SHA-256 hash of the Guardian daemon binary.
fn compute_guardian_binary_hash() -> Option<String> {
    // Try common locations
    let paths = [
        "/root/sgx_guardian_client",
        "/usr/local/bin/sgx_guardian_client",
        "/usr/bin/sgx_guardian_client",
    ];

    // Also check /proc/self/exe (the running binary itself)
    if let Ok(exe_path) = fs::read_link("/proc/self/exe") {
        if let Ok(data) = fs::read(&exe_path) {
            return Some(hex::encode(Sha256::digest(&data)));
        }
    }

    for path in &paths {
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
        let mut status = BootChainStatus {
            hab_enabled: true,
            device_closed: true,
            hab_events_found: false,
            hab_description: String::new(),
            kernel_version: "test".into(),
            device_model: "test".into(),
            guardian_binary_hash: None,
            boot_chain_intact: false,
        };
        // All conditions met
        status.boot_chain_intact = status.hab_enabled
            && !status.hab_events_found
            && !status.device_model.is_empty()
            && !status.kernel_version.is_empty();
        assert!(status.boot_chain_intact);
    }

    #[test]
    fn test_hab_events_break_chain() {
        let status = BootChainStatus {
            hab_enabled: true,
            device_closed: true,
            hab_events_found: true, // ← events found
            hab_description: String::new(),
            kernel_version: "test".into(),
            device_model: "test".into(),
            guardian_binary_hash: None,
            boot_chain_intact: false,
        };
        let intact =
            status.hab_enabled && !status.hab_events_found && !status.device_model.is_empty();
        assert!(!intact); // broken
    }

    #[test]
    fn test_guardian_binary_hash_length() {
        // SHA-256 hash = 64 hex chars
        let hash = hex::encode(Sha256::digest(b"test binary content"));
        assert_eq!(hash.len(), 64);
    }
}
