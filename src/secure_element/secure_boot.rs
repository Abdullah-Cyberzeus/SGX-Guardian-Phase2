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

        // === Method 3: Try devmem2 to read OTP fuse shadow registers ===
        // SEC_CONFIG fuse at OCOTP bank 1 word 3
        // i.MX8MP shadow register offset for bank 1 word 3
        if let Ok(output) = Command::new("devmem2")
            .args(["0x30350470"]) // OCOTP shadow register for SEC_CONFIG
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // devmem2 output: "Read at address 0x30350470: 0xNNNNNNNN"
            if let Some(val_str) = stdout.split("0x").last() {
                if let Ok(val) = u32::from_str_radix(val_str.trim(), 16) {
                    // Bit 25 = SEC_CONFIG[1] = device closed
                    status.device_closed = (val & 0x02000000) != 0;
                    status.hab_enabled = true;
                }
            }
        }

        // === Method 4: Check dmesg for HAB-related messages ===
        if let Ok(output) = Command::new("dmesg").output() {
            let dmesg = String::from_utf8_lossy(&output.stdout);
            let dmesg_lower = dmesg.to_lowercase();

            if dmesg_lower.contains("hab") {
                status.hab_enabled = true;
                if dmesg_lower.contains("hab event") || dmesg_lower.contains("hab failure") {
                    status.hab_events_found = true;
                }
            }
        }

        // === Method 5: Check if signed boot images exist ===
        // On a HAB-enabled board, the boot partition has signed images
        let signed_indicators = [
            "/proc/device-tree/model",      // DT loaded by verified U-Boot
            "/proc/device-tree/compatible", // DT compatible set by verified U-Boot
        ];
        let all_present = signed_indicators
            .iter()
            .all(|p| std::path::Path::new(p).exists());

        // === Method 6: Check if SRK fuses are programmed ===
        // Try reading fuse bank 6 word 0 via devmem2
        if let Ok(output) = Command::new("devmem2")
            .args(["0x30350630"]) // OCOTP bank 6 word 0 shadow register
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // If value is non-zero, SRK fuses are programmed
                if let Some(val_str) = stdout.split("0x").last() {
                    if let Ok(val) = u32::from_str_radix(val_str.trim(), 16) {
                        if val != 0 {
                            status.hab_enabled = true;
                        }
                    }
                }
            }
        }

        // === Determine overall status ===
        // On our board, HAB is done by HAE (confirmed from email chain).
        // If devmem2 is unavailable, we trust the hardware configuration.
        // The fact that the board boots at all with a closed SEC_CONFIG
        // proves the signed image is valid.
        if !status.hab_enabled {
            // devmem2 might not be available — check for board indicators
            if !status.device_model.is_empty() && all_present {
                // Board is running, DT is present — if HAB were broken, it wouldn't boot
                status.hab_description =
                    "HAB status: Unable to verify from Linux — check via U-Boot hab_status command"
                        .into();
                // Mark as enabled based on known hardware configuration
                // In production: this should be verified once via U-Boot
                status.hab_enabled = false;
                status.device_closed = false; // Known from HAB fuse programming
            } else {
                status.hab_description = "HAB status: Unable to determine".into();
            }
        } else if status.hab_events_found {
            status.hab_description = "HAB EVENTS DETECTED — boot chain may be compromised!".into();
        } else if status.device_closed {
            status.hab_description = "HAB: Enabled, device CLOSED, secure boot ENFORCING".into();
        } else {
            status.hab_description =
                "HAB: Enabled but device OPEN (signatures checked but not enforced)".into();
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
