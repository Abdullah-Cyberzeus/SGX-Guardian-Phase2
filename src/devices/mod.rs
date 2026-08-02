pub mod errors;
pub mod model;
pub mod registry;
pub mod scan;
pub mod scoring;

use std::path::PathBuf;

pub const DEVICES_BASE_ENV: &str = "SGX_GUARDIAN_DEVICES_BASE";
pub const SCAN_TIMEOUT_ENV: &str = "SGX_DEVICES_SCAN_TIMEOUT_SECS";
/// Guardian outer timeout around the per-device NMAP security scan.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 180;

#[derive(Debug, Clone)]
pub struct DevicesConfig {
    pub base_dir: PathBuf,
    pub scan_timeout_secs: u64,
}

impl DevicesConfig {
    pub fn from_env() -> Self {
        let base_dir = std::env::var_os(DEVICES_BASE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/sgx-guardian/devices"));
        let scan_timeout_secs = std::env::var(SCAN_TIMEOUT_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS);

        Self {
            base_dir,
            scan_timeout_secs,
        }
    }

    pub fn registry_path(&self) -> PathBuf {
        self.base_dir.join("registry.json")
    }

    pub fn scans_path(&self) -> PathBuf {
        self.base_dir.join("scans.jsonl")
    }
}

pub use model::{DeviceRecord, DeviceScanRun, DeviceScores};

#[cfg(test)]
mod tests {
    use super::DEFAULT_SCAN_TIMEOUT_SECS;

    #[test]
    fn default_scan_timeout_is_180s() {
        assert_eq!(DEFAULT_SCAN_TIMEOUT_SECS, 180);
    }
}
