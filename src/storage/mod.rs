pub mod file_lock;
pub mod backup;

use std::fs;
use std::path::PathBuf;

/// Resolves the storage path for data files (devices.json, pending_actions.json, automations.json).
/// Prefers:
/// 1. `SGX_DATA_DIR` environment variable override if set.
/// 2. `/var/lib/sgx-guardian` (standard Linux / hardware board data directory).
/// 3. Current working directory `.` (fallback for local non-root development).
pub fn resolve_data_file(filename: &str) -> String {
    let mut candidates = Vec::new();
    if let Ok(override_dir) = std::env::var("SGX_DATA_DIR") {
        if !override_dir.trim().is_empty() {
            candidates.push(PathBuf::from(override_dir));
        }
    }
    candidates.push(PathBuf::from("/var/lib/sgx-guardian"));
    candidates.push(PathBuf::from("."));

    let dir = candidates
        .into_iter()
        .find(|d| fs::create_dir_all(d).is_ok())
        .unwrap_or_else(|| PathBuf::from("."));

    dir.join(filename).to_string_lossy().to_string()
}

/// Resolves the storage directory for telemetry log files.
/// Prefers:
/// 1. `SGX_LOG_DIR` environment variable override if set.
/// 2. `/var/log/sgx-guardian/telemetry` (standard Linux log directory).
/// 3. `/var/lib/sgx-guardian/telemetry` (standard Linux data directory).
/// 4. `telemetry` (fallback for local non-root development).
pub fn resolve_telemetry_dir() -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(override_dir) = std::env::var("SGX_LOG_DIR") {
        if !override_dir.trim().is_empty() {
            candidates.push(PathBuf::from(override_dir));
        }
    }
    candidates.push(PathBuf::from("/var/log/sgx-guardian/telemetry"));
    candidates.push(PathBuf::from("/var/lib/sgx-guardian/telemetry"));
    candidates.push(PathBuf::from("telemetry"));

    for dir in candidates {
        if fs::create_dir_all(&dir).is_ok() {
            return dir;
        }
    }

    PathBuf::from("telemetry")
}
