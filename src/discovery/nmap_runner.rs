use crate::discovery::{
    config::NmapConfig,
    error::{DiscoveryError, DiscoveryResult},
    ScanIntensity,
};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::Duration;

pub struct NmapRunner;

impl NmapRunner {
    /// Async-only - never block the tokio runtime.
    /// Returns the raw XML on success.
    pub async fn run(cfg: &NmapConfig, target: &str) -> DiscoveryResult<String> {
        Self::run_with_intensity(cfg, target, cfg.ad_hoc_intensity()).await
    }

    /// Async-only - never block the tokio runtime.
    /// Returns the raw XML on success using the provided scan intensity.
    pub async fn run_with_intensity(
        cfg: &NmapConfig,
        target: &str,
        intensity: ScanIntensity,
    ) -> DiscoveryResult<String> {
        let args = cfg.nmap_args_for_intensity(target, intensity);
        Self::run_with_args(cfg, &args).await
    }

    /// Connected Devices targeted security scan — bounded profile for ARM boards.
    pub async fn run_device_security_scan(
        cfg: &NmapConfig,
        target: &str,
    ) -> DiscoveryResult<String> {
        let args = cfg.nmap_args_for_device_security_scan(target);
        Self::run_with_args(cfg, &args).await
    }

    async fn run_with_args(cfg: &NmapConfig, args: &[String]) -> DiscoveryResult<String> {
        if let Some(xml) = load_test_fixture_xml()? {
            return Ok(xml);
        }

        // Probe binary first; clearer error than spawn-failed.
        if which::which("nmap").is_err() {
            return Err(DiscoveryError::BinaryMissing);
        }

        let child = Command::new("nmap")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        // CRITICAL: stdout + stderr must be drained *concurrently* with the wait.
        //
        // The earlier version awaited `child.wait()` first and only read the
        // pipes afterwards. `wait()` does not drain the pipes - it only polls
        // for process exit. The OS pipe buffer is ~64 KiB; on Standard/Aggressive
        // `/24` scans the XML written to stdout exceeds that, so nmap blocks on
        // write(), never exits, `wait()` never returns, and the scan dead-locks
        // until the hard timeout fires (the "timeout after 600s" seen on board).
        // Stealth's tiny ARP-sweep output fits the buffer, which is the only
        // reason it ever completed.
        //
        // `wait_with_output()` reads both pipes to EOF while nmap is still
        // running, so the buffer can never fill. On timeout the future is
        // dropped, which drops the `Child`; `kill_on_drop(true)` then reaps nmap.
        let timeout = Duration::from_secs(cfg.timeout_secs);
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(DiscoveryError::Io(e)),
            Err(_) => {
                return Err(DiscoveryError::NmapFailed(
                    -1,
                    format!("timeout after {}s", cfg.timeout_secs),
                ));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DiscoveryError::NmapFailed(
                output.status.code().unwrap_or(-1),
                stderr.lines().take(3).collect::<Vec<_>>().join(" | "),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn load_test_fixture_xml() -> DiscoveryResult<Option<String>> {
    let Some(path) = std::env::var_os("SGX_TEST_NMAP_XML_FILE") else {
        return Ok(None);
    };

    let path = PathBuf::from(path);
    Ok(Some(std::fs::read_to_string(path)?))
}
