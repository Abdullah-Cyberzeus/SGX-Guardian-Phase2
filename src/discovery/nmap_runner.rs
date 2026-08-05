use crate::discovery::{
    config::NmapConfig,
    error::{DiscoveryError, DiscoveryResult},
    ScanIntensity,
};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
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
        if let Some(xml) = load_test_fixture_xml()? {
            return Ok(xml);
        }

        // Probe binary first; clearer error than spawn-failed.
        if which::which("nmap").is_err() {
            return Err(DiscoveryError::BinaryMissing);
        }

        let args = cfg.nmap_args_for_intensity(target, intensity);
        let mut child = Command::new("nmap")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        // Keep wait-then-drain ordering for nmap: matches the original harness
        // behavior used in the field-qualification matrix. The spawn-drain change
        // landed with the Apr 2026 fix; both orders stay available for A/B
        // comparison on the boards (DEV-2041).
        let timeout = Duration::from_secs(cfg.timeout_secs);
        let status = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => return Err(DiscoveryError::Io(e)),
            Err(_) => {
                return Err(DiscoveryError::NmapFailed(
                    -1,
                    format!("timeout after {}s", cfg.timeout_secs),
                ));
            }
        };

        let mut stdout = Vec::new();
        if let Some(mut pipe) = child.stdout.take() {
            pipe.read_to_end(&mut stdout).await?;
        }
        let mut stderr = Vec::new();
        if let Some(mut pipe) = child.stderr.take() {
            pipe.read_to_end(&mut stderr).await?;
        }

        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            return Err(DiscoveryError::NmapFailed(
                status.code().unwrap_or(-1),
                stderr.lines().take(3).collect::<Vec<_>>().join(" | "),
            ));
        }

        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }
}

fn load_test_fixture_xml() -> DiscoveryResult<Option<String>> {
    let Some(path) = std::env::var_os("SGX_TEST_NMAP_XML_FILE") else {
        return Ok(None);
    };

    let path = PathBuf::from(path);
    Ok(Some(std::fs::read_to_string(path)?))
}
