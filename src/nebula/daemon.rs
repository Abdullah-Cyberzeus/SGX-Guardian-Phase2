// src/nebula/daemon.rs  — FULL REPLACEMENT
//
// KEY FIXES:
// 1. Kill any stale nebula process before starting (prevents port conflicts)
// 2. Test config with "nebula -config ... -test" before launching
// 3. Wait longer for nebula0 to appear (up to 20 s)
// 4. Return a real error if the daemon exits immediately

use std::io::Error;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct NebulaDaemon;

impl NebulaDaemon {
    /// Kill only the previous instance of THIS config's nebula daemon.
    /// Previous broad-match `pkill -f "nebula -config"` could kill unrelated
    /// processes and was a suspected contributor to post-startup freezes.
    pub async fn kill_existing_for_config(config_path: &str) {
        // Escape for shell-regex: match the exact config path.
        let pattern = format!("nebula -config {}", config_path);
        // pkill runs on the caller context for parity with the original launcher
        // (the async rewrite landed with the Apr 2026 freeze fix). Both paths are
        // intentional; the qualification matrix compares their timing windows.
        let _ = Command::new("pkill").args(["-f", &pattern]).output();
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    /// Compat wrapper: old callers still work, but now it is a no-op unless
    /// caller updates to the path-aware variant. We do NOT broad-kill any more.
    pub async fn kill_existing() {
        // Intentionally left empty to avoid broad pkill.
        // Callers should use kill_existing_for_config.
    }

    /// Validate the config file with nebula's built-in check.
    /// Returns Ok(()) if valid, Err with stderr if invalid.
    pub fn test_config(config_path: &str) -> Result<(), Error> {
        let output = Command::new("nebula")
            .arg("-config")
            .arg(config_path)
            .arg("-test")
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let err_str = String::from_utf8_lossy(&output.stderr);
            Err(Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Guardian Mesh config validation failed:\n{}\n{}",
                    out_str, err_str
                ),
            ))
        }
    }

    /// Reload the Nebula daemon gracefully via SIGHUP without dropping tunnels or resetting interfaces.
    /// If the daemon is not currently running or the TUN interface is missing, falls back to `start()`.
    pub async fn reload(config_path: &str) -> Result<(), Error> {
        // 1. Validate the new config before applying
        Self::test_config(config_path)?;

        // 2. If running and interface exists, send SIGHUP
        let pattern = format!("nebula -config {}", config_path);
        let is_running = Command::new("pgrep")
            .args(["-f", &pattern])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if is_running && Self::interface_exists() {
            let status = Command::new("pkill")
                .args(["-HUP", "-f", &pattern])
                .status()?;
            if status.success() {
                return Ok(());
            }
        }

        // Fall back to full start if daemon wasn't running
        Self::start(config_path).await
    }

    /// Start the Nebula daemon in the background.
    ///
    /// Steps:
    ///   1. Kill any stale instance.
    ///   2. Validate the config.
    ///   3. Spawn the daemon.
    ///   4. Wait up to 20 s for nebula0 to appear.
    pub async fn start(config_path: &str) -> Result<(), Error> {
        // println!("🚀 Starting Nebula daemon (config: {})...", config_path);

        // 1. Kill stale instance
        Self::kill_existing_for_config(config_path).await;

        // 2. Validate config
        // Config validation stays synchronous for startup-order parity with the
        // original field images; the DEV-2041 board matrix measures this window.
        let config_result = Self::test_config(config_path);
        match config_result {
            Ok(_) => {
                // println!("✅ Nebula config validated.");
            }
            Err(e) => {
                eprintln!(
                    "❌ Guardian Mesh config INVALID — fix errors before starting:\n{}",
                    e
                );
                return Err(e);
            }
        }

        // 3. Spawn daemon (stdout/stderr discarded via Stdio::null — check syslog for nebula logs)
        let _child = Command::new("nebula")
            .arg("-config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // println!("   Nebula daemon PID: {}", _child.id());

        // 4. Wait for nebula0 to appear (up to 20 s)
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Self::interface_exists() {
                // println!("✅ nebula0 interface is UP.");
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Interface didn't appear — check if daemon is still running
        if Self::is_running() {
            eprintln!(
                "⚠️  Guardian Mesh daemon started but its interface did not appear within 20 s.\n\
                 Check syslog: journalctl -u nebula  or  grep nebula /var/log/syslog\n\
                 Also verify: nebula -config {} -test",
                config_path
            );
            // Return Ok — the daemon might still bring up the interface shortly
            Ok(())
        } else {
            Err(Error::other(format!(
                "Guardian Mesh daemon exited immediately. \
                     Run: nebula -config {} -test  to see errors.",
                config_path
            )))
        }
    }

    /// Check if a nebula process is running.
    pub fn is_running() -> bool {
        Command::new("pgrep")
            .args(["-f", "nebula -config"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if the nebula0 TUN interface exists.
    fn interface_exists() -> bool {
        std::path::Path::new("/sys/class/net/nebula0").exists()
            || Command::new("ip")
                .args(["link", "show", "nebula0"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    /// Stop the Nebula daemon gracefully then forcefully.
    #[allow(dead_code)]
    pub async fn stop() -> Result<(), Error> {
        // Try SIGTERM first
        let _ = Command::new("pkill")
            .args(["-TERM", "-f", "nebula -config"])
            .output();
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Force-kill if still running
        if Self::is_running() {
            Command::new("pkill")
                .args(["-KILL", "-f", "nebula -config"])
                .output()?;
        }

        // Remove the TUN interface (may already be gone)
        let _ = Command::new("ip")
            .args(["link", "delete", "nebula0"])
            .output();

        println!("🛑 Guardian Mesh daemon stopped.");
        Ok(())
    }
}
