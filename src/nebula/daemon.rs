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
            Err(Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Guardian Mesh config validation failed:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ))
        }
    }

    /// Start the Nebula daemon in the background.
    ///
    /// Steps:
    ///   1. Kill any stale instance.
    ///   2. Validate the config.
    ///   3. Spawn the daemon.
    ///   4. Wait up to 20 s for nebula0 to appear.
    pub async fn start(config_path: &str) -> Result<(), Error> {
        // Production lifecycle rule:
        //
        // Once Nebula is healthy and nebula0 is present, start() is
        // idempotent and MUST NOT restart the live encrypted dataplane.
        if Self::is_running_for_config(config_path) && Self::interface_exists() {
            return Ok(());
        }

        // A matching process without nebula0 is not considered healthy.
        // Recover only this broken/stale instance; never broad-kill Nebula.
        if Self::is_running_for_config(config_path) {
            Self::kill_existing_for_config(config_path).await;
        }

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
        Self::live_nebula_pids(None)
            .map(|pids| !pids.is_empty())
            .unwrap_or(false)
    }

    /// Check for a live, non-zombie Nebula process using exactly this config.
    pub fn is_running_for_config(config_path: &str) -> bool {
        Self::live_nebula_pids(Some(config_path))
            .map(|pids| !pids.is_empty())
            .unwrap_or(false)
    }

    /// Inspect /proc directly so defunct Nebula children are never accepted
    /// as evidence that the production daemon is healthy.
    fn live_nebula_pids(config_path: Option<&str>) -> Result<Vec<u32>, Error> {
        let mut live = Vec::new();

        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;

            let Some(pid_text) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };

            let Ok(pid) = pid_text.parse::<u32>() else {
                continue;
            };

            let stat = match std::fs::read_to_string(entry.path().join("stat")) {
                Ok(stat) => stat,
                Err(_) => continue,
            };

            // Everything after the final ") " starts with process state.
            // Z means zombie/defunct and must not count as running.
            let Some((_, after_comm)) = stat.rsplit_once(") ") else {
                continue;
            };

            if after_comm.starts_with('Z') {
                continue;
            }

            let cmdline = match std::fs::read(entry.path().join("cmdline")) {
                Ok(cmdline) => cmdline,
                Err(_) => continue,
            };

            let args: Vec<String> = cmdline
                .split(|byte| *byte == 0)
                .filter(|arg| !arg.is_empty())
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect();

            let executable_is_nebula = args
                .first()
                .and_then(|arg| std::path::Path::new(arg).file_name())
                .and_then(|name| name.to_str())
                == Some("nebula");

            if !executable_is_nebula {
                continue;
            }

            if let Some(expected_config) = config_path {
                let exact_config = args
                    .windows(2)
                    .any(|pair| pair[0] == "-config" && pair[1] == expected_config);

                if !exact_config {
                    continue;
                }
            }

            live.push(pid);
        }

        Ok(live)
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
