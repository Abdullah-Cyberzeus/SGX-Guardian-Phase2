use std::io::Error;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

pub struct NebulaDaemon;

impl NebulaDaemon {
    /// Start Nebula daemon in background
    pub fn start(config_path: &str) -> Result<(), Error> {
        println!("🚀 Starting Nebula daemon...");

        Command::new("nebula")
            .arg("-config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // small delay to allow startup
        thread::sleep(Duration::from_secs(2));
        if Self::is_running() {
            println!("✅ Nebula daemon started successfully.");
            Ok(())
        } else {
            Err(Error::new(
                std::io::ErrorKind::Other,
                "Nebula daemon failed to start",
            ))
        }
    }

    /// Check if Nebula process is running
    pub fn is_running() -> bool {
        Command::new("pgrep")
            .arg("-f")
            .arg("nebula -config")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Stop Nebula daemon
    #[allow(dead_code)]
    pub fn stop() -> Result<(), Error> {
        Command::new("pkill").arg("nebula").output()?;

        println!("🛑 Nebula daemon stopped.");
        Ok(())
    }
}
