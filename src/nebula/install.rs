use std::process::Command;

pub struct NebulaInstall;

impl NebulaInstall {
pub fn check_binary() -> Result<(), String> {
    let output = Command::new("nebula")
        .arg("--version")
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        Err("Nebula binary not found or not executable".into())
    }
}
    pub fn check_version() -> Result<String, String> {
        let output = Command::new("nebula")
            .arg("--version")
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout);
            Ok(version.to_string())
        } else {
            Err("Failed to get Nebula version".into())
        }
    }

    pub fn test_daemon_start() -> Result<(), String> {
        let output = Command::new("nebula")
            .arg("--help")
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            Ok(())
        } else {
            Err("Nebula daemon failed to respond".into())
        }
    }
}
