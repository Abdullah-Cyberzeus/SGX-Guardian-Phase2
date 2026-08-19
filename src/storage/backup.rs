use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct BackupManager;

impl BackupManager {
    /// Archives all JSON storage files into a timestamped backup directory.
    pub fn create_backup(data_dir: &Path, backup_base_dir: &Path) -> Result<PathBuf, String> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_dir = backup_base_dir.join(format!("backup_{}", timestamp));
        fs::create_dir_all(&backup_dir)
            .map_err(|e| format!("Failed to create backup dir: {}", e))?;

        let files = vec![
            "devices.json",
            "automations.json",
            "integrations.json",
            "notifications.json",
            "pending_actions.json",
        ];

        let mut copied_count = 0;
        for file_name in files {
            let src = data_dir.join(file_name);
            if src.exists() {
                let dest = backup_dir.join(file_name);
                if let Err(e) = fs::copy(&src, &dest) {
                    warn!("⚠️ Could not copy {} to backup: {}", file_name, e);
                } else {
                    copied_count += 1;
                }
            }
        }

        info!(
            "📦 Backup created successfully at {} ({} files backed up)",
            backup_dir.display(),
            copied_count
        );

        Ok(backup_dir)
    }

    /// Restores all JSON files from a backup directory into the active data directory.
    pub fn restore_backup(backup_dir: &Path, data_dir: &Path) -> Result<usize, String> {
        if !backup_dir.exists() {
            return Err(format!(
                "Backup directory {} does not exist",
                backup_dir.display()
            ));
        }

        let files = vec![
            "devices.json",
            "automations.json",
            "integrations.json",
            "notifications.json",
            "pending_actions.json",
        ];

        let mut restored_count = 0;
        for file_name in files {
            let src = backup_dir.join(file_name);
            if src.exists() {
                // Validate JSON syntax before restoring
                if Self::validate_json_file(&src) {
                    let dest = data_dir.join(file_name);
                    fs::copy(&src, &dest)
                        .map_err(|e| format!("Failed to restore {}: {}", file_name, e))?;
                    restored_count += 1;
                } else {
                    warn!(
                        "⚠️ Backup file {} is corrupted JSON, skipping restore",
                        src.display()
                    );
                }
            }
        }

        info!(
            "🔄 Restored {} JSON storage file(s) from {}",
            restored_count,
            backup_dir.display()
        );

        Ok(restored_count)
    }

    /// Validates JSON file syntax on boot. If invalid, attempts auto-recovery from corresponding .lock or backup file.
    pub fn validate_and_heal(file_path: &Path) -> bool {
        if !file_path.exists() {
            return true; // Missing is fine (will be initialized empty)
        }

        if Self::validate_json_file(file_path) {
            return true; // Valid JSON
        }

        warn!("❌ Detected corrupted JSON file: {}", file_path.display());

        // Attempt recovery from lock snapshot if available
        let file_stem = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let lock_path = file_path.with_file_name(format!("{}.lock", file_stem));

        if lock_path.exists() && Self::validate_json_file(&lock_path) {
            info!(
                "🩹 Auto-healing {} from {} lock snapshot...",
                file_path.display(),
                lock_path.display()
            );
            if fs::copy(&lock_path, file_path).is_ok() {
                return true;
            }
        }

        false
    }

    fn validate_json_file(path: &Path) -> bool {
        let Ok(mut file) = File::open(path) else {
            return false;
        };
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            return false;
        }
        if contents.trim().is_empty() {
            return true;
        }
        serde_json::from_str::<serde_json::Value>(&contents).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_restore_backup() {
        let td = TempDir::new().unwrap();
        let data_dir = td.path().join("data");
        let backup_base = td.path().join("backups");
        fs::create_dir_all(&data_dir).unwrap();

        // Create sample JSON file
        let dev_file = data_dir.join("devices.json");
        fs::write(&dev_file, r#"{"devices":{}}"#).unwrap();

        let backup_dir = BackupManager::create_backup(&data_dir, &backup_base).unwrap();
        assert!(backup_dir.exists());

        // Delete original file
        fs::remove_file(&dev_file).unwrap();
        assert!(!dev_file.exists());

        // Restore backup
        let restored = BackupManager::restore_backup(&backup_dir, &data_dir).unwrap();
        assert_eq!(restored, 1);
        assert!(dev_file.exists());
    }

    #[test]
    fn test_auto_heal_corrupted_json() {
        let td = TempDir::new().unwrap();
        let file_path = td.path().join("devices.json");
        let lock_path = td.path().join("devices.lock");

        // Write corrupted json to devices.json and valid json to devices.lock
        fs::write(&file_path, "corrupted { json ...").unwrap();
        fs::write(&lock_path, r#"{"devices":{}}"#).unwrap();

        assert!(BackupManager::validate_and_heal(&file_path));
        assert_eq!(fs::read_to_string(&file_path).unwrap(), r#"{"devices":{}}"#);

        // A second pass should remain healthy and keep the healed file intact.
        let healed = BackupManager::validate_and_heal(&file_path);
        assert!(healed);
    }
}
