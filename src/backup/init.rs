use crate::backup::errors::BackupError;
use crate::backup::BackupConfig;
use std::path::Path;

#[cfg(unix)]
const SECURE_DIR_MODE: u32 = 0o700;

pub fn initialize_storage_from_env() -> Result<(), BackupError> {
    initialize_storage(&BackupConfig::from_env())
}

pub fn initialize_storage(config: &BackupConfig) -> Result<(), BackupError> {
    for dir in required_dirs(config) {
        create_secure_dir(&dir)?;
    }
    Ok(())
}

fn required_dirs(config: &BackupConfig) -> Vec<std::path::PathBuf> {
    vec![
        config.base_dir.clone(),
        config.bundles_dir(),
        config.staging_dir(),
        config.restore_dir(),
        config.pre_restore_dir(),
    ]
}

fn create_secure_dir(path: &Path) -> Result<(), BackupError> {
    std::fs::create_dir_all(path).map_err(|error| {
        BackupError::Io(std::io::Error::new(
            error.kind(),
            format!("create backup directory {}: {}", path.display(), error),
        ))
    })?;
    set_secure_dir_permissions(path)
}

#[cfg(unix)]
fn set_secure_dir_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SECURE_DIR_MODE)).map_err(
        |error| {
            BackupError::Io(std::io::Error::new(
                error.kind(),
                format!(
                    "secure backup directory permissions for {}: {}",
                    path.display(),
                    error
                ),
            ))
        },
    )?;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != SECURE_DIR_MODE {
        return Err(BackupError::InvalidRequest(format!(
            "backup directory {} has insecure permissions {:o}; expected 700",
            path.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_secure_dir_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}
