use anyhow::{anyhow, Result};
use rand::RngCore;
use std::fs;
use std::path::Path;

const VIRTUAL_UID_PATH: &str = "/var/lib/sgx-guardian/virtual_uid";

pub fn ensure_virtual_uid() -> Result<String> {
    if let Ok(existing) = fs::read_to_string(VIRTUAL_UID_PATH) {
        let trimmed = existing.trim().to_string();
        if trimmed.len() == 36 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(trimmed);
        }
    }

    if let Some(parent) = Path::new(VIRTUAL_UID_PATH).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create virtual uid dir {}: {}", parent.display(), e))?;
    }

    let mut bytes = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut bytes);
    let uid = hex::encode(bytes);
    fs::write(VIRTUAL_UID_PATH, &uid).map_err(|e| anyhow!("write virtual uid: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(VIRTUAL_UID_PATH, fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow!("chmod virtual uid: {}", e))?;
    }
    Ok(uid)
}

pub fn virtual_device_model() -> String {
    "virtual-x86_64".to_string()
}
