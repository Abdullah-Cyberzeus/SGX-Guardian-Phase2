//! P4.8 — join codes. A short, human-typeable (or QR-encodable) single-use
//! code the CA hands out; redeeming a valid one satisfies P4.4 check (4) and
//! optionally auto-approves the resulting enrollment request instead of
//! waiting on manual approval.
//!
//! Only an HMAC of each code is ever persisted, not the code itself — a
//! join-code directory read off disk (a backup, a stolen SD card) reveals
//! nothing usable. The plaintext code is generated, returned to the caller
//! once, and never written down.

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum JoinCodeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("join code not found")]
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredJoinCode {
    pub id: String,
    pub code_hmac: String,
    pub circle_id: String,
    pub note: Option<String>,
    /// `Some(role)` — a valid, unexpired, unused code alone is sufficient to
    /// auto-approve at this role (P4.4/`JoinCodeAuto`-equivalent for this one
    /// code). `None` — the code only satisfies the join-code *check*; a
    /// human still approves the request (`JoinCodeThenManual`-equivalent).
    pub auto_approve_role: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub used_by_guardian_id: Option<String>,
}

impl StoredJoinCode {
    pub fn is_usable(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.used_at.is_some() {
            return false;
        }
        match chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            Ok(exp) => now <= exp.with_timezone(&chrono::Utc),
            Err(_) => false,
        }
    }
}

fn secret_path(paths: &crate::startup::GuardianPaths) -> PathBuf {
    paths.var_root.join("mesh").join("joincode_secret")
}

fn codes_dir(paths: &crate::startup::GuardianPaths) -> PathBuf {
    paths.var_root.join("mesh").join("joincodes")
}

/// Loads this Guardian's join-code HMAC secret, generating one on first use.
/// Not shared between Guardians and not derived from any other key — a
/// compromise of this secret only lets someone forge join codes for
/// themselves to check against their own store, which is already something
/// they could do by other means; it never needs to leave this device.
fn load_or_create_secret(paths: &crate::startup::GuardianPaths) -> Result<Vec<u8>, JoinCodeError> {
    let path = secret_path(paths);
    if let Ok(bytes) = fs::read(&path) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    let mut secret = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &secret)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(secret)
}

fn hmac_code(secret: &[u8], code: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(code.as_bytes());
    general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn generate_plaintext_code() -> String {
    let mut rng = rand::thread_rng();
    let mut buf = Vec::with_capacity(CODE_LEN);
    for _ in 0..CODE_LEN {
        let idx = (rng.next_u32() as usize) % CROCKFORD_ALPHABET.len();
        buf.push(CROCKFORD_ALPHABET[idx]);
    }
    String::from_utf8(buf).expect("Crockford alphabet is ASCII")
}

/// Creates a new join code for `circle_id`. Returns the stored record (safe
/// to log/list — carries only the HMAC) and the plaintext code (show it to
/// the operator once, as text and/or QR; never persist it separately).
pub fn create(
    paths: &crate::startup::GuardianPaths,
    circle_id: &str,
    ttl_minutes: i64,
    note: Option<String>,
    auto_approve_role: Option<String>,
) -> Result<(StoredJoinCode, String), JoinCodeError> {
    let secret = load_or_create_secret(paths)?;
    let code = generate_plaintext_code();
    let now = chrono::Utc::now();
    let stored = StoredJoinCode {
        id: uuid::Uuid::new_v4().to_string(),
        code_hmac: hmac_code(&secret, &code),
        circle_id: circle_id.to_string(),
        note,
        auto_approve_role,
        created_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::minutes(ttl_minutes)).to_rfc3339(),
        used_at: None,
        used_by_guardian_id: None,
    };
    let dir = codes_dir(paths);
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join(format!("{}.json", stored.id)),
        serde_json::to_vec_pretty(&stored)?,
    )?;
    Ok((stored, code))
}

pub fn list(paths: &crate::startup::GuardianPaths) -> Result<Vec<StoredJoinCode>, JoinCodeError> {
    let dir = codes_dir(paths);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(code) = serde_json::from_slice::<StoredJoinCode>(&bytes) {
                    out.push(code);
                }
            }
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
}

pub fn revoke(paths: &crate::startup::GuardianPaths, id: &str) -> Result<(), JoinCodeError> {
    let path = codes_dir(paths).join(format!("{id}.json"));
    if !path.exists() {
        return Err(JoinCodeError::NotFound);
    }
    fs::remove_file(path)?;
    Ok(())
}

/// P4.4 check (4): verifies `code` against `circle_id`'s stored codes and,
/// if valid, marks it used (single-use) by `guardian_id`. Returns the
/// matched code's `auto_approve_role` on success — `Ok(Some(None))` means a
/// valid code that still requires manual approval, `Ok(Some(Some(role)))`
/// means auto-approve at that role, `Ok(None)` means no code was offered
/// at all (not an error — plenty of valid joins have none), and `Err`
/// means a code was offered but did not check out.
pub fn redeem(
    paths: &crate::startup::GuardianPaths,
    circle_id: &str,
    code: &str,
    guardian_id: &str,
) -> Result<Option<Option<String>>, String> {
    let secret = load_or_create_secret(paths).map_err(|e| e.to_string())?;
    let target_hmac = hmac_code(&secret, code);
    let now = chrono::Utc::now();

    let dir = codes_dir(paths);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Err("no code matches".into());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else { continue };
        let Ok(mut stored) = serde_json::from_slice::<StoredJoinCode>(&bytes) else {
            continue;
        };
        if stored.circle_id != circle_id || stored.code_hmac != target_hmac {
            continue;
        }
        if !stored.is_usable(now) {
            return Err("code is expired or already used".into());
        }
        stored.used_at = Some(now.to_rfc3339());
        stored.used_by_guardian_id = Some(guardian_id.to_string());
        fs::write(&path, serde_json::to_vec_pretty(&stored).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        return Ok(Some(stored.auto_approve_role));
    }
    Err("no code matches".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::GuardianPaths;

    #[test]
    fn a_freshly_created_code_redeems_successfully_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let (_stored, code) = create(&paths, "circle-X", 10, None, Some("member".into())).unwrap();

        let first = redeem(&paths, "circle-X", &code, "edge-7").unwrap();
        assert_eq!(first, Some(Some("member".to_string())));

        let second = redeem(&paths, "circle-X", &code, "edge-8");
        assert!(second.is_err());
    }

    #[test]
    fn a_code_for_a_different_circle_does_not_redeem() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let (_stored, code) = create(&paths, "circle-X", 10, None, None).unwrap();
        assert!(redeem(&paths, "circle-Y", &code, "edge-7").is_err());
    }

    #[test]
    fn an_expired_code_does_not_redeem() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let (_stored, code) = create(&paths, "circle-X", -1, None, None).unwrap();
        assert!(redeem(&paths, "circle-X", &code, "edge-7").is_err());
    }

    #[test]
    fn the_stored_record_never_carries_the_plaintext_code() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let (stored, code) = create(&paths, "circle-X", 10, None, None).unwrap();
        let raw = fs::read_to_string(codes_dir(&paths).join(format!("{}.json", stored.id))).unwrap();
        assert!(!raw.contains(&code));
    }
}
