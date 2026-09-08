use sgx_guardian_client::key_manager::KeyManager;
use std::path::PathBuf;
use std::sync::Mutex;

static CWD_LOCK: Mutex<()> = Mutex::new(());

struct CwdGuard {
    previous: PathBuf,
}

impl CwdGuard {
    fn enter(path: &std::path::Path) -> Self {
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self { previous }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.previous).unwrap();
    }
}

fn isolated_key_path(
    name: &str,
) -> (
    std::sync::MutexGuard<'static, ()>,
    tempfile::TempDir,
    CwdGuard,
    String,
) {
    let lock = CWD_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let cwd = CwdGuard::enter(temp.path());
    let key_path = temp.path().join(name).to_string_lossy().to_string();
    (lock, temp, cwd, key_path)
}

#[test]
fn load_or_generate_creates_missing_key_file() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert!(PathBuf::from(&key_path).exists());
    assert_eq!(km.key_path(), key_path);
}

#[test]
fn load_or_generate_creates_nested_parent_directories() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("nested/keys/device.key");
    KeyManager::load_or_generate(&key_path).unwrap();
    assert!(PathBuf::from(&key_path).exists());
}

#[test]
fn load_or_generate_exports_public_key_in_isolated_cwd() {
    let (_lock, temp, _cwd, key_path) = isolated_key_path("device.key");
    KeyManager::load_or_generate(&key_path).unwrap();
    assert!(temp.path().join("sgx-agent/device_public.der").exists());
}

#[test]
fn reloading_existing_key_preserves_public_key() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let first = KeyManager::load_or_generate(&key_path).unwrap();
    let second = KeyManager::load_or_generate(&key_path).unwrap();
    assert_eq!(first.pubkey_der().unwrap(), second.pubkey_der().unwrap());
}

#[test]
fn sign_returns_non_empty_signature() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert!(!km.sign(b"message").unwrap().is_empty());
}

#[test]
fn verify_signature_accepts_signature_from_same_key() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let data = b"guardian message";
    let sig = km.sign(data).unwrap();
    KeyManager::verify_signature(data, &sig, &km.pubkey_der().unwrap()).unwrap();
}

#[test]
fn verify_signature_rejects_tampered_data() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let sig = km.sign(b"original").unwrap();
    assert!(KeyManager::verify_signature(b"changed", &sig, &km.pubkey_der().unwrap()).is_err());
}

#[test]
fn verify_signature_rejects_tampered_signature() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let mut sig = km.sign(b"message").unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert!(KeyManager::verify_signature(b"message", &sig, &km.pubkey_der().unwrap()).is_err());
}

#[test]
fn verify_signature_rejects_invalid_public_key() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let sig = km.sign(b"message").unwrap();
    assert!(KeyManager::verify_signature(b"message", &sig, b"not-a-public-key").is_err());
}

#[test]
fn empty_message_can_be_signed_and_verified() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let sig = km.sign(b"").unwrap();
    KeyManager::verify_signature(b"", &sig, &km.pubkey_der().unwrap()).unwrap();
}

#[test]
fn binary_message_can_be_signed_and_verified() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let data = [0, 1, 2, 3, 255, 0, 42];
    let sig = km.sign(&data).unwrap();
    KeyManager::verify_signature(&data, &sig, &km.pubkey_der().unwrap()).unwrap();
}

#[test]
fn software_backend_names_are_stable() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert_eq!(km.backend_name(), "Software");
    assert_eq!(km.backend_display_name(), "software");
}

#[test]
fn software_dkp_version_is_one() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert_eq!(km.dkp_version(), 1);
}

#[test]
fn refresh_for_active_dkp_is_none_for_software_backend() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert!(km.refresh_for_active_dkp().unwrap().is_none());
}

#[test]
fn pubkey_der_is_raw_uncompressed_p256_point() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    let pubkey = km.pubkey_der().unwrap();
    assert_eq!(pubkey.len(), 65);
    assert_eq!(pubkey[0], 0x04);
}

#[test]
fn runtime_public_key_export_matches_pubkey_for_software_backend() {
    let (_lock, _temp, _cwd, key_path) = isolated_key_path("device.key");
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert_eq!(
        km.runtime_public_key_export().unwrap(),
        km.pubkey_der().unwrap()
    );
}

#[test]
fn corrupt_existing_key_is_quarantined_and_regenerated() {
    let (_lock, temp, _cwd, key_path) = isolated_key_path("device.key");
    std::fs::write(&key_path, b"bad-key").unwrap();
    let km = KeyManager::load_or_generate(&key_path).unwrap();
    assert_eq!(km.pubkey_der().unwrap().len(), 65);
    let quarantined = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt."));
    assert!(quarantined);
}
