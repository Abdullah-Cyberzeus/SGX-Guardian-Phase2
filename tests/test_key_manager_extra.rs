use sgx_guardian_client::key_manager::KeyManager;
use std::fs;
use std::path::PathBuf;

/// Helper: create a temporary test file path
fn make_temp_key_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("km_test_{}_{}", name, std::process::id()));
    p
}

#[test]
fn test_load_or_generate_fails_with_corrupted_key() {
    // Create corrupted PKCS#8 file
    let path = make_temp_key_path("corrupt");
    fs::write(&path, b"this_is_not_a_valid_pkcs8").unwrap();

    // Should fail to load
    let result = KeyManager::load_or_generate(path.to_str().unwrap());
    assert!(result.is_err(), "Corrupted key file should cause failure");

    let _ = fs::remove_file(path);
}

#[test]
fn test_load_or_generate_fails_with_invalid_path() {
    // INVALID PATH: contains null-byte → always fails on ALL OS
    let bad_path = "invalid\0key";

    let result = KeyManager::load_or_generate(bad_path);

    assert!(
        result.is_err(),
        "load_or_generate must fail on invalid directory paths"
    );
}
