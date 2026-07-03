// tests/key_manager_extended_test.rs
// Integration tests for src/key_manager.rs uncovered paths (like corrupt key quarantine)

use sgx_guardian_client::key_manager::KeyManager;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_key_manager_quarantines_corrupt_file_and_regenerates() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    // Write invalid/corrupt data to simulate a bad key
    fs::write(&path, b"not-a-valid-pkcs8-key").unwrap();

    // Should detect corruption, quarantine, and generate a new key rather than fail
    let km = KeyManager::load_or_generate(&path).expect("Failed to handle corrupt key");
    assert_eq!(km.backend_name(), "Software");

    // The key should now be a valid size (newly generated pkcs8 is typically > 100 bytes)
    let new_content = fs::read(&path).unwrap();
    assert!(new_content.len() > 50, "New key should be valid");

    // We can also verify that a quarantine file was created alongside
    let parent = tmp.path().parent().unwrap();
    let file_name = tmp.path().file_name().unwrap().to_str().unwrap();
    
    let mut found_quarantine = false;
    for entry in fs::read_dir(parent).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.starts_with(file_name) && name.contains(".corrupt.") {
            found_quarantine = true;
            let corrupt_content = fs::read(entry.path()).unwrap();
            assert_eq!(corrupt_content, b"not-a-valid-pkcs8-key");
            break; // found it
        }
    }
    assert!(found_quarantine, "Quarantine file was not created");
}

#[test]
fn test_key_manager_backend_name_software() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let km = KeyManager::load_or_generate(&path).unwrap();
    assert_eq!(km.backend_name(), "Software");
}

#[test]
fn test_key_manager_key_path() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let km = KeyManager::load_or_generate(&path).unwrap();
    assert_eq!(km.key_path(), path);
}
