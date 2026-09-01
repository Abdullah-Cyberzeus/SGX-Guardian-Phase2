use sgx_guardian_client::storage::backup::BackupManager;

const FILES: [&str; 5] = [
    "devices.json",
    "automations.json",
    "integrations.json",
    "notifications.json",
    "pending_actions.json",
];

fn write_json(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), body).unwrap();
}

#[test]
fn create_backup_creates_timestamped_directory() {
    let td = tempfile::tempdir().unwrap();
    let backup = BackupManager::create_backup(&td.path().join("data"), &td.path().join("backups"))
        .unwrap();
    assert!(backup.exists());
    assert!(backup.file_name().unwrap().to_string_lossy().starts_with("backup_"));
}

#[test]
fn create_backup_copies_single_known_json_file() {
    let td = tempfile::tempdir().unwrap();
    let data = td.path().join("data");
    write_json(&data, "devices.json", r#"{"devices":{}}"#);
    let backup = BackupManager::create_backup(&data, &td.path().join("backups")).unwrap();
    assert_eq!(std::fs::read_to_string(backup.join("devices.json")).unwrap(), r#"{"devices":{}}"#);
}

#[test]
fn create_backup_copies_all_known_files() {
    let td = tempfile::tempdir().unwrap();
    let data = td.path().join("data");
    for name in FILES {
        write_json(&data, name, "{}");
    }
    let backup = BackupManager::create_backup(&data, &td.path().join("backups")).unwrap();
    for name in FILES {
        assert!(backup.join(name).exists(), "{name}");
    }
}

#[test]
fn create_backup_ignores_unknown_files() {
    let td = tempfile::tempdir().unwrap();
    let data = td.path().join("data");
    write_json(&data, "unknown.json", "{}");
    let backup = BackupManager::create_backup(&data, &td.path().join("backups")).unwrap();
    assert!(!backup.join("unknown.json").exists());
}

#[test]
fn create_backup_succeeds_when_data_dir_is_missing() {
    let td = tempfile::tempdir().unwrap();
    let backup = BackupManager::create_backup(&td.path().join("missing"), &td.path().join("backups"))
        .unwrap();
    assert!(backup.exists());
}

#[test]
fn create_backup_preserves_file_contents_exactly() {
    let td = tempfile::tempdir().unwrap();
    let data = td.path().join("data");
    write_json(&data, "notifications.json", "{\n  \"items\": [1,2,3]\n}");
    let backup = BackupManager::create_backup(&data, &td.path().join("backups")).unwrap();
    assert_eq!(
        std::fs::read_to_string(backup.join("notifications.json")).unwrap(),
        "{\n  \"items\": [1,2,3]\n}"
    );
}

#[test]
fn restore_backup_rejects_missing_backup_directory() {
    let td = tempfile::tempdir().unwrap();
    let err = BackupManager::restore_backup(&td.path().join("missing"), &td.path().join("data"))
        .unwrap_err();
    assert!(err.contains("does not exist"));
}

#[test]
fn restore_backup_restores_single_valid_file() {
    let td = tempfile::tempdir().unwrap();
    let backup = td.path().join("backup");
    write_json(&backup, "devices.json", r#"{"devices":{"a":1}}"#);
    let data = td.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    assert_eq!(BackupManager::restore_backup(&backup, &data).unwrap(), 1);
    assert_eq!(
        std::fs::read_to_string(data.join("devices.json")).unwrap(),
        r#"{"devices":{"a":1}}"#
    );
}

#[test]
fn restore_backup_restores_all_known_valid_files() {
    let td = tempfile::tempdir().unwrap();
    let backup = td.path().join("backup");
    for name in FILES {
        write_json(&backup, name, "{}");
    }
    let data = td.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    assert_eq!(BackupManager::restore_backup(&backup, &data).unwrap(), FILES.len());
}

#[test]
fn restore_backup_skips_unknown_files() {
    let td = tempfile::tempdir().unwrap();
    let backup = td.path().join("backup");
    write_json(&backup, "unknown.json", "{}");
    let data = td.path().join("data");
    assert_eq!(BackupManager::restore_backup(&backup, &data).unwrap(), 0);
    assert!(!data.join("unknown.json").exists());
}

#[test]
fn restore_backup_skips_corrupted_json() {
    let td = tempfile::tempdir().unwrap();
    let backup = td.path().join("backup");
    write_json(&backup, "devices.json", "{bad");
    let data = td.path().join("data");
    assert_eq!(BackupManager::restore_backup(&backup, &data).unwrap(), 0);
    assert!(!data.join("devices.json").exists());
}

#[test]
fn restore_backup_treats_empty_json_file_as_valid() {
    let td = tempfile::tempdir().unwrap();
    let backup = td.path().join("backup");
    write_json(&backup, "devices.json", " \n");
    let data = td.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    assert_eq!(BackupManager::restore_backup(&backup, &data).unwrap(), 1);
    assert_eq!(std::fs::read_to_string(data.join("devices.json")).unwrap(), " \n");
}

#[test]
fn restore_backup_overwrites_existing_data_file() {
    let td = tempfile::tempdir().unwrap();
    let backup = td.path().join("backup");
    let data = td.path().join("data");
    write_json(&backup, "devices.json", r#"{"new":true}"#);
    write_json(&data, "devices.json", r#"{"old":true}"#);
    assert_eq!(BackupManager::restore_backup(&backup, &data).unwrap(), 1);
    assert_eq!(std::fs::read_to_string(data.join("devices.json")).unwrap(), r#"{"new":true}"#);
}

#[test]
fn validate_and_heal_missing_file_is_success() {
    let td = tempfile::tempdir().unwrap();
    assert!(BackupManager::validate_and_heal(&td.path().join("missing.json")));
}

#[test]
fn validate_and_heal_valid_object_is_success() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("devices.json");
    std::fs::write(&path, r#"{"ok":true}"#).unwrap();
    assert!(BackupManager::validate_and_heal(&path));
}

#[test]
fn validate_and_heal_valid_array_is_success() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("devices.json");
    std::fs::write(&path, "[1,2,3]").unwrap();
    assert!(BackupManager::validate_and_heal(&path));
}

#[test]
fn validate_and_heal_empty_file_is_success() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("devices.json");
    std::fs::write(&path, " \n\t").unwrap();
    assert!(BackupManager::validate_and_heal(&path));
}

#[test]
fn validate_and_heal_corrupt_without_lock_fails() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("devices.json");
    std::fs::write(&path, "{bad").unwrap();
    assert!(!BackupManager::validate_and_heal(&path));
}

#[test]
fn validate_and_heal_recovers_from_valid_lock_snapshot() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("devices.json");
    std::fs::write(&path, "{bad").unwrap();
    std::fs::write(td.path().join("devices.lock"), r#"{"healed":true}"#).unwrap();
    assert!(BackupManager::validate_and_heal(&path));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"healed":true}"#);
}

#[test]
fn validate_and_heal_does_not_recover_from_invalid_lock_snapshot() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("devices.json");
    std::fs::write(&path, "{bad").unwrap();
    std::fs::write(td.path().join("devices.lock"), "{also-bad").unwrap();
    assert!(!BackupManager::validate_and_heal(&path));
}

#[test]
fn validate_and_heal_uses_file_stem_for_lock_name() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("pending_actions.json");
    std::fs::write(&path, "{bad").unwrap();
    std::fs::write(td.path().join("pending_actions.lock"), "[]").unwrap();
    assert!(BackupManager::validate_and_heal(&path));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[]");
}
