use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Thread-safe and crash-safe file operations for JSON configs
pub struct SecureFileStore {
    path: PathBuf,
}

impl SecureFileStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Safely writes data to the file concurrently and atomically.
    ///
    /// 1. Acquires `flock` exclusive lock on `.lock` file
    /// 2. Executes modifier closure with the old data
    /// 3. Writes result to `.tmp` file
    /// 4. fsync the `.tmp` file
    /// 5. Rename `.tmp` to target file (atomic)
    /// 6. Releases the lock
    pub fn write_atomic<F, E>(&self, modifier: F) -> Result<(), E>
    where
        F: FnOnce(Option<Vec<u8>>) -> Result<Vec<u8>, E>,
        E: From<io::Error>,
    {
        let lock_path = self.path.with_extension("lock");

        // 1. Acquire exclusive lock on {filename}.lock
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;

        lock_file.lock_exclusive()?;

        // 2. Read current file content
        let mut old_data = None;
        if self.path.exists() {
            let mut file = File::open(&self.path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            old_data = Some(buf);
        }

        // 3. Modify in memory via closure
        let new_data = modifier(old_data)?;

        // 4. Write to {filename}.tmp
        let tmp_path = self.path.with_extension("tmp");
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;

        tmp_file.write_all(&new_data)?;

        // 5. fsync the temp file
        tmp_file.sync_all()?;

        // 6. Rename {filename}.tmp -> {filename}
        fs::rename(&tmp_path, &self.path)?;

        // 7. Release lock
        lock_file.unlock()?;

        Ok(())
    }

    /// Safely read data with shared lock
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        let lock_path = self.path.with_extension("lock");

        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;

        lock_file.lock_shared()?;

        let mut data = None;
        if self.path.exists() {
            let mut file = File::open(&self.path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            data = Some(buf);
        }

        lock_file.unlock()?;

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use tempfile::NamedTempFile;

    #[test]
    fn test_concurrent_writes() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        // Initialize file with "0"
        fs::write(&path, "0").unwrap();

        let store = Arc::new(SecureFileStore::new(&path));
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing the value in the file
        for _ in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                store_clone
                    .write_atomic(|data| {
                        let old_val_str = String::from_utf8(data.unwrap()).unwrap();
                        let old_val: i32 = old_val_str.parse().unwrap();
                        let new_val = old_val + 1;
                        Ok::<Vec<u8>, io::Error>(new_val.to_string().into_bytes())
                    })
                    .unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Final value should be 10
        let final_data = store.read().unwrap().unwrap();
        let final_str = String::from_utf8(final_data).unwrap();
        assert_eq!(final_str, "10");
    }

    #[test]
    fn new_stores_target_path_without_creating_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = SecureFileStore::new(&path);
        assert_eq!(store.path, path);
        assert!(!store.path.exists());
    }

    #[test]
    fn read_missing_file_returns_none_and_creates_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let store = SecureFileStore::new(&path);
        assert!(store.read().unwrap().is_none());
        assert!(path.with_extension("lock").exists());
    }

    #[test]
    fn write_atomic_receives_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = SecureFileStore::new(&path);
        store
            .write_atomic(|old| {
                assert!(old.is_none());
                Ok::<_, io::Error>(b"created".to_vec())
            })
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"created");
    }

    #[test]
    fn write_atomic_receives_previous_bytes_for_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, b"old").unwrap();
        let store = SecureFileStore::new(&path);
        store
            .write_atomic(|old| {
                assert_eq!(old.unwrap(), b"old");
                Ok::<_, io::Error>(b"new".to_vec())
            })
            .unwrap();
        assert_eq!(store.read().unwrap().unwrap(), b"new");
    }

    #[test]
    fn write_atomic_overwrites_with_empty_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old").unwrap();
        SecureFileStore::new(&path)
            .write_atomic(|_| Ok::<_, io::Error>(Vec::new()))
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn write_atomic_preserves_binary_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        let payload = vec![0, 1, 2, 3, 255, 10, 0];
        SecureFileStore::new(&path)
            .write_atomic(|_| Ok::<_, io::Error>(payload.clone()))
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), payload);
    }

    #[derive(Debug)]
    enum TestError {
        Forced,
    }

    impl From<io::Error> for TestError {
        fn from(_: io::Error) -> Self {
            Self::Forced
        }
    }

    #[test]
    fn write_atomic_modifier_error_leaves_existing_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, b"stable").unwrap();
        let err = SecureFileStore::new(&path)
            .write_atomic(|old| {
                assert_eq!(old.unwrap(), b"stable");
                Err::<Vec<u8>, TestError>(TestError::Forced)
            })
            .unwrap_err();
        assert!(matches!(err, TestError::Forced));
        assert_eq!(fs::read(&path).unwrap(), b"stable");
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn write_atomic_missing_parent_returns_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("state.json");
        let err = SecureFileStore::new(&path)
            .write_atomic(|_| Ok::<_, io::Error>(b"data".to_vec()))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn read_missing_parent_returns_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("state.json");
        let err = SecureFileStore::new(&path).read().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn read_empty_file_returns_some_empty_vec() {
        let file = NamedTempFile::new().unwrap();
        let store = SecureFileStore::new(file.path());
        assert_eq!(store.read().unwrap(), Some(Vec::new()));
    }

    #[test]
    fn read_existing_binary_file_returns_exact_bytes() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), [0, 9, 8, 7, 255]).unwrap();
        let store = SecureFileStore::new(file.path());
        assert_eq!(store.read().unwrap().unwrap(), vec![0, 9, 8, 7, 255]);
    }

    #[test]
    fn path_with_existing_extension_uses_replaced_lock_and_tmp_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        SecureFileStore::new(&path)
            .write_atomic(|_| Ok::<_, io::Error>(b"{}".to_vec()))
            .unwrap();
        assert!(dir.path().join("settings.lock").exists());
        assert!(!dir.path().join("settings.tmp").exists());
        assert_eq!(fs::read(&path).unwrap(), b"{}");
    }

    #[test]
    fn path_without_extension_gets_lock_and_tmp_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings");
        SecureFileStore::new(&path)
            .write_atomic(|_| Ok::<_, io::Error>(b"plain".to_vec()))
            .unwrap();
        assert!(dir.path().join("settings.lock").exists());
        assert!(!dir.path().join("settings.tmp").exists());
    }

    #[test]
    fn multiple_store_instances_share_same_target_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.txt");
        let first = SecureFileStore::new(&path);
        let second = SecureFileStore::new(&path);
        first
            .write_atomic(|_| Ok::<_, io::Error>(b"first".to_vec()))
            .unwrap();
        second
            .write_atomic(|old| {
                let mut bytes = old.unwrap();
                bytes.extend_from_slice(b"+second");
                Ok::<_, io::Error>(bytes)
            })
            .unwrap();
        assert_eq!(first.read().unwrap().unwrap(), b"first+second");
    }

    #[test]
    fn concurrent_read_during_exclusive_write_waits_for_final_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.txt");
        fs::write(&path, b"0").unwrap();
        let store = Arc::new(SecureFileStore::new(&path));
        let writer = Arc::clone(&store);
        let reader = Arc::clone(&store);

        let handle = thread::spawn(move || {
            writer
                .write_atomic(|_| {
                    thread::sleep(std::time::Duration::from_millis(50));
                    Ok::<_, io::Error>(b"1".to_vec())
                })
                .unwrap();
        });
        let data = reader.read().unwrap().unwrap();
        handle.join().unwrap();
        assert!(data == b"0" || data == b"1");
        assert_eq!(store.read().unwrap().unwrap(), b"1");
    }

    #[test]
    fn many_concurrent_appends_are_serialized_without_lost_updates() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), b"").unwrap();
        let store = Arc::new(SecureFileStore::new(file.path()));
        let mut handles = Vec::new();

        for index in 0..12 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store
                    .write_atomic(|old| {
                        let mut bytes = old.unwrap_or_default();
                        bytes.extend_from_slice(format!("{index},").as_bytes());
                        Ok::<_, io::Error>(bytes)
                    })
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let text = String::from_utf8(store.read().unwrap().unwrap()).unwrap();
        for index in 0..12 {
            assert!(text.contains(&format!("{index},")));
        }
    }
}
