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
            .truncate(false)
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
            .truncate(false)
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
}
