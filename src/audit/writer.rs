//! Append-only audit log writer with hash chaining.

use serde_json::json;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use crate::audit::event::AuditEvent;
use crate::audit::hasher::AuditHashChain;

/// Handles persistent audit log writing.
pub struct AuditWriter {
    file_path: PathBuf,
    chain: AuditHashChain,
}

impl AuditWriter {
    /// Create a new audit writer.
    pub fn new(file_path: PathBuf) -> Self {
        let mut chain = AuditHashChain::new();

        if let Ok(file) = File::open(&file_path) {
            let reader = BufReader::new(file);
            if let Some(Ok(last_line)) = reader.lines().last() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&last_line) {
                    if let Some(hash) = v.get("hash").and_then(|h| h.as_str()) {
                        chain.set_last_hash(hash.to_string());
                    }
                }
            }
        }

        Self { file_path, chain }
    }

    /// Build a serialized audit record (PURE, testable, no I/O)
    pub fn build_record(&mut self, event: &AuditEvent) -> String {
        let payload = serde_json::to_string(event).expect("audit event serialization failed");

        let prev = self.chain.last_hash().to_string();
        let hash = self.chain.next_hash(&payload);

        json!({
            "previous_hash": prev,
            "hash": hash,
            "event": event
        })
        .to_string()
    }

    /// Append an audit event to disk (tamper-evident).
    pub fn append(&mut self, event: &AuditEvent) -> std::io::Result<()> {
        let record = self.build_record(event);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        file.write_all(record.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }
}
