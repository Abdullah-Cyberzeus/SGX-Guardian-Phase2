use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::audit::hasher::AuditHashChain;

pub struct AuditVerifier;

impl AuditVerifier {
    pub fn verify(path: &str) -> Result<(), String> {
        let file = File::open(path).map_err(|e| format!("Failed to open audit log: {}", e))?;

        let reader = BufReader::new(file);
        let mut chain = AuditHashChain::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| e.to_string())?;

            let parsed: serde_json::Value = serde_json::from_str(&line)
                .map_err(|_| format!("Invalid JSON at line {}", line_no + 1))?;

            let event = parsed.get("event").ok_or("Missing event field")?;

            let stored_hash = parsed
                .get("hash")
                .and_then(|h| h.as_str())
                .ok_or("Missing hash field")?;

            let payload = serde_json::to_string(event).map_err(|_| "Failed to serialize event")?;

            let computed = chain.next_hash(&payload);

            if computed != stored_hash {
                return Err(format!("AUDIT LOG TAMPER DETECTED at line {}", line_no + 1));
            }
        }

        Ok(())
    }
}
