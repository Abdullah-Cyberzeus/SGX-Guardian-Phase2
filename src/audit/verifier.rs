use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::audit::event::AuditEvent;
use crate::audit::hasher::AuditHashChain;

pub struct AuditVerifier;

impl AuditVerifier {
    /// Segment-aware verifier (FIX #8).
    ///
    /// The append-only log can contain multiple "segments" stitched together
    /// across daemon restarts, log rotations, or manual log moves. Each segment's
    /// first entry has a `previous_hash` that points to the last hash of the
    /// *previous* segment (or "GENESIS" for the very first segment).
    ///
    /// The verifier walks the file, and when it sees a `previous_hash` that
    /// doesn't match the running chain, it ANCHORS the chain to that value
    /// (treating it as a legitimate segment boundary) instead of failing.
    /// Within a single segment, any computed-vs-stored mismatch IS a tamper.
    ///
    /// Returns Ok((total_lines, segment_count)) on success.
    pub fn verify(path: &str) -> Result<(usize, usize), String> {
        let file = File::open(path).map_err(|e| format!("Failed to open audit log: {}", e))?;
        let reader = BufReader::new(file);
        let mut chain = AuditHashChain::new();

        let mut line_count = 0usize;
        let mut segment_count = 0usize;
        let mut current_segment_start: Option<usize> = None;

        for (idx, line) in reader.lines().enumerate() {
            let line_no = idx + 1;
            let line = line.map_err(|e| e.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            line_count += 1;

            let parsed: serde_json::Value = serde_json::from_str(&line)
                .map_err(|_| format!("Invalid JSON at line {}", line_no))?;

            let event = parsed.get("event").ok_or("Missing event field")?;
            let stored_prev = parsed
                .get("previous_hash")
                .and_then(|h| h.as_str())
                .unwrap_or("GENESIS");
            let stored_hash = parsed
                .get("hash")
                .and_then(|h| h.as_str())
                .ok_or("Missing hash field")?;
            let canonical_event: AuditEvent =
                serde_json::from_value(event.clone()).map_err(|_| "Failed to parse event")?;
            let payload =
                serde_json::to_string(&canonical_event).map_err(|_| "Failed to serialize event")?;

            // Detect segment boundary: very first line OR stored_prev != chain.last_hash().
            // On boundary, ANCHOR the chain to stored_prev and start a new segment.
            // Inside a segment, any mismatch is a tamper.
            let chain_state_matches = chain.last_hash() == stored_prev;
            let is_first_line = current_segment_start.is_none();

            if is_first_line || !chain_state_matches {
                chain.set_last_hash(stored_prev.to_string());
                segment_count += 1;
                current_segment_start = Some(line_no);
            }

            let computed = chain.next_hash(&payload);
            if computed != stored_hash {
                let seg_start = current_segment_start.unwrap_or(line_no);
                return Err(format!(
                    "AUDIT LOG TAMPER DETECTED at line {} (within segment starting at line {})",
                    line_no, seg_start
                ));
            }
        }

        Ok((line_count, segment_count))
    }
}
