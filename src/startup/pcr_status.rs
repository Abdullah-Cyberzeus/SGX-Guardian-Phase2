//! Platform-integrity classification and the PCR composite signing input.
//!
//! Both were inline inside `main()`'s PCR block, so the DEGRADED/FAIL split —
//! the decision that determines whether peers will accept this node's
//! attestation — had no direct test.

use crate::secure_element::pcr::{
    canonical_static_yaml_measurement, PcrEngine, PcrMeasurementError,
};
use crate::secure_element::pcr_config::{self, PcrMeasurementSource};

/// Result of the startup platform integrity measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// Every configured source measured cleanly.
    Pass,
    /// At least one non-critical source failed; the node still attests.
    Degraded,
    /// A source marked `critical` failed; peers will reject the attestation.
    Fail,
}

impl IntegrityStatus {
    /// The wire/JSON form persisted in the PCR snapshot.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Degraded => "DEGRADED",
            Self::Fail => "FAIL",
        }
    }
}

impl std::fmt::Display for IntegrityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies a measurement run.
///
/// A failure counts as critical when *any* configured source at that PCR
/// index is marked critical — the index, not the individual source, is what
/// the baseline comparison trusts.
pub fn integrity_status(
    errors: &[PcrMeasurementError],
    sources: &[PcrMeasurementSource],
) -> IntegrityStatus {
    if errors.is_empty() {
        return IntegrityStatus::Pass;
    }
    let has_critical_failure = errors.iter().any(|error| {
        sources
            .iter()
            .any(|source| source.pcr_index == error.pcr_index && source.critical)
    });
    if has_critical_failure {
        IntegrityStatus::Fail
    } else {
        IntegrityStatus::Degraded
    }
}

/// The exact bytes the DKP signs over a PCR snapshot:
/// `composite_digest_bytes || nonce_bytes || timestamp_bytes`.
///
/// The two hex inputs are decoded to binary first. A malformed digest or
/// nonce degrades to zero bytes of the right length rather than shortening the
/// input, so a verifier never accepts a truncated preimage as a match.
pub fn composite_sign_input(composite_digest_hex: &str, nonce_hex: &str, measured_at: &str) -> Vec<u8> {
    let composite = hex::decode(composite_digest_hex).unwrap_or_else(|_| vec![0u8; 32]);
    let nonce = hex::decode(nonce_hex).unwrap_or_else(|_| vec![0u8; 16]);
    let timestamp = measured_at.as_bytes();

    let mut input = Vec::with_capacity(composite.len() + nonce.len() + timestamp.len());
    input.extend_from_slice(&composite);
    input.extend_from_slice(&nonce);
    input.extend_from_slice(timestamp);
    input
}

/// SHA-256 over [`composite_sign_input`] — what is handed to `KeyManager::sign`.
pub fn composite_sign_hash(
    composite_digest_hex: &str,
    nonce_hex: &str,
    measured_at: &str,
) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(composite_sign_input(
        composite_digest_hex,
        nonce_hex,
        measured_at,
    ))
    .to_vec()
}

/// Marker file that only exists on a real board, used to pick between the
/// hardware and software measurement source sets.
pub const HARDWARE_MARKER: &str = "/proc/device-tree/model";

/// Whether this process is running on board hardware.
pub fn running_on_hardware() -> bool {
    std::path::Path::new(HARDWARE_MARKER).exists()
}

/// The measurement sources to use for `node_id` on this platform.
pub fn measurement_sources(node_id: &str, is_hardware: bool) -> Vec<PcrMeasurementSource> {
    if is_hardware {
        pcr_config::default_measurement_sources(node_id)
    } else {
        pcr_config::software_measurement_sources()
    }
}

/// One line of operator-facing output per measured source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementLine {
    pub pcr_index: usize,
    pub label: String,
    /// The truncated hash prefix on success, `None` when the source failed.
    pub hash_prefix: Option<String>,
    pub error: Option<String>,
}

/// Outcome of extending every configured source into `engine`.
#[derive(Debug, Default)]
pub struct MeasurementRun {
    pub lines: Vec<MeasurementLine>,
    pub errors: Vec<PcrMeasurementError>,
}

/// Extends `engine` with every configured source.
///
/// A source that cannot be read is still extended — with an `ERROR:<reason>`
/// marker — so the PCR chain stays the same length regardless of which sources
/// were readable. A run that silently skipped a failed source would produce a
/// composite digest that collides with a shorter, differently-configured node.
pub fn measure_sources(engine: &mut PcrEngine, sources: &[PcrMeasurementSource]) -> MeasurementRun {
    let mut run = MeasurementRun::default();

    for source in sources {
        if source.source_type == "multi_file" {
            // extend_from_files already records one error per unreadable file.
            let files: Vec<String> = source
                .source
                .split(',')
                .map(|file| file.trim().to_string())
                .collect();
            run.errors
                .extend(engine.extend_from_files(source.pcr_index, &files));
            continue;
        }

        let result = match source.source_type.as_str() {
            "boot_chain" => {
                let measurement = crate::secure_element::secure_boot::BootChainStatus::check()
                    .to_measurement_string();
                engine.extend_from_string(source.pcr_index, &measurement)
            }
            "static_yaml" => {
                let canonical = canonical_static_yaml_measurement(&source.source);
                engine.extend_from_string(source.pcr_index, &canonical)
            }
            "file" => engine.extend_from_file(source.pcr_index, &source.source),
            "string" => engine.extend_from_string(source.pcr_index, &source.source),
            other => Err(format!("Unknown type: {other}")),
        };

        match result {
            Ok(hash) => run.lines.push(MeasurementLine {
                pcr_index: source.pcr_index,
                label: source.label.clone(),
                hash_prefix: Some(hash.chars().take(12).collect()),
                error: None,
            }),
            Err(error) => {
                let _ = engine.extend_from_string(source.pcr_index, &format!("ERROR:{error}"));
                run.errors.push(PcrMeasurementError {
                    pcr_index: source.pcr_index,
                    source: source.source.clone(),
                    error: error.clone(),
                });
                run.lines.push(MeasurementLine {
                    pcr_index: source.pcr_index,
                    label: source.label.clone(),
                    hash_prefix: None,
                    error: Some(error),
                });
            }
        }
    }

    run
}

/// Prints [`measure_sources`] output in the operator-facing startup format.
pub fn print_measurement_lines(lines: &[MeasurementLine]) {
    for line in lines {
        match (&line.hash_prefix, &line.error) {
            (Some(hash), _) => println!("    PCR{}: {} → {}...", line.pcr_index, line.label, hash),
            (None, Some(error)) => {
                println!("    PCR{}: {} → ⚠️ {}", line.pcr_index, line.label, error)
            }
            (None, None) => println!("    PCR{}: {}", line.pcr_index, line.label),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(pcr_index: usize, critical: bool) -> PcrMeasurementSource {
        PcrMeasurementSource {
            pcr_index,
            label: format!("source-{pcr_index}"),
            source_type: "string".to_string(),
            source: "value".to_string(),
            critical,
        }
    }

    fn error(pcr_index: usize) -> PcrMeasurementError {
        PcrMeasurementError {
            pcr_index,
            source: "value".to_string(),
            error: "unreadable".to_string(),
        }
    }

    #[test]
    fn a_clean_run_passes() {
        let sources = vec![source(0, true), source(1, false)];
        assert_eq!(integrity_status(&[], &sources), IntegrityStatus::Pass);
        assert_eq!(
            integrity_status(&[], &[]),
            IntegrityStatus::Pass,
            "no sources and no errors is still a pass"
        );
    }

    #[test]
    fn a_non_critical_failure_degrades_without_failing() {
        let sources = vec![source(0, true), source(1, false)];
        assert_eq!(
            integrity_status(&[error(1)], &sources),
            IntegrityStatus::Degraded
        );
    }

    #[test]
    fn a_critical_failure_fails_the_whole_run() {
        let sources = vec![source(0, true), source(1, false)];
        assert_eq!(
            integrity_status(&[error(1), error(0)], &sources),
            IntegrityStatus::Fail,
            "one critical failure outweighs any number of degraded ones"
        );
    }

    #[test]
    fn an_error_at_an_unconfigured_index_only_degrades() {
        let sources = vec![source(0, true)];
        assert_eq!(
            integrity_status(&[error(7)], &sources),
            IntegrityStatus::Degraded
        );
        assert_eq!(
            integrity_status(&[error(0)], &[]),
            IntegrityStatus::Degraded,
            "with no source configuration nothing can be proven critical"
        );
    }

    #[test]
    fn any_critical_source_at_an_index_makes_that_index_critical() {
        let sources = vec![source(3, false), source(3, true)];
        assert_eq!(
            integrity_status(&[error(3)], &sources),
            IntegrityStatus::Fail
        );
    }

    #[test]
    fn status_strings_match_the_persisted_snapshot_values() {
        assert_eq!(IntegrityStatus::Pass.as_str(), "PASS");
        assert_eq!(IntegrityStatus::Degraded.as_str(), "DEGRADED");
        assert_eq!(IntegrityStatus::Fail.as_str(), "FAIL");
        assert_eq!(IntegrityStatus::Fail.to_string(), "FAIL");
    }

    #[test]
    fn sign_input_is_the_binary_concatenation_of_digest_nonce_and_timestamp() {
        let composite = "ab".repeat(32);
        let nonce = "cd".repeat(16);
        let measured_at = "2026-01-01T00:00:00Z";

        let input = composite_sign_input(&composite, &nonce, measured_at);

        assert_eq!(input.len(), 32 + 16 + measured_at.len());
        assert_eq!(&input[..32], &[0xabu8; 32]);
        assert_eq!(&input[32..48], &[0xcdu8; 16]);
        assert_eq!(&input[48..], measured_at.as_bytes());
    }

    #[test]
    fn malformed_hex_degrades_to_zero_padding_of_the_expected_length() {
        let measured_at = "2026-01-01T00:00:00Z";

        let input = composite_sign_input("not-hex", "also-not-hex", measured_at);

        assert_eq!(input.len(), 32 + 16 + measured_at.len());
        assert_eq!(&input[..48], vec![0u8; 48].as_slice());
    }

    #[test]
    fn sign_hash_is_sha256_over_the_sign_input_and_is_input_sensitive() {
        use sha2::Digest;
        let composite = "ab".repeat(32);
        let nonce = "cd".repeat(16);

        let hash = composite_sign_hash(&composite, &nonce, "2026-01-01T00:00:00Z");

        assert_eq!(hash.len(), 32);
        assert_eq!(
            hash,
            sha2::Sha256::digest(composite_sign_input(
                &composite,
                &nonce,
                "2026-01-01T00:00:00Z"
            ))
            .to_vec()
        );
        assert_ne!(
            hash,
            composite_sign_hash(&composite, &nonce, "2026-01-01T00:00:01Z"),
            "the timestamp is bound into the signature"
        );
        assert_ne!(
            hash,
            composite_sign_hash(&composite, &"ce".repeat(16), "2026-01-01T00:00:00Z"),
            "the nonce is bound into the signature"
        );
    }

    #[test]
    fn measurement_sources_differ_between_hardware_and_software() {
        let hardware = measurement_sources("nodeA", true);
        let software = measurement_sources("nodeA", false);

        assert!(!hardware.is_empty());
        assert!(!software.is_empty());
        assert_ne!(
            hardware.len() == software.len()
                && hardware
                    .iter()
                    .zip(&software)
                    .all(|(a, b)| a.source == b.source),
            true,
            "the two source sets must not be identical"
        );
        // `running_on_hardware` reads a path that does not exist off-board.
        assert_eq!(
            running_on_hardware(),
            std::path::Path::new(HARDWARE_MARKER).exists()
        );
    }

    #[test]
    fn string_sources_are_measured_and_reported() {
        let mut engine = PcrEngine::new();
        let sources = vec![PcrMeasurementSource {
            pcr_index: 0,
            label: "firmware".to_string(),
            source_type: "string".to_string(),
            source: "v1.2.3".to_string(),
            critical: true,
        }];

        let run = measure_sources(&mut engine, &sources);

        assert!(run.errors.is_empty());
        assert_eq!(run.lines.len(), 1);
        let line = &run.lines[0];
        assert_eq!(line.pcr_index, 0);
        assert_eq!(line.label, "firmware");
        assert_eq!(
            line.hash_prefix.as_ref().map(String::len),
            Some(12),
            "the operator line shows a 12-character hash prefix"
        );
        assert!(line.error.is_none());
    }

    #[test]
    fn a_readable_file_source_is_measured() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let file = temp.path().join("kernel.img");
        std::fs::write(&file, b"kernel bytes").expect("write measured file");
        let mut engine = PcrEngine::new();
        let sources = vec![PcrMeasurementSource {
            pcr_index: 1,
            label: "kernel".to_string(),
            source_type: "file".to_string(),
            source: file.to_string_lossy().into_owned(),
            critical: true,
        }];

        let run = measure_sources(&mut engine, &sources);

        assert!(run.errors.is_empty(), "{:?}", run.errors);
        assert!(run.lines[0].hash_prefix.is_some());
    }

    #[test]
    fn an_unreadable_source_is_recorded_and_still_extended() {
        let mut engine = PcrEngine::new();
        let sources = vec![PcrMeasurementSource {
            pcr_index: 2,
            label: "missing".to_string(),
            source_type: "file".to_string(),
            source: "/nonexistent/measured/file".to_string(),
            critical: false,
        }];

        let run = measure_sources(&mut engine, &sources);

        assert_eq!(run.errors.len(), 1);
        assert_eq!(run.errors[0].pcr_index, 2);
        assert_eq!(run.errors[0].source, "/nonexistent/measured/file");
        assert!(run.lines[0].hash_prefix.is_none());
        assert!(run.lines[0].error.is_some());

        // The failure was still extended into the chain, so PCR2 is not the
        // untouched zero value a skipped source would have left behind.
        let untouched = PcrEngine::new();
        let baseline = untouched.snapshot();
        assert_ne!(engine.snapshot().pcr_values[2], baseline.pcr_values[2]);
    }

    #[test]
    fn an_unknown_source_type_is_reported_as_an_error() {
        let mut engine = PcrEngine::new();
        let sources = vec![PcrMeasurementSource {
            pcr_index: 3,
            label: "mystery".to_string(),
            source_type: "carrier-pigeon".to_string(),
            source: "somewhere".to_string(),
            critical: true,
        }];

        let run = measure_sources(&mut engine, &sources);

        assert_eq!(run.errors.len(), 1);
        assert!(
            run.errors[0].error.contains("Unknown type: carrier-pigeon"),
            "{}",
            run.errors[0].error
        );
        assert_eq!(
            integrity_status(&run.errors, &sources),
            IntegrityStatus::Fail
        );
    }

    #[test]
    fn multi_file_sources_report_one_error_per_unreadable_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let present = temp.path().join("present.bin");
        std::fs::write(&present, b"data").expect("write file");
        let mut engine = PcrEngine::new();
        let sources = vec![PcrMeasurementSource {
            pcr_index: 4,
            label: "bundle".to_string(),
            source_type: "multi_file".to_string(),
            source: format!("{}, /nonexistent/a, /nonexistent/b", present.display()),
            critical: false,
        }];

        let run = measure_sources(&mut engine, &sources);

        assert_eq!(run.errors.len(), 2, "{:?}", run.errors);
        assert!(run.errors.iter().all(|error| error.pcr_index == 4));
        assert!(
            run.lines.is_empty(),
            "multi-file sources report through errors, not per-source lines"
        );
    }

    #[test]
    fn static_yaml_sources_are_canonicalised_before_measuring() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let yaml = temp.path().join("policy.yaml");
        std::fs::write(&yaml, "b: 2
a: 1
").expect("write yaml");
        let mut engine = PcrEngine::new();
        let source = |path: &std::path::Path| PcrMeasurementSource {
            pcr_index: 3,
            label: "policy".to_string(),
            source_type: "static_yaml".to_string(),
            source: path.to_string_lossy().into_owned(),
            critical: false,
        };

        let run = measure_sources(&mut engine, &[source(&yaml)]);
        assert!(run.errors.is_empty(), "{:?}", run.errors);
        let first = run.lines[0].hash_prefix.clone().expect("measured");

        // Reordering the keys must not change the canonical measurement.
        let reordered = temp.path().join("policy2.yaml");
        std::fs::write(&reordered, "a: 1
b: 2
").expect("write yaml");
        let mut engine2 = PcrEngine::new();
        let run2 = measure_sources(&mut engine2, &[source(&reordered)]);

        assert_eq!(run2.lines[0].hash_prefix.as_deref(), Some(first.as_str()));
    }

    #[test]
    fn a_full_software_run_measures_every_source_and_prints() {
        let sources = measurement_sources("nodeA", false);
        let mut engine = PcrEngine::new();

        let run = measure_sources(&mut engine, &sources);

        assert!(
            !run.lines.is_empty() || !run.errors.is_empty(),
            "the software source set must produce some measurement output"
        );
        // Exercised for panic-freedom; the formatting itself is what operators
        // read at startup.
        print_measurement_lines(&run.lines);
        print_measurement_lines(&[MeasurementLine {
            pcr_index: 9,
            label: "no outcome".to_string(),
            hash_prefix: None,
            error: None,
        }]);
    }
}
