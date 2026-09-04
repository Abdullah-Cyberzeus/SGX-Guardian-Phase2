use super::tools::Tpm2Cli;
use super::{ek, TpmConfig, TpmError};
use crate::secure_element::pcr::{
    read_dkp_key_version, PcrMeasurementError, PcrSnapshot, PCR_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};

pub fn selected_indices(selection: &str) -> Vec<u32> {
    selection
        .split_once(':')
        .map(|(_, values)| {
            values
                .split(',')
                .filter_map(|part| part.trim().parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct PathGuard(Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    fn config(selection: &str) -> TpmConfig {
        TpmConfig {
            device: "/missing/tpm".into(),
            tcti: "device:/missing/tpm".into(),
            explicit_backend: true,
            dik_handle: 0x8100_0100,
            dkp_handle_base: 0x8100_0010,
            ek_handle: 0x8101_0001,
            pcr_selection: selection.into(),
            owner_auth: None,
            key_auth: None,
        }
    }

    #[cfg(unix)]
    fn with_pcr_tool(output: &str, test: impl FnOnce()) {
        use std::os::unix::fs::PermissionsExt;

        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("tool directory");
        let tool = dir.path().join("tpm2_pcrread");
        let escaped = output.replace('\\', "\\\\").replace('"', "\\\"");
        std::fs::write(&tool, format!("#!/bin/sh\nprintf \"%s\" \"{escaped}\"\n"))
            .expect("write fake PCR tool");
        let mut permissions = std::fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool, permissions).expect("make executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());
        let _guard = PathGuard(old_path);
        test();
    }

    #[test]
    fn selected_indices_parses_single_range() {
        let v = selected_indices("sha1:0,1,2");
        assert_eq!(v, vec![0, 1, 2]);
    }

    #[test]
    fn selected_indices_returns_empty_on_invalid() {
        let v = selected_indices("invalid-format");
        assert!(v.is_empty());
    }

    #[test]
    fn selected_indices_skips_whitespace_and_invalid_members() {
        assert_eq!(selected_indices("sha256: 0, bad, 7, ,24"), vec![0, 7, 24]);
        assert!(selected_indices(":none").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn read_pcr_values_orders_expected_indices_and_normalizes_hex() {
        let a = "A".repeat(64);
        let b = "b".repeat(64);
        with_pcr_tool(&format!("sha256:\n  7 : 0x{b}\n  0 : 0x{a}\n"), || {
            assert_eq!(
                read_pcr_values(&config("sha256:0,7")).expect("PCR values"),
                vec![(0, "a".repeat(64)), (7, b)]
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn read_pcr_values_rejects_invalid_selection_and_missing_values() {
        with_pcr_tool("noise\n", || {
            let invalid = read_pcr_values(&config("sha256"))
                .expect_err("selection without indices must fail");
            assert!(
                matches!(invalid, TpmError::Parse(message) if message.contains("invalid PCR selection"))
            );

            let missing =
                read_pcr_values(&config("sha256:0")).expect_err("missing selected PCR must fail");
            assert!(
                matches!(missing, TpmError::Parse(message) if message.contains("missing PCR0"))
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn read_snapshot_fails_once_it_reaches_the_unreachable_ek_step() {
        // read_pcr_values succeeds against the fake tool, but read_snapshot then calls
        // ek::node_uid_hex, which needs /var/lib/sgx-guardian/keys (unwritable here) — a
        // real, deterministic failure past the PCR-reading step.
        let a = "a".repeat(64);
        with_pcr_tool(&format!("sha256:\n  0 : 0x{a}\n"), || {
            let result = read_snapshot(&config("sha256:0"), "/missing/dkp.der");
            assert!(result.is_err());
        });
    }

    #[cfg(unix)]
    #[test]
    fn read_pcr_values_ignores_short_hex_and_unparseable_lines() {
        let valid = "c".repeat(64);
        with_pcr_tool(
            &format!("not-a-pcr\n  bad: 0x{valid}\n  0: 0x1234\n  PCR0: 0x{valid} trailing\n"),
            || {
                assert_eq!(
                    read_pcr_values(&config("sha256:0")).expect("valid PCR remains"),
                    vec![(0, valid)]
                );
            },
        );
    }
}

pub fn read_pcr_values(cfg: &TpmConfig) -> Result<Vec<(u32, String)>, TpmError> {
    let cli = Tpm2Cli::new(cfg.clone());
    let raw = cli.pcr_read_text(&cfg.pcr_selection)?;
    let expected = selected_indices(&cfg.pcr_selection);
    if expected.is_empty() {
        return Err(TpmError::Parse(format!(
            "invalid PCR selection `{}`",
            cfg.pcr_selection
        )));
    }

    let mut values = std::collections::BTreeMap::new();
    for line in raw.lines() {
        let Some((prefix, suffix)) = line.split_once(':') else {
            continue;
        };
        let Some(start) = suffix.find("0x") else {
            continue;
        };

        let hex_value = suffix[start + 2..]
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .collect::<String>();
        if hex_value.len() < 64 {
            continue;
        }

        let index_digits = prefix
            .chars()
            .filter(|ch| ch.is_ascii_digit())
            .collect::<String>();
        let Ok(index) = index_digits.parse::<u32>() else {
            continue;
        };
        values.insert(index, hex_value.to_lowercase());
    }

    let mut ordered = Vec::with_capacity(expected.len());
    for index in expected {
        let Some(value) = values.get(&index) else {
            return Err(TpmError::Parse(format!(
                "missing PCR{} in tpm2_pcrread output",
                index
            )));
        };
        ordered.push((index, value.clone()));
    }

    Ok(ordered)
}

pub fn read_snapshot(cfg: &TpmConfig, dkp_pub_path: &str) -> Result<PcrSnapshot, TpmError> {
    let values = read_pcr_values(cfg)?;
    let mut composite_input = Vec::new();
    for (_, value) in &values {
        let bytes = hex::decode(value)
            .map_err(|error| TpmError::Parse(format!("invalid PCR hex `{}`: {}", value, error)))?;
        composite_input.extend_from_slice(&bytes);
    }

    Ok(PcrSnapshot {
        pcr_values: values.into_iter().map(|(_, value)| value).collect(),
        composite_digest: hex::encode(Sha256::digest(&composite_input)),
        composite_signature: None,
        nonce: String::new(),
        measured_at: chrono::Utc::now().to_rfc3339(),
        device_uid: ek::node_uid_hex(cfg, dkp_pub_path)?,
        key_version: read_dkp_key_version(),
        firmware_version: None,
        measurement_errors: Vec::<PcrMeasurementError>::new(),
        integrity_status: "PASS".to_string(),
        schema_version: PCR_SCHEMA_VERSION,
    })
}
