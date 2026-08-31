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
