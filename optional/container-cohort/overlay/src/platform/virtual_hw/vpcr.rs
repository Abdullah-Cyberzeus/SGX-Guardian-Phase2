use crate::config_loader::NodeConfig;
use crate::secure_element::pcr::{canonical_static_yaml_measurement, PcrEngine};
use crate::secure_element::pcr_config::PcrMeasurementSource;
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

pub fn measurement_sources(node_config: &NodeConfig) -> Vec<PcrMeasurementSource> {
    vec![
        PcrMeasurementSource {
            pcr_index: 0,
            label: "Virtual boot seed".to_string(),
            source_type: "string".to_string(),
            source: format!(
                "VIRTUAL_BOOT:{}",
                node_config.platform_or_default().virtual_pcr_seed
            ),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 1,
            label: "Node config".to_string(),
            source_type: "static_yaml".to_string(),
            source: format!("/etc/sgx-guardian/config/{}.yaml", node_config.node_id),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 2,
            label: "Kernel".to_string(),
            source_type: "file".to_string(),
            source: "/proc/version".to_string(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 3,
            label: "Guardian binary".to_string(),
            source_type: "string".to_string(),
            source: guardian_binary_digest(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 4,
            label: "Guardian config (static)".to_string(),
            source_type: "static_yaml".to_string(),
            source: format!("/etc/sgx-guardian/config/{}.yaml", node_config.node_id),
            critical: false,
        },
    ]
}

pub fn seed_engine(node_config: &NodeConfig, engine: &mut PcrEngine) -> Result<()> {
    for source in measurement_sources(node_config) {
        match source.source_type.as_str() {
            "string" => {
                engine
                    .extend_from_string(source.pcr_index, &source.source)
                    .map_err(|e| anyhow!("virtual PCR{} string: {}", source.pcr_index, e))?;
            }
            "file" => {
                engine
                    .extend_from_file(source.pcr_index, &source.source)
                    .map_err(|e| anyhow!("virtual PCR{} file: {}", source.pcr_index, e))?;
            }
            "static_yaml" => {
                let canonical = canonical_static_yaml_measurement(&source.source);
                engine
                    .extend_from_string(source.pcr_index, &canonical)
                    .map_err(|e| anyhow!("virtual PCR{} yaml: {}", source.pcr_index, e))?;
            }
            other => {
                return Err(anyhow!("unsupported virtual PCR source type {}", other));
            }
        }
    }
    Ok(())
}

fn guardian_binary_digest() -> String {
    let path =
        std::env::current_exe().unwrap_or_else(|_| "/usr/local/bin/sgx_guardian_client".into());
    let digest = std::fs::read(path)
        .map(|bytes| Sha256::digest(bytes))
        .unwrap_or_else(|_| Sha256::digest(b"guardian-binary-unavailable".as_slice()));
    hex::encode(digest)
}
