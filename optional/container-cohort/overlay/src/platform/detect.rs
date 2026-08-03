use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedPlatform {
    Real,
    VirtualCandidate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionInputs {
    pub device_model: Option<String>,
    pub compatible: Option<String>,
    pub arch_aarch64: bool,
    pub arch_x86_64: bool,
    pub se050_probe_ok: bool,
}

impl DetectionInputs {
    pub fn describe(&self) -> String {
        format!(
            "model={:?}, compatible={:?}, arch_aarch64={}, arch_x86_64={}, se050_probe_ok={}",
            self.device_model,
            self.compatible,
            self.arch_aarch64,
            self.arch_x86_64,
            self.se050_probe_ok
        )
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_matches('\0').trim().to_string())
        .filter(|text| !text.is_empty())
}

fn read_device_tree_model() -> Option<String> {
    read_trimmed("/proc/device-tree/model")
        .or_else(|| read_trimmed("/sys/firmware/devicetree/base/model"))
}

fn read_device_tree_compatible() -> Option<String> {
    read_trimmed("/proc/device-tree/compatible")
        .or_else(|| read_trimmed("/sys/firmware/devicetree/base/compatible"))
}

fn real_board_marker(model: Option<&str>, compatible: Option<&str>) -> bool {
    let model_match = model
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("var-som-mx8m") || value.contains("imx8mp")
        })
        .unwrap_or(false);
    let compatible_match = compatible
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("fsl,imx8mp") || value.contains("imx8mp")
        })
        .unwrap_or(false);
    model_match || compatible_match
}

#[cfg(feature = "secure-element")]
fn probe_se050() -> bool {
    use crate::secure_element::config::SeConfig;
    use crate::secure_element::key_storage::SeKeyStorage;

    match SeKeyStorage::new(&SeConfig::default()) {
        Ok(store) => store.list_slots().is_ok(),
        Err(_) => false,
    }
}

#[cfg(not(feature = "secure-element"))]
fn probe_se050() -> bool {
    false
}

pub fn gather_detection_inputs() -> DetectionInputs {
    if let Ok(force) = std::env::var("SGX_TEST_PLATFORM_FORCE") {
        match force.as_str() {
            "real" => {
                return DetectionInputs {
                    device_model: Some("VAR-SOM-MX8M Plus test fixture".to_string()),
                    compatible: Some("fsl,imx8mp".to_string()),
                    arch_aarch64: true,
                    arch_x86_64: false,
                    se050_probe_ok: true,
                };
            }
            "real-se050-fail" => {
                return DetectionInputs {
                    device_model: Some("VAR-SOM-MX8M Plus test fixture".to_string()),
                    compatible: Some("fsl,imx8mp".to_string()),
                    arch_aarch64: true,
                    arch_x86_64: false,
                    se050_probe_ok: false,
                };
            }
            "virtual" => {
                return DetectionInputs {
                    device_model: None,
                    compatible: None,
                    arch_aarch64: false,
                    arch_x86_64: true,
                    se050_probe_ok: false,
                };
            }
            "unknown" => {
                return DetectionInputs {
                    device_model: Some("mystery-board".to_string()),
                    compatible: None,
                    arch_aarch64: true,
                    arch_x86_64: false,
                    se050_probe_ok: false,
                };
            }
            _ => {}
        }
    }

    let device_model = read_device_tree_model();
    let compatible = read_device_tree_compatible();
    let looks_real = real_board_marker(device_model.as_deref(), compatible.as_deref());

    DetectionInputs {
        device_model,
        compatible,
        arch_aarch64: cfg!(target_arch = "aarch64"),
        arch_x86_64: cfg!(target_arch = "x86_64"),
        se050_probe_ok: if looks_real { probe_se050() } else { false },
    }
}

pub fn detect_platform(inputs: &DetectionInputs) -> DetectedPlatform {
    let looks_real =
        real_board_marker(inputs.device_model.as_deref(), inputs.compatible.as_deref());

    if looks_real && inputs.arch_aarch64 {
        return DetectedPlatform::Real;
    }

    if inputs.arch_x86_64 && !looks_real {
        return DetectedPlatform::VirtualCandidate;
    }

    DetectedPlatform::Unknown
}

#[cfg(test)]
mod tests {
    use super::{detect_platform, DetectedPlatform, DetectionInputs};

    #[test]
    fn test_detect_real_board() {
        let detected = detect_platform(&DetectionInputs {
            device_model: Some("VAR-SOM-MX8M Plus".to_string()),
            compatible: Some("fsl,imx8mp".to_string()),
            arch_aarch64: true,
            arch_x86_64: false,
            se050_probe_ok: true,
        });
        assert_eq!(detected, DetectedPlatform::Real);
    }

    #[test]
    fn test_detect_virtual_candidate() {
        let detected = detect_platform(&DetectionInputs {
            device_model: None,
            compatible: None,
            arch_aarch64: false,
            arch_x86_64: true,
            se050_probe_ok: false,
        });
        assert_eq!(detected, DetectedPlatform::VirtualCandidate);
    }

    #[test]
    fn test_detect_unknown_partial_match() {
        let detected = detect_platform(&DetectionInputs {
            device_model: Some("some-arm-vm".to_string()),
            compatible: None,
            arch_aarch64: true,
            arch_x86_64: false,
            se050_probe_ok: false,
        });
        assert_eq!(detected, DetectedPlatform::Unknown);
    }
}
