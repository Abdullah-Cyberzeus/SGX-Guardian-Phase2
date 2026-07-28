use crate::netbridge::types::{NetbridgeError, WifiClientSettings};
use std::fs;
use std::path::Path;
use tracing::info;

pub struct WpaConfigGenerator;

impl WpaConfigGenerator {
    pub fn new() -> Self {
        WpaConfigGenerator {}
    }
}

impl Default for WpaConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl WpaConfigGenerator {
    pub fn generate<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        template_path: P1,
        output_path: P2,
        settings: &WifiClientSettings,
    ) -> Result<String, NetbridgeError> {
        info!("Generating wpa_supplicant configuration from template...");

        let template_content = fs::read_to_string(template_path.as_ref()).map_err(|e| {
            NetbridgeError::TemplateError(format!("Failed to read wpa_supplicant template: {}", e))
        })?;

        if settings.country.len() != 2 || !settings.country.chars().all(|c| c.is_ascii_alphabetic())
        {
            return Err(NetbridgeError::ConfigGenerationFailed(
                "Country code must be 2 ASCII letters".into(),
            ));
        }

        let mut config_content = template_content.replace("{COUNTRY}", &settings.country);

        for network in &settings.networks {
            let ssid = &network.ssid;
            let psk = network.password.as_deref();

            if ssid.contains('\n') || ssid.contains('\r') {
                return Err(NetbridgeError::ConfigGenerationFailed(
                    "SSID cannot contain newlines".into(),
                ));
            }
            if ssid.len() > 32 {
                return Err(NetbridgeError::ConfigGenerationFailed(
                    "SSID must be at most 32 bytes".into(),
                ));
            }

            let mut block = format!("\nnetwork={{\n    ssid=\"{}\"\n    scan_ssid=1\n", ssid);

            let valid_psk = psk.filter(|p| !p.trim().is_empty());

            if let Some(password) = valid_psk {
                if password.len() < 8 || password.len() > 63 {
                    return Err(NetbridgeError::ConfigGenerationFailed(
                        "WPA passphrase must be 8-63 characters".into(),
                    ));
                }
                if password.contains('\n') || password.contains('\r') {
                    return Err(NetbridgeError::ConfigGenerationFailed(
                        "WPA passphrase cannot contain newlines".into(),
                    ));
                }
                block.push_str(&format!("    psk=\"{}\"\n", password));
            } else {
                block.push_str("    key_mgmt=NONE\n");
            }

            if let Some(bssid) = &network.bssid {
                if !bssid.trim().is_empty() {
                    let parts: Vec<&str> = bssid.split(':').collect();
                    if parts.len() != 6
                        || parts
                            .iter()
                            .any(|p| p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit()))
                    {
                        return Err(NetbridgeError::ConfigGenerationFailed(format!(
                            "Invalid BSSID format: {}",
                            bssid
                        )));
                    }
                    block.push_str(&format!("    bssid={}\n", bssid));
                }
            }

            block.push_str("}\n");
            config_content.push_str(&block);
        }

        if let Some(parent) = Path::new(output_path.as_ref()).parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(NetbridgeError::IoError)?;
            }
        }

        fs::write(output_path.as_ref(), config_content).map_err(|e| {
            NetbridgeError::ConfigGenerationFailed(format!(
                "Failed to write wpa_supplicant config: {}",
                e
            ))
        })?;

        info!(
            "Successfully generated wpa_supplicant config at {:?}",
            output_path.as_ref()
        );

        Ok(output_path.as_ref().to_string_lossy().to_string())
    }

    pub fn generate_default(
        &self,
        settings: &WifiClientSettings,
    ) -> Result<String, NetbridgeError> {
        let template_path = "/etc/sgx-guardian/wpa_supplicant.conf.template";
        let output_path = "/tmp/netbridge/wpa_supplicant.conf";
        self.generate(template_path, output_path, settings)
    }
}
