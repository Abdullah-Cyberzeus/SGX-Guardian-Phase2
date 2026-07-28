use std::fs;
use std::path::Path;

// Re-export ApSettings so existing modules don't break
pub use crate::netbridge::types::ApSettings;
use crate::netbridge::types::NetbridgeError;

pub struct ConfigGenerator;

impl ConfigGenerator {
    pub fn new() -> Self {
        ConfigGenerator {}
    }
}

impl Default for ConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigGenerator {
    /// Reads the hostapd configuration template from the filesystem.
    pub fn read_template<P: AsRef<Path>>(
        &self,
        template_path: P,
    ) -> Result<String, NetbridgeError> {
        let content = fs::read_to_string(template_path).map_err(NetbridgeError::IoError)?;
        Ok(content)
    }

    /// Replaces variables in the template with values from ApSettings.
    /// Expected placeholders: {INTERFACE}, {SSID}, {CHANNEL}, {HW_MODE}, {WPA_PASSPHRASE}
    pub fn replace_variables(
        &self,
        template: &str,
        settings: &ApSettings,
    ) -> Result<String, NetbridgeError> {
        if settings.ssid.contains('\n') || settings.ssid.contains('\r') {
            return Err(NetbridgeError::ConfigGenerationFailed(
                "SSID cannot contain newlines".into(),
            ));
        }
        if settings.ssid.len() > 32 {
            return Err(NetbridgeError::ConfigGenerationFailed(
                "SSID must be at most 32 bytes".into(),
            ));
        }

        let mut config = template
            .replace("{INTERFACE}", &settings.interface)
            .replace("{SSID}", &settings.ssid)
            .replace("{CHANNEL}", &settings.channel.to_string())
            .replace("{HW_MODE}", &settings.hw_mode)
            .replace("{COUNTRY_CODE}", &settings.country_code);

        if let Some(passphrase) = &settings.wpa_passphrase {
            if passphrase.len() < 8 || passphrase.len() > 63 {
                return Err(NetbridgeError::ConfigGenerationFailed(
                    "WPA passphrase must be 8-63 characters".into(),
                ));
            }
            if passphrase.contains('\n') || passphrase.contains('\r') {
                return Err(NetbridgeError::ConfigGenerationFailed(
                    "WPA passphrase cannot contain newlines".into(),
                ));
            }
            config = config.replace("{WPA_PASSPHRASE}", passphrase);
            // Configure WPA2-PSK only to maximize compatibility across client devices
            config = config.replace("{WPA}", "2");
            config = config.replace("{WPA_KEY_MGMT}", "WPA-PSK");
            config = config.replace("{WPA_PAIRWISE}", "CCMP");
            config = config.replace("{RSN_PAIRWISE}", "CCMP");
        } else {
            config = config.replace("{WPA_PASSPHRASE}", "");
            config = config.replace("{WPA}", "0");
            config = config.replace("{WPA_KEY_MGMT}", "");
            config = config.replace("{WPA_PAIRWISE}", "");
            config = config.replace("{RSN_PAIRWISE}", "");
        }

        Ok(config)
    }

    /// Generates the final hostapd.conf and writes it to the specified output path.
    pub fn generate_config<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        template_path: P1,
        output_path: P2,
        settings: &ApSettings,
    ) -> Result<(), NetbridgeError> {
        let template = self.read_template(template_path)?;
        let final_config = self.replace_variables(&template, settings)?;

        // Ensure the parent directories exist (like config/hostapd/generated)
        if let Some(parent) = output_path.as_ref().parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(NetbridgeError::IoError)?;
            }
        }

        fs::write(output_path, final_config).map_err(NetbridgeError::IoError)?;

        Ok(())
    }

    /// Generates to the default project paths requested.
    pub fn generate_default(&self, settings: &ApSettings) -> Result<(), NetbridgeError> {
        let template_path = "/etc/sgx-guardian/hostapd.conf.template";
        let output_path = "/tmp/netbridge/hostapd.conf";
        self.generate_config(template_path, output_path, settings)
    }
}

pub struct DnsmasqConfigGenerator;

impl DnsmasqConfigGenerator {
    pub fn new() -> Self {
        DnsmasqConfigGenerator {}
    }
}

impl Default for DnsmasqConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsmasqConfigGenerator {
    pub fn read_template<P: AsRef<Path>>(
        &self,
        template_path: P,
    ) -> Result<String, NetbridgeError> {
        let content = fs::read_to_string(template_path).map_err(NetbridgeError::IoError)?;
        Ok(content)
    }

    pub fn replace_variables(
        &self,
        template: &str,
        settings: &crate::netbridge::types::DnsmasqSettings,
    ) -> String {
        template
            .replace("{INTERFACE}", &settings.interface)
            .replace("{GATEWAY_IP}", &settings.gateway_ip)
            .replace("{DHCP_RANGE_START}", &settings.dhcp_range_start)
            .replace("{DHCP_RANGE_END}", &settings.dhcp_range_end)
            .replace("{LOCAL_DOMAIN}", &settings.local_domain)
    }

    pub fn generate_config<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        template_path: P1,
        output_path: P2,
        settings: &crate::netbridge::types::DnsmasqSettings,
    ) -> Result<(), NetbridgeError> {
        let template = self.read_template(template_path)?;
        let final_config = self.replace_variables(&template, settings);

        if let Some(parent) = output_path.as_ref().parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(NetbridgeError::IoError)?;
            }
        }

        fs::write(output_path, final_config).map_err(NetbridgeError::IoError)?;
        Ok(())
    }

    pub fn generate_default(
        &self,
        settings: &crate::netbridge::types::DnsmasqSettings,
    ) -> Result<(), NetbridgeError> {
        let template_path = "/etc/sgx-guardian/dnsmasq.conf.template";
        let output_path = "/tmp/netbridge/dnsmasq.conf";
        self.generate_config(template_path, output_path, settings)
    }
}
