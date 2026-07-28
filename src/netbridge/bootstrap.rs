use std::fs;
use std::path::Path;
use tracing::info;

use crate::netbridge::config::{ApSettings, ConfigGenerator};
use crate::netbridge::types::NetbridgeError;
use crate::netbridge::validator::{ValidationError, Validator};

#[derive(Debug)]
pub enum BootstrapError {
    Validation(ValidationError),
    Config(NetbridgeError),
    Io(std::io::Error),
    MissingTemplate(String),
}

impl From<ValidationError> for BootstrapError {
    fn from(err: ValidationError) -> Self {
        BootstrapError::Validation(err)
    }
}

impl From<NetbridgeError> for BootstrapError {
    fn from(err: NetbridgeError) -> Self {
        BootstrapError::Config(err)
    }
}

impl From<std::io::Error> for BootstrapError {
    fn from(err: std::io::Error) -> Self {
        BootstrapError::Io(err)
    }
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::Validation(e) => write!(f, "Validation Error: {}", e),
            BootstrapError::Config(e) => write!(f, "Config Error: {}", e),
            BootstrapError::Io(e) => write!(f, "IO Error: {}", e),
            BootstrapError::MissingTemplate(path) => write!(f, "Missing Template: {}", path),
        }
    }
}

impl std::error::Error for BootstrapError {}

pub struct BootstrapOptions {
    pub runtime_dir: String,
    pub template_path: String,
    pub output_config_path: String,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        BootstrapOptions {
            runtime_dir: "/tmp/netbridge".to_string(),
            template_path: "/etc/sgx-guardian/hostapd.conf.template".to_string(),
            output_config_path: "/tmp/netbridge/hostapd.conf".to_string(),
        }
    }
}

pub struct Bootstrapper {
    options: BootstrapOptions,
    validator: Validator,
    config_generator: ConfigGenerator,
}

impl Bootstrapper {
    pub fn new(options: BootstrapOptions) -> Self {
        Bootstrapper {
            options,
            validator: Validator::new(),
            config_generator: ConfigGenerator::new(),
        }
    }

    /// Prepares all required runtime directories on first boot.
    /// This makes the binary self-provisioning on a fresh device.
    pub fn prepare_runtime_directories(&self) -> Result<(), BootstrapError> {
        let dirs = [
            self.options.runtime_dir.as_str(), // /tmp/netbridge
            "/var/run/wpa_supplicant",         // wpa_supplicant socket dir
            "/etc/sgx-guardian",               // template config dir
        ];

        for dir in dirs.iter() {
            let path = Path::new(dir);
            if !path.exists() {
                info!("Creating directory: {}", dir);
                fs::create_dir_all(path)?;
            }
        }
        Ok(())
    }

    /// Embed default templates directly into the binary so they can be recreated if missing
    const DEFAULT_HOSTAPD: &'static str =
        include_str!("../../config/hostapd/hostapd.conf.template");
    const DEFAULT_WPA: &'static str =
        include_str!("../../config/wpa_supplicant/wpa_supplicant.conf.template");
    const DEFAULT_DNSMASQ: &'static str =
        include_str!("../../config/dnsmasq/dnsmasq.conf.template");

    /// Verifies if the required configuration templates exist, and generates them if they don't
    pub fn ensure_templates_exist(&self) -> Result<(), BootstrapError> {
        info!("Verifying configuration templates...");

        let templates = [
            (
                "/etc/sgx-guardian/hostapd.conf.template",
                Self::DEFAULT_HOSTAPD,
            ),
            (
                "/etc/sgx-guardian/wpa_supplicant.conf.template",
                Self::DEFAULT_WPA,
            ),
            (
                "/etc/sgx-guardian/dnsmasq.conf.template",
                Self::DEFAULT_DNSMASQ,
            ),
        ];

        for (path_str, content) in templates.iter() {
            let path = Path::new(path_str);
            let needs_update = match fs::read_to_string(path) {
                Ok(existing) => existing != *content || existing.contains("{BSSID}"),
                Err(_) => true,
            };

            if needs_update {
                info!("Updating/synchronizing template: {}", path_str);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, content)?;
            }
        }

        // Also explicitly check the template specified in options just in case it's custom
        let custom_path = Path::new(&self.options.template_path);
        if !custom_path.exists() {
            return Err(BootstrapError::MissingTemplate(
                self.options.template_path.clone(),
            ));
        }
        Ok(())
    }

    /// Runs all startup validations including AP support and dependencies
    pub fn run_startup_validations(&self) -> Result<(), BootstrapError> {
        info!("Running system validations for AP mode...");
        self.validator.validate_runtime_conditions()?;
        info!("All system validations passed.");
        Ok(())
    }

    /// Orchestrates the entire AP startup flow before hostapd is actually launched
    pub fn initialize_ap_startup(&self, settings: &ApSettings) -> Result<(), BootstrapError> {
        // 1. Run startup validations (iw, hostapd, wifi interface, AP mode support)
        self.run_startup_validations()?;

        // 2. Prepare runtime directories
        self.prepare_runtime_directories()?;

        // 3. Ensure configuration templates are present
        self.ensure_templates_exist()?;

        // 4. Generate the final hostapd.conf for launch
        info!("Generating final hostapd configuration...");
        self.config_generator.generate_config(
            &self.options.template_path,
            &self.options.output_config_path,
            settings,
        )?;
        info!(
            "Configuration successfully generated at {}",
            self.options.output_config_path
        );

        Ok(())
    }

    /// Validates uplink dependencies: wpa_supplicant, udhcpc, permissions, and client-mode hardware support
    pub fn run_uplink_validations(
        &self,
        settings: &crate::netbridge::types::WifiClientSettings,
    ) -> Result<(), BootstrapError> {
        info!("Running system validations for Wi-Fi client (uplink) mode...");
        self.validator
            .validate_uplink_runtime_conditions(&settings.interface)?;
        info!("All uplink system validations passed.");
        Ok(())
    }

    /// Orchestrates the runtime preparation for the Wi-Fi uplink
    pub fn initialize_uplink_startup(
        &self,
        settings: &crate::netbridge::types::WifiClientSettings,
    ) -> Result<(), BootstrapError> {
        // 1. Run startup validations
        self.run_uplink_validations(settings)?;

        // 2. Prepare runtime directories
        self.prepare_runtime_directories()?;

        // 3. Ensure configuration templates are present
        self.ensure_templates_exist()?;

        Ok(())
    }
}
