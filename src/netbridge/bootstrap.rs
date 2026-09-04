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

/// Tests for the first-boot provisioning flow.
///
/// `prepare_runtime_directories` and `ensure_templates_exist` both target
/// hardcoded system paths (`/var/run/wpa_supplicant`, `/etc/sgx-guardian`) that
/// only root can create, and every validation in the startup flow shells out to
/// a wireless tool (`iw`, `hostapd`, `wpa_supplicant`, `udhcpc`) that is not
/// installed here. Both facts make the unprivileged outcome fully
/// deterministic, so these tests assert the real failure the daemon gets when
/// it is started on a host that has not been provisioned — including which step
/// of each orchestration aborts first, which is the part that actually matters
/// for diagnosing a failed bring-up.
#[cfg(test)]
mod tests {
    use super::{BootstrapError, BootstrapOptions, Bootstrapper};
        use crate::netbridge::types::{ApSettings, NetbridgeError, WifiClientSettings};
    use crate::netbridge::validator::ValidationError;
    use std::path::Path;

    fn options_in(dir: &Path) -> BootstrapOptions {
        BootstrapOptions {
            runtime_dir: dir.join("runtime").to_string_lossy().into_owned(),
            template_path: dir.join("hostapd.conf.template").to_string_lossy().into_owned(),
            output_config_path: dir.join("hostapd.conf").to_string_lossy().into_owned(),
        }
    }

    fn ap_settings() -> ApSettings {
        ApSettings {
            ssid: "sgx-test-ap".to_string(),
            interface: "wlan0".to_string(),
            ..ApSettings::default()
        }
    }

    fn uplink_settings() -> WifiClientSettings {
        WifiClientSettings {
            interface: "wlan0".to_string(),
            ..WifiClientSettings::default()
        }
    }

    /// True when this process cannot create the hardcoded system directories.
    fn unprivileged() -> bool {
        std::fs::create_dir_all("/var/run/sgx-bootstrap-privilege-probe").is_err()
    }

    #[test]
    fn default_options_point_at_the_documented_system_paths() {
        let defaults = BootstrapOptions::default();
        assert_eq!(defaults.runtime_dir, "/tmp/netbridge");
        assert_eq!(
            defaults.template_path,
            "/etc/sgx-guardian/hostapd.conf.template"
        );
        assert_eq!(defaults.output_config_path, "/tmp/netbridge/hostapd.conf");
    }

    #[test]
    fn bootstrap_error_display_names_the_failing_stage() {
        let validation: BootstrapError = ValidationError::IwNotInstalled.into();
        assert!(
            validation.to_string().starts_with("Validation Error: "),
            "got {validation}"
        );

        let config: BootstrapError =
            NetbridgeError::ValidationFailed("bad channel".to_string()).into();
        let config_text = config.to_string();
        assert!(config_text.starts_with("Config Error: "), "got {config_text}");
        assert!(config_text.contains("bad channel"));

        let io: BootstrapError =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied").into();
        let io_text = io.to_string();
        assert!(io_text.starts_with("IO Error: "), "got {io_text}");
        assert!(io_text.contains("denied"));

        let missing = BootstrapError::MissingTemplate("/etc/sgx-guardian/x.template".to_string());
        assert_eq!(
            missing.to_string(),
            "Missing Template: /etc/sgx-guardian/x.template"
        );

        // The Debug derive and the `std::error::Error` impl are both part of the
        // public contract callers rely on when logging a failed bring-up.
        assert!(format!("{missing:?}").contains("MissingTemplate"));
        let as_error: &dyn std::error::Error = &missing;
        assert!(as_error.source().is_none());
    }

    #[test]
    fn prepare_runtime_directories_creates_the_runtime_dir_then_fails_on_the_system_dirs() {
        if !unprivileged() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let options = options_in(temp.path());
        let runtime_dir = options.runtime_dir.clone();
        let bootstrapper = Bootstrapper::new(options);

        // The loop creates the (missing) runtime directory first, and only then
        // hits `/var/run/wpa_supplicant`, which it cannot create.
        let error = bootstrapper
            .prepare_runtime_directories()
            .expect_err("creating /var/run/wpa_supplicant must be refused");
        assert!(
            matches!(error, BootstrapError::Io(_)),
            "expected an IO error, got {error:?}"
        );
        assert!(
            Path::new(&runtime_dir).is_dir(),
            "the runtime directory must still have been created before the failure"
        );

        // Second call: the runtime directory now exists, so the `!path.exists()`
        // guard skips it and the same system directory fails again.
        assert!(matches!(
            bootstrapper.prepare_runtime_directories(),
            Err(BootstrapError::Io(_))
        ));
    }

    #[test]
    fn ensure_templates_exist_fails_when_the_template_directory_cannot_be_created() {
        if !unprivileged() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let bootstrapper = Bootstrapper::new(options_in(temp.path()));

        // Reading each `/etc/sgx-guardian` template fails, so every one is
        // marked as needing an update, and creating the parent is refused.
        let error = bootstrapper
            .ensure_templates_exist()
            .expect_err("writing into /etc/sgx-guardian must be refused");
        assert!(
            matches!(error, BootstrapError::Io(_)),
            "expected an IO error, got {error:?}"
        );
    }

    #[test]
    fn embedded_templates_are_compiled_in_and_usable() {
        // These are `include_str!`ed at build time, so a missing or emptied
        // template file is a build-time regression this asserts against.
        assert!(Bootstrapper::DEFAULT_HOSTAPD.contains("ssid="));
        assert!(!Bootstrapper::DEFAULT_WPA.trim().is_empty());
        assert!(!Bootstrapper::DEFAULT_DNSMASQ.trim().is_empty());
        // `ensure_templates_exist` rewrites any template still carrying the
        // legacy `{BSSID}` placeholder, so the embedded copy must not have it.
        assert!(!Bootstrapper::DEFAULT_HOSTAPD.contains("{BSSID}"));
    }

    #[test]
    fn run_startup_validations_reports_the_missing_wireless_toolchain() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bootstrapper = Bootstrapper::new(options_in(temp.path()));
        // `iw` is the first thing checked and is not installed here.
        match bootstrapper.run_startup_validations() {
            Err(BootstrapError::Validation(_)) => {}
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn initialize_ap_startup_aborts_at_the_validation_step() {
        let temp = tempfile::tempdir().expect("tempdir");
        let options = options_in(temp.path());
        let runtime_dir = options.runtime_dir.clone();
        let output_config = options.output_config_path.clone();
        let bootstrapper = Bootstrapper::new(options);

        match bootstrapper.initialize_ap_startup(&ap_settings()) {
            Err(BootstrapError::Validation(_)) => {}
            other => panic!("expected the validation step to abort first, got {other:?}"),
        }
        // Aborting at step 1 must leave every later side effect undone.
        assert!(!Path::new(&runtime_dir).exists());
        assert!(!Path::new(&output_config).exists());
    }

    #[test]
    fn run_uplink_validations_reports_the_missing_uplink_toolchain() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bootstrapper = Bootstrapper::new(options_in(temp.path()));
        match bootstrapper.run_uplink_validations(&uplink_settings()) {
            Err(BootstrapError::Validation(_)) => {}
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn initialize_uplink_startup_aborts_at_the_validation_step() {
        let temp = tempfile::tempdir().expect("tempdir");
        let options = options_in(temp.path());
        let runtime_dir = options.runtime_dir.clone();
        let bootstrapper = Bootstrapper::new(options);

        match bootstrapper.initialize_uplink_startup(&uplink_settings()) {
            Err(BootstrapError::Validation(_)) => {}
            other => panic!("expected the validation step to abort first, got {other:?}"),
        }
        assert!(!Path::new(&runtime_dir).exists());
    }
}
