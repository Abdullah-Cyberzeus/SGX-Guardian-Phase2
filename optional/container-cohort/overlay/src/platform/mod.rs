pub mod detect;
pub mod real;
pub mod traits;
#[cfg(feature = "virtual-platform")]
pub mod virtual_hw;

use crate::config_loader::NodeConfig;
use crate::key_manager::KeyManager;
use crate::platform::detect::{detect_platform, gather_detection_inputs, DetectedPlatform};
use crate::platform::real::RealHardwareProvider;
use crate::platform::traits::{
    AttestationProvider, KeyStoreProvider, MeasurementProvider, PlatformClass,
    PlatformInfoProvider, SecureBootProvider,
};
use crate::runtime_gates::GATES;
use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use std::sync::Arc;

static PLATFORM_CONTEXT: OnceCell<Arc<PlatformContext>> = OnceCell::new();

fn env_true(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

fn force_software_keys_requested() -> bool {
    env_true("SGX_FORCE_SOFTWARE_KEYS")
        || env_true("SGX_DISABLE_SE050_DKP")
        || GATES.force_software_keys
}

fn allow_debug_soft_keys_requested() -> bool {
    env_true("SGX_ALLOW_DEBUG_SOFT_KEYS") || GATES.allow_debug_soft_keys
}

pub struct PlatformContext {
    node_config: NodeConfig,
    requested_mode: String,
    debug_soft_keys_on_real: bool,
    key_store: Box<dyn KeyStoreProvider>,
    measurement: Box<dyn MeasurementProvider>,
    secure_boot: Box<dyn SecureBootProvider>,
    attestation: Box<dyn AttestationProvider>,
    info: Box<dyn PlatformInfoProvider>,
}

impl PlatformContext {
    pub fn init(node_config: NodeConfig) -> Result<Self> {
        let requested_mode = std::env::var("SGX_PLATFORM_MODE")
            .unwrap_or_else(|_| node_config.platform_or_default().mode);
        let requested_mode = requested_mode.to_ascii_lowercase();
        if !matches!(requested_mode.as_str(), "auto" | "real" | "virtual") {
            return Err(anyhow!(
                "Unsupported SGX platform mode '{}'; expected auto, real, or virtual",
                requested_mode
            ));
        }

        let inputs = gather_detection_inputs();
        let detected = detect_platform(&inputs);
        match detected {
            DetectedPlatform::Real => {
                if requested_mode == "virtual" {
                    return Err(anyhow!(
                        "Detected real i.MX8MP hardware but platform.mode=virtual was requested"
                    ));
                }
                if !inputs.se050_probe_ok {
                    return Err(anyhow!(
                        "Detected production hardware ({}) but SE050 probe failed — refusing to start",
                        inputs.describe()
                    ));
                }
                Ok(Self {
                    node_config: node_config.clone(),
                    requested_mode,
                    debug_soft_keys_on_real: force_software_keys_requested()
                        && allow_debug_soft_keys_requested(),
                    key_store: Box::new(RealHardwareProvider::new(node_config.clone())),
                    measurement: Box::new(RealHardwareProvider::new(node_config.clone())),
                    secure_boot: Box::new(RealHardwareProvider::new(node_config.clone())),
                    attestation: Box::new(RealHardwareProvider::new(node_config.clone())),
                    info: Box::new(RealHardwareProvider::new(node_config)),
                })
            }
            DetectedPlatform::VirtualCandidate => {
                if requested_mode == "real" {
                    return Err(anyhow!(
                        "Requested real platform mode on a non-board host ({})",
                        inputs.describe()
                    ));
                }
                #[cfg(feature = "virtual-platform")]
                {
                    Ok(Self {
                        node_config: node_config.clone(),
                        requested_mode,
                        debug_soft_keys_on_real: false,
                        key_store: Box::new(
                            crate::platform::virtual_hw::VirtualHardwareProvider::new(
                                node_config.clone(),
                            ),
                        ),
                        measurement: Box::new(
                            crate::platform::virtual_hw::VirtualHardwareProvider::new(
                                node_config.clone(),
                            ),
                        ),
                        secure_boot: Box::new(
                            crate::platform::virtual_hw::VirtualHardwareProvider::new(
                                node_config.clone(),
                            ),
                        ),
                        attestation: Box::new(
                            crate::platform::virtual_hw::VirtualHardwareProvider::new(
                                node_config.clone(),
                            ),
                        ),
                        info: Box::new(crate::platform::virtual_hw::VirtualHardwareProvider::new(
                            node_config,
                        )),
                    })
                }
                #[cfg(not(feature = "virtual-platform"))]
                {
                    Err(anyhow!(
                        "x86_64 development startup requires a binary built with --features virtual-platform"
                    ))
                }
            }
            DetectedPlatform::Unknown => Err(anyhow!(
                "Unsupported platform; refusing to start. Detection: {}",
                inputs.describe()
            )),
        }
    }

    pub fn install_global(self) -> Arc<Self> {
        let ctx = Arc::new(self);
        let _ = PLATFORM_CONTEXT.set(ctx.clone());
        ctx
    }

    pub fn global() -> Option<Arc<Self>> {
        PLATFORM_CONTEXT.get().cloned()
    }

    pub fn node_config(&self) -> &NodeConfig {
        &self.node_config
    }

    pub fn requested_mode(&self) -> &str {
        &self.requested_mode
    }

    pub fn platform_class(&self) -> PlatformClass {
        self.info.platform_class()
    }

    pub fn is_real(&self) -> bool {
        self.platform_class() == PlatformClass::Real
    }

    pub fn is_virtual(&self) -> bool {
        self.platform_class() == PlatformClass::Virtual
    }

    pub fn debug_soft_keys_on_real(&self) -> bool {
        self.debug_soft_keys_on_real
    }

    pub fn device_uid(&self) -> Result<String> {
        self.info.device_uid()
    }

    pub fn device_model(&self) -> String {
        self.info.device_model()
    }

    pub fn measurement_sources(
        &self,
    ) -> Vec<crate::secure_element::pcr_config::PcrMeasurementSource> {
        self.measurement.measurement_sources()
    }

    pub fn seed_pcr_engine(
        &self,
        engine: &mut crate::secure_element::pcr::PcrEngine,
    ) -> Result<()> {
        self.measurement.seed_engine(engine)
    }

    pub fn boot_chain_status(&self) -> crate::secure_element::secure_boot::BootChainStatus {
        self.secure_boot.boot_chain_status()
    }

    pub fn generate_quote(
        &self,
        nonce: &str,
        km: &KeyManager,
    ) -> Result<crate::attestation_service::SignedQuote> {
        self.attestation.generate_quote(nonce, km)
    }

    pub fn initialize_key_manager(
        &self,
        _node_id: &str,
        node_key_path: &str,
    ) -> Result<KeyManager> {
        if self.is_real() {
            if force_software_keys_requested() {
                if !allow_debug_soft_keys_requested() {
                    return Err(anyhow!(
                        "Real hardware software-key mode requires BOTH SGX_FORCE_SOFTWARE_KEYS=1 and SGX_ALLOW_DEBUG_SOFT_KEYS=1"
                    ));
                }
                return KeyManager::load_or_generate(node_key_path);
            }

            #[cfg(feature = "secure-element")]
            {
                return KeyManager::init_with_se050(
                    &crate::secure_element::config::SeConfig::default(),
                    "/var/lib/sgx-guardian",
                    node_key_path,
                );
            }
            #[cfg(not(feature = "secure-element"))]
            {
                return Err(anyhow!(
                    "Real hardware startup requires a secure-element-enabled binary"
                ));
            }
        }

        if force_software_keys_requested() {
            return KeyManager::load_or_generate(node_key_path);
        }

        #[cfg(feature = "virtual-platform")]
        {
            KeyManager::init_virtual_pkcs11(&self.node_config.node_id, node_key_path)
        }
        #[cfg(not(feature = "virtual-platform"))]
        {
            Err(anyhow!(
                "Virtual-platform startup requires a binary built with --features virtual-platform"
            ))
        }
    }

    pub fn ensure_dik(&self) -> Result<Vec<u8>> {
        self.key_store.ensure_dik()
    }

    pub fn rotate_dkp(&self) -> Result<crate::platform::traits::KeyRef> {
        self.key_store.rotate_dkp()
    }

    pub fn key_backend_name(&self) -> &'static str {
        self.key_store.backend_name()
    }
}
