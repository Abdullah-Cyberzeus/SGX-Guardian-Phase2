use crate::attestation_service::{AttestationQuote, SignedQuote};
use crate::config_loader::NodeConfig;
use crate::key_manager::KeyManager;
use crate::platform::traits::{
    AttestationProvider, KeyRef, KeyStoreProvider, MeasurementProvider, PlatformClass,
    PlatformInfoProvider, SecureBootProvider,
};
use crate::secure_element::dik::DeviceIdentityKey;
use crate::secure_element::pcr::{read_device_uid_from_source, PcrEngine};
use crate::secure_element::pcr_config::{self, PcrMeasurementSource};
use crate::secure_element::secure_boot::BootChainStatus;
use anyhow::{anyhow, Result};

pub struct RealHardwareProvider {
    node_config: NodeConfig,
}

impl RealHardwareProvider {
    pub fn new(node_config: NodeConfig) -> Self {
        Self { node_config }
    }
}

impl KeyStoreProvider for RealHardwareProvider {
    fn ensure_dik(&self) -> Result<Vec<u8>> {
        DeviceIdentityKey::ensure(&crate::secure_element::config::SeConfig::default())
            .map_err(|e| anyhow!("DIK ensure: {}", e))
    }

    fn ensure_dkp(&self) -> Result<KeyRef> {
        let dkp = crate::secure_element::dkp::DkpManager::init(
            &crate::secure_element::config::SeConfig::default(),
            "/var/lib/sgx-guardian",
        )
        .map_err(|e| anyhow!("DKP init: {}", e))?;
        Ok(KeyRef {
            label: format!("0x{:08X}", dkp.active_key_id()),
        })
    }

    fn sign(&self, _key: &KeyRef, data: &[u8]) -> Result<Vec<u8>> {
        let dkp = crate::secure_element::dkp::DkpManager::init(
            &crate::secure_element::config::SeConfig::default(),
            "/var/lib/sgx-guardian",
        )
        .map_err(|e| anyhow!("DKP init: {}", e))?;
        let signer = dkp
            .create_signer()
            .map_err(|e| anyhow!("Create signer: {}", e))?;
        signer
            .sign(dkp.active_key_id(), data)
            .map_err(|e| anyhow!("SE050 sign: {}", e))
    }

    fn public_key_der(&self, _key: &KeyRef) -> Result<Vec<u8>> {
        std::fs::read("/var/lib/sgx-guardian/keys/dkp_pub.der")
            .map_err(|e| anyhow!("read dkp_pub.der: {}", e))
    }

    fn rotate_dkp(&self) -> Result<KeyRef> {
        let mut dkp = crate::secure_element::dkp::DkpManager::init(
            &crate::secure_element::config::SeConfig::default(),
            "/var/lib/sgx-guardian",
        )
        .map_err(|e| anyhow!("DKP init: {}", e))?;
        let new_meta = dkp.rotate().map_err(|e| anyhow!("DKP rotate: {}", e))?;
        Ok(KeyRef {
            label: new_meta.key_id,
        })
    }

    fn backend_name(&self) -> &'static str {
        "SE050"
    }
}

impl MeasurementProvider for RealHardwareProvider {
    fn measurement_sources(&self) -> Vec<PcrMeasurementSource> {
        pcr_config::default_measurement_sources(&self.node_config.node_id)
    }

    fn seed_engine(&self, _engine: &mut PcrEngine) -> Result<()> {
        Ok(())
    }
}

impl SecureBootProvider for RealHardwareProvider {
    fn boot_chain_status(&self) -> BootChainStatus {
        BootChainStatus::check()
    }
}

impl AttestationProvider for RealHardwareProvider {
    fn generate_quote(&self, nonce: &str, km: &KeyManager) -> Result<SignedQuote> {
        AttestationQuote::generate_for_platform(
            nonce,
            &self.node_config.node_id,
            km,
            PlatformClass::Real,
        )?
        .sign(km)
    }

    fn platform_class(&self) -> PlatformClass {
        PlatformClass::Real
    }
}

impl PlatformInfoProvider for RealHardwareProvider {
    fn device_uid(&self) -> Result<String> {
        Ok(read_device_uid_from_source(&self.node_config.node_id))
    }

    fn device_model(&self) -> String {
        std::fs::read_to_string("/proc/device-tree/model")
            .or_else(|_| std::fs::read_to_string("/sys/firmware/devicetree/base/model"))
            .unwrap_or_else(|_| "VAR-SOM-MX8M".to_string())
            .trim_matches('\0')
            .trim()
            .to_string()
    }

    fn platform_class(&self) -> PlatformClass {
        PlatformClass::Real
    }
}
