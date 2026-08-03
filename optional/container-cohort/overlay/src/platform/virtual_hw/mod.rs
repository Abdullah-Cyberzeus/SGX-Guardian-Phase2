pub mod softhsm;
pub mod vattest;
pub mod vboot;
pub mod vinfo;
pub mod vpcr;

use crate::config_loader::NodeConfig;
use crate::key_manager::KeyManager;
use crate::platform::traits::{
    AttestationProvider, KeyRef, KeyStoreProvider, MeasurementProvider, PlatformClass,
    PlatformInfoProvider, SecureBootProvider,
};
use crate::secure_element::pcr::PcrEngine;
use crate::secure_element::pcr_config::PcrMeasurementSource;
use crate::secure_element::secure_boot::BootChainStatus;
use anyhow::{anyhow, Result};

pub struct VirtualHardwareProvider {
    node_config: NodeConfig,
}

impl VirtualHardwareProvider {
    pub fn new(node_config: NodeConfig) -> Self {
        Self { node_config }
    }
}

impl KeyStoreProvider for VirtualHardwareProvider {
    fn ensure_dik(&self) -> Result<Vec<u8>> {
        Ok(softhsm::ensure_named_key(&self.node_config.node_id, "dik", 1)?.spki_public_key)
    }

    fn ensure_dkp(&self) -> Result<KeyRef> {
        let _ = softhsm::ensure_virtual_dkp(&self.node_config.node_id)?;
        Ok(KeyRef {
            label: "virtual-dkp".to_string(),
        })
    }

    fn sign(&self, _key: &KeyRef, data: &[u8]) -> Result<Vec<u8>> {
        let history = crate::secure_element::key_meta::DkpKeyHistory::load(
            "/var/lib/sgx-guardian/keys/dkp_metadata.json",
        )
        .map_err(|e| anyhow!("load virtual dkp history: {}", e))?;
        let version = history.active_key().map(|meta| meta.version).unwrap_or(1);
        softhsm::sign_with_key(&self.node_config.node_id, "dkp", version, data)
    }

    fn public_key_der(&self, _key: &KeyRef) -> Result<Vec<u8>> {
        Ok(softhsm::ensure_virtual_dkp(&self.node_config.node_id)?.raw_public_key)
    }

    fn rotate_dkp(&self) -> Result<KeyRef> {
        let next = softhsm::rotate_virtual_dkp(&self.node_config.node_id)?;
        Ok(KeyRef { label: next.key_id })
    }

    fn backend_name(&self) -> &'static str {
        "SoftHSM2"
    }
}

impl MeasurementProvider for VirtualHardwareProvider {
    fn measurement_sources(&self) -> Vec<PcrMeasurementSource> {
        vpcr::measurement_sources(&self.node_config)
    }

    fn seed_engine(&self, engine: &mut PcrEngine) -> Result<()> {
        vpcr::seed_engine(&self.node_config, engine)
    }
}

impl SecureBootProvider for VirtualHardwareProvider {
    fn boot_chain_status(&self) -> BootChainStatus {
        vboot::simulated_boot_chain_status()
    }
}

impl AttestationProvider for VirtualHardwareProvider {
    fn generate_quote(
        &self,
        nonce: &str,
        km: &KeyManager,
    ) -> Result<crate::attestation_service::SignedQuote> {
        vattest::generate_quote(&self.node_config, nonce, km)
    }

    fn platform_class(&self) -> PlatformClass {
        PlatformClass::Virtual
    }
}

impl PlatformInfoProvider for VirtualHardwareProvider {
    fn device_uid(&self) -> Result<String> {
        vinfo::ensure_virtual_uid()
    }

    fn device_model(&self) -> String {
        vinfo::virtual_device_model()
    }

    fn platform_class(&self) -> PlatformClass {
        PlatformClass::Virtual
    }
}
