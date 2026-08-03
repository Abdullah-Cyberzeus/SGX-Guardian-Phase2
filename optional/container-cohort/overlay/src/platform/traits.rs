use crate::attestation_service::SignedQuote;
use crate::key_manager::KeyManager;
use crate::secure_element::pcr::PcrEngine;
use crate::secure_element::pcr_config::PcrMeasurementSource as MeasurementSource;
use crate::secure_element::secure_boot::BootChainStatus;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformClass {
    Real,
    Virtual,
}

impl PlatformClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Virtual => "virtual",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    pub label: String,
}

pub trait KeyStoreProvider: Send + Sync {
    fn ensure_dik(&self) -> Result<Vec<u8>>;
    fn ensure_dkp(&self) -> Result<KeyRef>;
    fn sign(&self, key: &KeyRef, data: &[u8]) -> Result<Vec<u8>>;
    fn public_key_der(&self, key: &KeyRef) -> Result<Vec<u8>>;
    fn rotate_dkp(&self) -> Result<KeyRef>;
    fn backend_name(&self) -> &'static str;
}

pub trait MeasurementProvider: Send + Sync {
    fn measurement_sources(&self) -> Vec<MeasurementSource>;
    fn seed_engine(&self, engine: &mut PcrEngine) -> Result<()>;
}

pub trait SecureBootProvider: Send + Sync {
    fn boot_chain_status(&self) -> BootChainStatus;
}

pub trait AttestationProvider: Send + Sync {
    fn generate_quote(&self, nonce: &str, km: &KeyManager) -> Result<SignedQuote>;
    fn platform_class(&self) -> PlatformClass;
}

pub trait PlatformInfoProvider: Send + Sync {
    fn device_uid(&self) -> Result<String>;
    fn device_model(&self) -> String;
    fn platform_class(&self) -> PlatformClass;
}
