use crate::attestation_service::{AttestationQuote, SignedQuote};
use crate::config_loader::NodeConfig;
use crate::key_manager::KeyManager;
use crate::platform::traits::PlatformClass;
use anyhow::Result;

pub fn generate_quote(
    node_config: &NodeConfig,
    nonce: &str,
    km: &KeyManager,
) -> Result<SignedQuote> {
    AttestationQuote::generate_for_platform(
        nonce,
        &node_config.node_id,
        km,
        PlatformClass::Virtual,
    )?
    .sign(km)
}
