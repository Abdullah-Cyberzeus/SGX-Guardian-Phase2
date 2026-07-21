use super::{TpmConfig, TpmError};

pub fn generate_quote_stub(_cfg: &TpmConfig, _nonce: &str) -> Result<(), TpmError> {
    Ok(())
}
