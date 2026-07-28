use crate::did::errors::DidError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const METHOD: &str = "guardian";
pub const METHOD_PREFIX: &str = "did:guardian:";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    pub fn from_id_bytes(id_bytes: &[u8; 32]) -> Self {
        let b58 = bs58::encode(id_bytes).into_string();
        Self(format!("{}{}", METHOD_PREFIX, b58))
    }

    pub fn parse(s: &str) -> Result<Self, DidError> {
        if !s.starts_with("did:") {
            return Err(DidError::InvalidFormat(format!(
                "missing 'did:' scheme: {}",
                s
            )));
        }
        let rest = &s[4..];
        let (method, msi) = rest
            .split_once(':')
            .ok_or_else(|| DidError::InvalidFormat(format!("missing method delimiter: {}", s)))?;
        if method != METHOD {
            return Err(DidError::WrongMethod(method.to_string()));
        }

        let decoded = bs58::decode(msi)
            .into_vec()
            .map_err(|e| DidError::Base58(e.to_string()))?;
        if decoded.len() != 32 {
            return Err(DidError::InvalidFormat(format!(
                "MSI decodes to {} bytes, expected 32",
                decoded.len()
            )));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn msi(&self) -> &str {
        &self.0[METHOD_PREFIX.len()..]
    }

    pub fn id_bytes(&self) -> [u8; 32] {
        let v = bs58::decode(self.msi())
            .into_vec()
            .expect("Did invariant: msi must decode to 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn derive(se050_uid: &[u8], dkp_pubkey_der: &[u8]) -> Did {
    let mut hasher = Sha256::new();
    hasher.update(se050_uid);
    hasher.update(dkp_pubkey_der);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Did::from_id_bytes(&out)
}
