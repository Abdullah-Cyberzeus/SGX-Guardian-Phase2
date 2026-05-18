use crate::did::did::Did;
use crate::did::errors::DidError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_IDENTITY_DIR: &str = "/var/lib/sgx-guardian/identity";
pub const DEFAULT_DID_PATH: &str = "/var/lib/sgx-guardian/identity/did.json";
pub const DEFAULT_PEERS_DIR: &str = "/var/lib/sgx-guardian/identity/peers";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationProof {
    pub se050_uid: String,
    pub se050_uid_source: String,
    pub dkp_v1_pubkey_sha256_b16: String,
    pub dkp_v1_pubkey_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRecord {
    pub did: String,
    pub method: String,
    pub method_version: String,
    pub did_id_b58: String,
    pub did_id_hex: String,
    pub created_at: String,
    pub deactivated_at: Option<String>,
    pub derivation: DerivationProof,
    pub current_dkp_version: u32,
    pub deriv_signature_b64: String,
}

impl DidRecord {
    pub fn save(&self, path: &str) -> Result<(), DidError> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(self)?;
        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
        }

        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, DidError> {
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn did(&self) -> Result<Did, DidError> {
        Did::parse(&self.did)
    }

    pub fn is_active(&self) -> bool {
        self.deactivated_at.is_none()
    }
}

#[derive(Serialize)]
struct CanonicalDerivation<'a> {
    se050_uid: &'a str,
    se050_uid_source: &'a str,
    dkp_v1_pubkey_sha256_b16: &'a str,
    dkp_v1_pubkey_path: &'a str,
}

pub fn derivation_signing_bytes(d: &DerivationProof) -> Vec<u8> {
    let canonical = CanonicalDerivation {
        se050_uid: &d.se050_uid,
        se050_uid_source: &d.se050_uid_source,
        dkp_v1_pubkey_sha256_b16: &d.dkp_v1_pubkey_sha256_b16,
        dkp_v1_pubkey_path: &d.dkp_v1_pubkey_path,
    };

    let mut out = b"sgx-guardian:did:guardian:v1:derivation:".to_vec();
    out.extend_from_slice(
        &serde_json::to_vec(&canonical)
            .expect("Canonical derivation serialization should never fail"),
    );
    out
}
