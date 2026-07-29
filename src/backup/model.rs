use serde::{Deserialize, Serialize};

pub const BACKUP_SCHEMA_VERSION: u32 = 1;
pub const COMPONENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Policy,
    Config,
    Nebula,
    Nftables,
    IdentityMeta,
    Tls,
    Credentials,
    Crl,
    State,
    FeatureState,
    Vault,
}

impl Component {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Config => "config",
            Self::Nebula => "nebula",
            Self::Nftables => "nftables",
            Self::IdentityMeta => "identity_meta",
            Self::Tls => "tls",
            Self::Credentials => "credentials",
            Self::Crl => "crl",
            Self::State => "state",
            Self::FeatureState => "feature_state",
            Self::Vault => "vault",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMeta {
    pub did: String,
    pub dkp_slot_id: String,
    pub dik_slot_id: String,
    pub dkp_public_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentManifest {
    pub component: Component,
    pub schema_version: u32,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub backup_id: String,
    pub created_at: String,
    pub source_node_id: String,
    pub source_did: String,
    pub portable: bool,
    pub components: Vec<ComponentManifest>,
    pub identity_meta: IdentityMeta,
    pub plaintext_sha256: String,
    pub bundle_hmac_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: String,
    pub created_at: String,
    pub source_node_id: String,
    pub source_did: String,
    pub portable: bool,
    pub components: Vec<Component>,
    pub bundle_path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupHistory {
    pub records: Vec<BackupRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateReport {
    pub status: String,
    pub backup_id: String,
    pub source_node_id: String,
    pub source_did: String,
    pub target_did: String,
    pub same_device_identity: bool,
    pub portable: bool,
    pub components: Vec<ComponentManifest>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub status: String,
    pub message: String,
    pub restart_required: bool,
}
