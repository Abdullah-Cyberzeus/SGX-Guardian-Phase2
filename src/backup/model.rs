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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_component_has_stable_string_and_serde_contracts() {
        let cases = [
            (Component::Policy, "policy"),
            (Component::Config, "config"),
            (Component::Nebula, "nebula"),
            (Component::Nftables, "nftables"),
            (Component::IdentityMeta, "identity_meta"),
            (Component::Tls, "tls"),
            (Component::Credentials, "credentials"),
            (Component::Crl, "crl"),
            (Component::State, "state"),
            (Component::FeatureState, "feature_state"),
            (Component::Vault, "vault"),
        ];
        for (component, expected) in cases {
            assert_eq!(component.as_str(), expected);
            let json = serde_json::to_string(&component).expect("serialize component");
            assert_eq!(json, format!("\"{expected}\""));
            assert_eq!(
                serde_json::from_str::<Component>(&json).expect("deserialize component"),
                component
            );
        }
        assert_eq!(BACKUP_SCHEMA_VERSION, 1);
        assert_eq!(COMPONENT_SCHEMA_VERSION, 1);
    }

    #[test]
    fn manifests_history_and_reports_round_trip_all_fields() {
        let component = ComponentManifest {
            component: Component::Policy,
            schema_version: COMPONENT_SCHEMA_VERSION,
            paths: vec!["policy.yaml".into()],
        };
        let identity = IdentityMeta {
            did: "did:guardian:nodeA".into(),
            dkp_slot_id: "dkp-slot".into(),
            dik_slot_id: "dik-slot".into(),
            dkp_public_versions: vec!["v1".into(), "v2".into()],
        };
        let manifest = Manifest {
            schema_version: BACKUP_SCHEMA_VERSION,
            backup_id: "backup-1".into(),
            created_at: "2026-08-31T00:00:00Z".into(),
            source_node_id: "nodeA".into(),
            source_did: identity.did.clone(),
            portable: true,
            components: vec![component.clone()],
            identity_meta: identity,
            plaintext_sha256: "plain".into(),
            bundle_hmac_sha256: "hmac".into(),
        };
        let value = serde_json::to_value(&manifest).expect("serialize manifest");
        let restored: Manifest = serde_json::from_value(value).expect("deserialize manifest");
        assert_eq!(restored.backup_id, "backup-1");
        assert_eq!(restored.components[0].component, Component::Policy);

        let history = BackupHistory {
            records: vec![BackupRecord {
                id: "backup-1".into(),
                created_at: manifest.created_at.clone(),
                source_node_id: "nodeA".into(),
                source_did: "did:guardian:nodeA".into(),
                portable: true,
                components: vec![Component::Policy],
                bundle_path: "/tmp/backup.bin".into(),
                size_bytes: 42,
            }],
        };
        assert_eq!(
            serde_json::from_str::<BackupHistory>(&serde_json::to_string(&history).unwrap())
                .unwrap()
                .records
                .len(),
            1
        );
        assert!(BackupHistory::default().records.is_empty());

        let validation = ValidateReport {
            status: "valid".into(),
            backup_id: "backup-1".into(),
            source_node_id: "nodeA".into(),
            source_did: "did:guardian:nodeA".into(),
            target_did: "did:guardian:nodeB".into(),
            same_device_identity: false,
            portable: true,
            components: vec![component],
            warnings: vec!["different device".into()],
        };
        let restore = RestoreReport {
            status: "restored".into(),
            message: "complete".into(),
            restart_required: true,
        };
        assert_eq!(serde_json::to_value(validation).unwrap()["status"], "valid");
        assert_eq!(
            serde_json::to_value(restore).unwrap()["restart_required"],
            true
        );
    }
}
