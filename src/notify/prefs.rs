use crate::did::doc_persistence;
use crate::did::doc_sign;
use crate::did::document::Proof;
use crate::did::DidRecord;
use crate::notify::errors::{NotifyError, NotifyResult};
use crate::notify::model::NotificationKind;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertPrefs {
    pub high: bool,
    pub medium: bool,
    pub low: bool,
}

impl Default for AlertPrefs {
    fn default() -> Self {
        Self {
            high: true,
            medium: true,
            low: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePrefs {
    pub new_device: bool,
    pub pending_approval: bool,
    pub guardian_offline: bool,
}

impl Default for DevicePrefs {
    fn default() -> Self {
        Self {
            new_device: true,
            pending_approval: true,
            guardian_offline: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CirclePrefs {
    pub new_message: bool,
    pub incoming_call: bool,
    pub member_joined: bool,
}

impl Default for CirclePrefs {
    fn default() -> Self {
        Self {
            new_message: true,
            incoming_call: true,
            member_joined: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NotificationPrefs {
    #[serde(default)]
    pub alerts: AlertPrefs,
    #[serde(default)]
    pub devices: DevicePrefs,
    #[serde(default)]
    pub circles: CirclePrefs,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub proof: Proof,
}

impl NotificationPrefs {
    pub fn create_signed_default(node_id: &str) -> NotifyResult<Self> {
        let mut prefs = Self {
            sequence: 1,
            ..Self::default()
        };
        prefs.sign_for_node(node_id)?;
        Ok(prefs)
    }

    pub fn allows(&self, kind: NotificationKind) -> bool {
        match kind {
            NotificationKind::AlertHigh => self.alerts.high,
            NotificationKind::AlertMedium => self.alerts.medium,
            NotificationKind::AlertLow => self.alerts.low,
            NotificationKind::DeviceDiscovered => self.devices.new_device,
            NotificationKind::DevicePendingApproval => self.devices.pending_approval,
            NotificationKind::GuardianOffline => self.devices.guardian_offline,
            NotificationKind::CircleNewMessage | NotificationKind::CircleFileShared => {
                self.circles.new_message
            }
            NotificationKind::CircleIncomingCall => self.circles.incoming_call,
            NotificationKind::CircleMemberJoined => self.circles.member_joined,
        }
    }

    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut clone = self.clone();
        clone.proof = Proof::default();
        let value = serde_json::to_value(&clone)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }

    pub fn sign_for_node(&mut self, node_id: &str) -> NotifyResult<()> {
        let record = DidRecord::load(&crate::crl::gossip::engine::did_record_path())?;
        let km = crate::vc::issue::load_runtime_key_manager(node_id)
            .map_err(|error| NotifyError::InvalidProof(format!("key manager: {}", error)))?;
        let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
        let canonical = self.canonical_bytes_for_sign()?;
        doc_sign::sign_in_place_generic(&mut self.proof, &canonical, &km, &vm_ref)?;
        Ok(())
    }

    pub fn verify(&self) -> NotifyResult<()> {
        let proof = &self.proof;
        if proof.verification_method.trim().is_empty() || proof.proof_value.trim().is_empty() {
            return Err(NotifyError::InvalidProof("missing proof fields".into()));
        }

        let doc = doc_persistence::load_self()?.ok_or(NotifyError::MissingSelfDocument)?;
        let vm = doc
            .verification_method
            .iter()
            .find(|vm| vm.id == proof.verification_method)
            .ok_or_else(|| {
                NotifyError::InvalidProof(format!(
                    "verification method {} not found",
                    proof.verification_method
                ))
            })?;

        let x = general_purpose::URL_SAFE_NO_PAD
            .decode(&vm.public_key_jwk.x)
            .map_err(|error| NotifyError::InvalidProof(format!("jwk.x decode: {}", error)))?;
        let y = general_purpose::URL_SAFE_NO_PAD
            .decode(&vm.public_key_jwk.y)
            .map_err(|error| NotifyError::InvalidProof(format!("jwk.y decode: {}", error)))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(NotifyError::InvalidProof(format!(
                "unexpected jwk coordinate lengths x={} y={}",
                x.len(),
                y.len()
            )));
        }

        let mut raw = Vec::with_capacity(65);
        raw.push(0x04);
        raw.extend_from_slice(&x);
        raw.extend_from_slice(&y);

        let signature = general_purpose::STANDARD
            .decode(&proof.proof_value)
            .map_err(|error| NotifyError::InvalidProof(format!("proof decode: {}", error)))?;
        let canonical = self.canonical_bytes_for_sign()?;
        let digest = Sha256::digest(&canonical);
        doc_sign::ecdsa_p256_verify_der_or_raw(&raw, &digest, &signature)?;
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> NotifyResult<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }

        let bytes = std::fs::read(path)?;
        if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Ok(None);
        }

        let prefs: Self = serde_json::from_slice(&bytes)?;
        prefs.verify()?;
        Ok(Some(prefs))
    }

    pub fn save_atomic(&self, path: &Path) -> NotifyResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = serde_json::to_vec_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

fn sort_json_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = std::collections::BTreeMap::new();
            for (key, entry) in map {
                sorted.insert(key.clone(), sort_json_keys(entry));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(entries) => {
            serde_json::Value::Array(entries.iter().map(sort_json_keys).collect())
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn allows_maps_every_kind_to_its_pref_bucket() {
        let mut prefs = NotificationPrefs::default();
        assert!(prefs.allows(NotificationKind::AlertHigh));
        assert!(prefs.allows(NotificationKind::AlertMedium));
        assert!(prefs.allows(NotificationKind::AlertLow));
        assert!(prefs.allows(NotificationKind::DeviceDiscovered));
        assert!(prefs.allows(NotificationKind::DevicePendingApproval));
        assert!(prefs.allows(NotificationKind::GuardianOffline));
        assert!(prefs.allows(NotificationKind::CircleNewMessage));
        assert!(prefs.allows(NotificationKind::CircleIncomingCall));
        assert!(prefs.allows(NotificationKind::CircleMemberJoined));
        assert!(prefs.allows(NotificationKind::CircleFileShared));

        prefs.alerts.medium = false;
        prefs.devices.new_device = false;
        prefs.circles.member_joined = false;
        assert!(!prefs.allows(NotificationKind::AlertMedium));
        assert!(!prefs.allows(NotificationKind::DeviceDiscovered));
        assert!(!prefs.allows(NotificationKind::CircleMemberJoined));
        // CircleFileShared shares the new_message bucket, not member_joined.
        assert!(prefs.allows(NotificationKind::CircleFileShared));
    }

    #[test]
    fn canonical_bytes_for_sign_ignore_proof_but_detect_field_changes() {
        let mut prefs = NotificationPrefs {
            sequence: 1,
            ..NotificationPrefs::default()
        };
        let baseline = prefs.canonical_bytes_for_sign().expect("canonical");

        prefs.proof = Proof {
            verification_method: "did:guardian:owner#dkp-v1".to_string(),
            proof_value: "signature".to_string(),
            ..Proof::default()
        };
        assert_eq!(
            baseline,
            prefs.canonical_bytes_for_sign().expect("canonical")
        );

        prefs.sequence = 2;
        assert_ne!(
            baseline,
            prefs.canonical_bytes_for_sign().expect("canonical")
        );
    }

    #[test]
    fn verify_rejects_empty_proof_without_touching_disk() {
        let prefs = NotificationPrefs::default();
        let err = prefs.verify().unwrap_err();
        assert!(matches!(err, NotifyError::InvalidProof(_)));
    }

    #[test]
    fn sort_json_keys_orders_nested_objects_and_arrays() {
        let value = serde_json::json!({
            "b": 1,
            "a": {"z": 1, "y": 2},
            "c": [{"b": 1, "a": 2}]
        });
        let sorted = sort_json_keys(&value);
        let rendered = serde_json::to_string(&sorted).unwrap();
        assert_eq!(rendered, r#"{"a":{"y":2,"z":1},"b":1,"c":[{"a":2,"b":1}]}"#);
    }
}
