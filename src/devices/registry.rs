use crate::devices::errors::{DevicesError, DevicesResult};
use crate::devices::model::DeviceRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRegistry {
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub devices: BTreeMap<String, DeviceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AddManualDevice {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DevicePatch {
    #[serde(default)]
    pub display_name: Option<Option<String>>,
    #[serde(default)]
    pub monitoring_enabled: Option<bool>,
    #[serde(default)]
    pub notes: Option<Option<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RejectDeviceRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

impl DeviceRegistry {
    pub async fn load(path: &Path) -> DevicesResult<Self> {
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    version: 1,
                    ..Self::default()
                });
            }
            Err(err) => return Err(err.into()),
        };
        let registry: Self = serde_json::from_slice(&bytes)?;
        if !registry.verify_signature() {
            return Err(DevicesError::TamperedRegistry);
        }
        Ok(registry)
    }

    pub async fn save_atomic(&mut self, path: &Path) -> DevicesResult<()> {
        self.version = 1;
        self.signature = Some(self.content_signature()?);
        let bytes = serde_json::to_vec_pretty(self)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = path.with_extension("json.tmp");
        tokio::fs::write(&tmp, bytes).await?;
        tokio::fs::rename(tmp, path).await?;
        Ok(())
    }

    pub fn insert_manual(&mut self, request: AddManualDevice) -> DevicesResult<DeviceRecord> {
        if request.ip.as_deref().unwrap_or("").trim().is_empty()
            && request.mac.as_deref().unwrap_or("").trim().is_empty()
        {
            return Err(DevicesError::Invalid(
                "manual device requires ip or mac".into(),
            ));
        }
        let device_id = manual_device_id(request.ip.as_deref(), request.mac.as_deref());
        let record = DeviceRecord::new_manual(
            device_id.clone(),
            clean_optional(request.display_name),
            clean_optional(request.ip),
            clean_optional(request.mac).map(|mac| mac.to_ascii_uppercase()),
            clean_optional(request.manufacturer),
            clean_optional(request.notes),
        );
        self.devices.insert(device_id, record.clone());
        Ok(record)
    }

    pub fn patch(&mut self, device_id: &str, patch: DevicePatch) -> DevicesResult<DeviceRecord> {
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(DevicesError::NotFound)?;
        if let Some(display_name) = patch.display_name {
            record.display_name = clean_optional(display_name);
        }
        if let Some(monitoring_enabled) = patch.monitoring_enabled {
            record.monitoring_enabled = monitoring_enabled;
        }
        if let Some(notes) = patch.notes {
            record.notes = clean_optional(notes);
        }
        record.touch();
        Ok(record.clone())
    }

    pub fn mark_blocked(&mut self, device_id: &str, blocked: bool) -> DevicesResult<DeviceRecord> {
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(DevicesError::NotFound)?;
        record.blocked = blocked;
        record.touch();
        Ok(record.clone())
    }

    pub fn reject(
        &mut self,
        device_id: &str,
        reason: Option<String>,
    ) -> DevicesResult<DeviceRecord> {
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(DevicesError::NotFound)?;
        record.rejected = true;
        record.rejection_reason = clean_optional(reason);
        record.blocked = true;
        record.touch();
        Ok(record.clone())
    }

    pub fn clear_rejection_for_mac(&mut self, mac: &str) -> Option<DeviceRecord> {
        let normalized = normalize_mac_for_match(mac);
        let record = self.devices.values_mut().find(|record| {
            record
                .mac
                .as_deref()
                .map(normalize_mac_for_match)
                .is_some_and(|record_mac| record_mac == normalized)
        })?;
        record.rejected = false;
        record.rejection_reason = None;
        record.blocked = false;
        record.touch();
        Some(record.clone())
    }

    pub fn remove(&mut self, device_id: &str) -> bool {
        self.devices.remove(device_id).is_some()
    }

    fn verify_signature(&self) -> bool {
        match &self.signature {
            Some(signature) => self
                .content_signature()
                .map(|expected| expected == *signature)
                .unwrap_or(false),
            None => self.devices.is_empty(),
        }
    }

    fn content_signature(&self) -> DevicesResult<String> {
        let mut clone = self.clone();
        clone.signature = None;
        let bytes = serde_json::to_vec(&clone)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

pub fn manual_device_id(ip: Option<&str>, mac: Option<&str>) -> String {
    let identity = mac
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
        .or_else(|| {
            ip.map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut hasher = Sha256::new();
    hasher.update(identity.as_bytes());
    format!("manual-{}", hex::encode(&hasher.finalize()[..8]))
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_mac_for_match(mac: &str) -> String {
    mac.chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(|ch| ch.to_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_rejects_tampering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("registry.json");
        let mut registry = DeviceRegistry::default();
        registry
            .insert_manual(AddManualDevice {
                ip: Some("192.168.1.77".into()),
                display_name: Some("Lab Printer".into()),
                ..Default::default()
            })
            .expect("insert manual");
        registry.save_atomic(&path).await.expect("save");

        let mut value: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.expect("read")).expect("json");
        value["devices"]
            .as_object_mut()
            .expect("devices")
            .values_mut()
            .next()
            .expect("record")["display_name"] = serde_json::json!("Tampered");
        tokio::fs::write(&path, serde_json::to_vec_pretty(&value).expect("json"))
            .await
            .expect("write tampered");

        assert!(matches!(
            DeviceRegistry::load(&path).await,
            Err(DevicesError::TamperedRegistry)
        ));
    }

    #[tokio::test]
    async fn load_missing_registry_returns_version_one_empty_registry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = DeviceRegistry::load(&dir.path().join("missing.json"))
            .await
            .expect("load missing");
        assert_eq!(registry.version, 1);
        assert!(registry.devices.is_empty());
        assert!(registry.signature.is_none());
    }

    #[tokio::test]
    async fn save_atomic_creates_parent_sets_version_and_signature_and_removes_tmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("registry.json");
        let mut registry = DeviceRegistry::default();
        registry
            .insert_manual(AddManualDevice {
                ip: Some("192.168.1.2".into()),
                ..Default::default()
            })
            .expect("insert");

        registry.save_atomic(&path).await.expect("save");
        assert_eq!(registry.version, 1);
        assert!(registry.signature.is_some());
        assert!(path.exists());
        assert!(!path.with_extension("json.tmp").exists());
        assert!(DeviceRegistry::load(&path).await.expect("reload").verify_signature());
    }

    #[tokio::test]
    async fn load_malformed_json_returns_json_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("registry.json");
        tokio::fs::write(&path, b"{broken").await.expect("write");
        assert!(matches!(
            DeviceRegistry::load(&path).await,
            Err(DevicesError::Json(_))
        ));
    }

    #[tokio::test]
    async fn unsigned_empty_registry_loads_but_unsigned_nonempty_registry_is_tampered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty_path = dir.path().join("empty.json");
        tokio::fs::write(&empty_path, br#"{"version":1,"devices":{}}"#)
            .await
            .expect("write empty");
        assert!(DeviceRegistry::load(&empty_path).await.is_ok());

        let full_path = dir.path().join("full.json");
        tokio::fs::write(
            &full_path,
            br#"{"version":1,"devices":{"dev":{"device_id":"dev","manual":true,"created_at":"now","updated_at":"now"}}}"#,
        )
        .await
        .expect("write nonempty");
        assert!(matches!(
            DeviceRegistry::load(&full_path).await,
            Err(DevicesError::TamperedRegistry)
        ));
    }

    #[test]
    fn insert_manual_requires_ip_or_mac() {
        let mut registry = DeviceRegistry::default();
        let err = registry
            .insert_manual(AddManualDevice {
                ip: Some(" ".into()),
                mac: Some("\t".into()),
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, DevicesError::Invalid(_)));
        assert!(registry.devices.is_empty());
    }

    #[test]
    fn insert_manual_trims_optional_fields_and_uppercases_mac() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                display_name: Some("  Printer  ".into()),
                ip: Some(" 192.168.1.9 ".into()),
                mac: Some(" aa:bb:cc:dd:ee:ff ".into()),
                manufacturer: Some("  Acme  ".into()),
                notes: Some("  Lab  ".into()),
            })
            .expect("insert");
        assert_eq!(record.display_name.as_deref(), Some("Printer"));
        assert_eq!(record.ip.as_deref(), Some("192.168.1.9"));
        assert_eq!(record.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(record.manufacturer.as_deref(), Some("Acme"));
        assert_eq!(record.notes.as_deref(), Some("Lab"));
        assert!(record.manual);
        assert!(record.monitoring_enabled);
    }

    #[test]
    fn insert_manual_empty_optional_strings_are_removed() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                ip: Some("10.0.0.8".into()),
                display_name: Some(" ".into()),
                manufacturer: Some("\n".into()),
                notes: Some("\t".into()),
                ..Default::default()
            })
            .expect("insert");
        assert!(record.display_name.is_none());
        assert!(record.manufacturer.is_none());
        assert!(record.notes.is_none());
    }

    #[test]
    fn manual_device_id_prefers_mac_over_ip_and_is_case_normalized() {
        let upper = manual_device_id(Some("192.168.1.9"), Some("AA:BB"));
        let lower = manual_device_id(Some("10.0.0.1"), Some("aa:bb"));
        assert_eq!(upper, lower);
        assert!(upper.starts_with("manual-"));
    }

    #[test]
    fn manual_device_id_uses_trimmed_ip_when_mac_is_missing() {
        assert_eq!(
            manual_device_id(Some(" 192.168.1.9 "), None),
            manual_device_id(Some("192.168.1.9"), Some(" "))
        );
    }

    #[test]
    fn manual_device_id_generates_uuid_identity_when_ip_and_mac_are_absent() {
        let first = manual_device_id(None, None);
        let second = manual_device_id(Some(" "), Some(""));
        assert!(first.starts_with("manual-"));
        assert!(second.starts_with("manual-"));
        assert_ne!(first, second);
    }

    #[test]
    fn patch_updates_only_present_fields_and_can_clear_optional_values() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                ip: Some("10.0.0.2".into()),
                display_name: Some("Old".into()),
                notes: Some("old notes".into()),
                ..Default::default()
            })
            .expect("insert");
        let patched = registry
            .patch(
                &record.device_id,
                DevicePatch {
                    display_name: Some(Some(" New ".into())),
                    monitoring_enabled: Some(false),
                    notes: Some(None),
                },
            )
            .expect("patch");
        assert_eq!(patched.display_name.as_deref(), Some("New"));
        assert!(!patched.monitoring_enabled);
        assert!(patched.notes.is_none());
    }

    #[test]
    fn patch_missing_device_returns_not_found() {
        let mut registry = DeviceRegistry::default();
        assert!(matches!(
            registry.patch("missing", DevicePatch::default()),
            Err(DevicesError::NotFound)
        ));
    }

    #[test]
    fn mark_blocked_sets_and_clears_blocked_flag() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                mac: Some("AA:BB".into()),
                ..Default::default()
            })
            .expect("insert");
        assert!(registry.mark_blocked(&record.device_id, true).unwrap().blocked);
        assert!(!registry
            .mark_blocked(&record.device_id, false)
            .unwrap()
            .blocked);
    }

    #[test]
    fn mark_blocked_missing_device_returns_not_found() {
        let mut registry = DeviceRegistry::default();
        assert!(matches!(
            registry.mark_blocked("missing", true),
            Err(DevicesError::NotFound)
        ));
    }

    #[test]
    fn reject_sets_rejected_reason_and_blocks_device() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                mac: Some("AA:BB:CC".into()),
                ..Default::default()
            })
            .expect("insert");
        let rejected = registry
            .reject(&record.device_id, Some("  unknown device  ".into()))
            .expect("reject");
        assert!(rejected.rejected);
        assert!(rejected.blocked);
        assert_eq!(rejected.rejection_reason.as_deref(), Some("unknown device"));
    }

    #[test]
    fn reject_missing_device_returns_not_found() {
        let mut registry = DeviceRegistry::default();
        assert!(matches!(
            registry.reject("missing", None),
            Err(DevicesError::NotFound)
        ));
    }

    #[test]
    fn clear_rejection_for_mac_matches_punctuation_and_case() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                ..Default::default()
            })
            .expect("insert");
        registry
            .reject(&record.device_id, Some("blocked".into()))
            .expect("reject");
        let cleared = registry
            .clear_rejection_for_mac("AA-BB-CC-DD-EE-FF")
            .expect("clear");
        assert!(!cleared.rejected);
        assert!(!cleared.blocked);
        assert!(cleared.rejection_reason.is_none());
    }

    #[test]
    fn clear_rejection_for_missing_mac_returns_none() {
        let mut registry = DeviceRegistry::default();
        assert!(registry.clear_rejection_for_mac("AA:BB").is_none());
    }

    #[test]
    fn remove_returns_true_once_and_false_after_device_is_gone() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                ip: Some("10.0.0.3".into()),
                ..Default::default()
            })
            .expect("insert");
        assert!(registry.remove(&record.device_id));
        assert!(!registry.remove(&record.device_id));
    }
}
