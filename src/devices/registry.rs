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

    pub fn approve(&mut self, device_id: &str) -> DevicesResult<DeviceRecord> {
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(DevicesError::NotFound)?;
        record.rejected = false;
        record.rejection_reason = None;
        record.blocked = false;
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

    #[test]
    fn approve_clears_rejection_reason_and_block() {
        let mut registry = DeviceRegistry::default();
        let record = registry
            .insert_manual(AddManualDevice {
                ip: Some("192.168.1.77".into()),
                ..Default::default()
            })
            .expect("insert manual");
        registry
            .reject(&record.device_id, Some("Unknown device".into()))
            .expect("reject");

        let approved = registry.approve(&record.device_id).expect("approve");
        assert!(!approved.rejected);
        assert!(!approved.blocked);
        assert_eq!(approved.rejection_reason, None);
    }

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
}
