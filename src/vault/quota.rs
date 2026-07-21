use crate::vault::errors::VaultError;
use crate::vault::namespace::VaultNamespace;
use crate::vault::persistence;
use crate::vault::VaultConfig;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

pub const CAPACITY_ENV: &str = "SGX_VAULT_CAPACITY_BYTES";
pub const PERSONAL_QUOTA_ENV: &str = "SGX_VAULT_PERSONAL_QUOTA_BYTES";
pub const CIRCLE_QUOTA_ENV: &str = "SGX_VAULT_CIRCLE_QUOTA_BYTES";
pub const DEFAULT_CAPACITY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultQuota {
    pub capacity_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultQuotaSettings {
    pub personal_quota_bytes: u64,
    pub circle_quota_bytes: u64,
}

impl VaultQuotaSettings {
    fn validate(&self) -> Result<(), VaultError> {
        if self.personal_quota_bytes == 0 {
            return Err(VaultError::InvalidStructure(
                "vault personal quota must be greater than zero".to_string(),
            ));
        }
        if self.circle_quota_bytes == 0 {
            return Err(VaultError::InvalidStructure(
                "vault Circle quota must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    fn quota_bytes_for_namespace(&self, namespace: &VaultNamespace) -> u64 {
        match namespace {
            VaultNamespace::Personal => self.personal_quota_bytes,
            VaultNamespace::Circle(_) => self.circle_quota_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceQuota {
    pub namespace: VaultNamespace,
    pub quota_bytes: u64,
    pub used_bytes: u64,
}

impl NamespaceQuota {
    pub fn remaining_bytes(&self) -> u64 {
        self.quota_bytes.saturating_sub(self.used_bytes)
    }

    pub fn usage_percent(&self) -> f64 {
        if self.quota_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f64 / self.quota_bytes as f64) * 100.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QuotaReservation {
    namespace_key: String,
    required_bytes: u64,
}

pub fn capacity_bytes() -> u64 {
    env_capacity_bytes(CAPACITY_ENV).unwrap_or(DEFAULT_CAPACITY_BYTES)
}

pub fn default_settings() -> VaultQuotaSettings {
    let fallback = capacity_bytes();
    VaultQuotaSettings {
        personal_quota_bytes: env_capacity_bytes(PERSONAL_QUOTA_ENV).unwrap_or(fallback),
        circle_quota_bytes: env_capacity_bytes(CIRCLE_QUOTA_ENV).unwrap_or(fallback),
    }
}

pub async fn load_settings(config: &VaultConfig) -> Result<VaultQuotaSettings, VaultError> {
    let path = persistence::quota_settings_path(config);
    if let Some(settings) = persistence::read_json_if_exists::<VaultQuotaSettings>(&path).await? {
        settings.validate()?;
        return Ok(settings);
    }

    let settings = default_settings();
    save_settings(config, &settings).await?;
    Ok(settings)
}

pub async fn save_settings(
    config: &VaultConfig,
    settings: &VaultQuotaSettings,
) -> Result<(), VaultError> {
    settings.validate()?;
    persistence::save_json_pretty(&persistence::quota_settings_path(config), settings).await
}

pub fn estimate_cipher_size(size_plain: u64, chunk_bytes: u32) -> u64 {
    if size_plain == 0 {
        return 0;
    }
    let chunk_count = size_plain.div_ceil(chunk_bytes as u64);
    size_plain + chunk_count * 20
}

pub async fn compute(config: &VaultConfig) -> Result<VaultQuota, VaultError> {
    let settings = load_settings(config).await?;
    let records = persistence::list_records(config, None).await?;
    let used_bytes = records.iter().map(|record| record.size_cipher).sum();
    let mut namespaces = BTreeSet::new();
    namespaces.insert(VaultNamespace::PERSONAL_STORAGE_KEY.to_string());
    for record in &records {
        namespaces.insert(record.namespace_key());
    }

    let capacity_bytes = namespaces
        .into_iter()
        .try_fold(0_u64, |total, namespace_key| {
            let namespace = VaultNamespace::parse(&namespace_key)?;
            Ok::<u64, VaultError>(
                total.saturating_add(settings.quota_bytes_for_namespace(&namespace)),
            )
        })?;

    Ok(VaultQuota {
        capacity_bytes,
        used_bytes,
    })
}

pub async fn compute_namespace(
    config: &VaultConfig,
    namespace: &VaultNamespace,
) -> Result<NamespaceQuota, VaultError> {
    let settings = load_settings(config).await?;
    let used_bytes = persistence::list_records(config, Some(&namespace.storage_key()))
        .await?
        .into_iter()
        .map(|record| record.size_cipher)
        .sum();

    Ok(NamespaceQuota {
        namespace: namespace.clone(),
        quota_bytes: settings.quota_bytes_for_namespace(namespace),
        used_bytes,
    })
}

pub async fn configured_quota_bytes(
    config: &VaultConfig,
    namespace: &VaultNamespace,
) -> Result<u64, VaultError> {
    Ok(load_settings(config)
        .await?
        .quota_bytes_for_namespace(namespace))
}

pub async fn ensure_capacity_for_plaintext(
    config: &VaultConfig,
    size_plain: u64,
    chunk_bytes: u32,
) -> Result<NamespaceQuota, VaultError> {
    ensure_namespace_capacity_for_plaintext(
        config,
        &VaultNamespace::Personal,
        size_plain,
        chunk_bytes,
    )
    .await
}

pub async fn ensure_namespace_capacity_for_plaintext(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    size_plain: u64,
    chunk_bytes: u32,
) -> Result<NamespaceQuota, VaultError> {
    let quota = compute_namespace(config, namespace).await?;
    let required_bytes = estimate_cipher_size(size_plain, chunk_bytes);
    let projected = quota.used_bytes.saturating_add(required_bytes);
    if projected > quota.quota_bytes {
        return Err(VaultError::QuotaExceeded {
            capacity_bytes: quota.quota_bytes,
            used_bytes: quota.used_bytes,
            required_bytes,
        });
    }
    Ok(quota)
}

pub(crate) async fn reserve_namespace_capacity_for_plaintext(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    size_plain: u64,
    chunk_bytes: u32,
) -> Result<QuotaReservation, VaultError> {
    let required_bytes = estimate_cipher_size(size_plain, chunk_bytes);
    let namespace_key = namespace.storage_key();
    let _guard = crate::vault::write_lock().lock().await;
    let quota = compute_namespace(config, namespace).await?;
    let reserved_bytes = current_reserved_bytes(&namespace_key);
    let projected = quota
        .used_bytes
        .saturating_add(reserved_bytes)
        .saturating_add(required_bytes);
    if projected > quota.quota_bytes {
        return Err(VaultError::QuotaExceeded {
            capacity_bytes: quota.quota_bytes,
            used_bytes: quota.used_bytes.saturating_add(reserved_bytes),
            required_bytes,
        });
    }

    let mut reservations = reservations()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    reservations
        .entry(namespace_key.clone())
        .and_modify(|value| *value = value.saturating_add(required_bytes))
        .or_insert(required_bytes);

    Ok(QuotaReservation {
        namespace_key,
        required_bytes,
    })
}

pub(crate) fn release_reservation(reservation: &QuotaReservation) {
    let mut reservations = reservations()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(value) = reservations.get_mut(&reservation.namespace_key) {
        *value = value.saturating_sub(reservation.required_bytes);
        if *value == 0 {
            reservations.remove(&reservation.namespace_key);
        }
    }
}

fn current_reserved_bytes(namespace_key: &str) -> u64 {
    reservations()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(namespace_key)
        .copied()
        .unwrap_or(0)
}

fn reservations() -> &'static Mutex<HashMap<String, u64>> {
    static RESERVATIONS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    RESERVATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn env_capacity_bytes(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
}
