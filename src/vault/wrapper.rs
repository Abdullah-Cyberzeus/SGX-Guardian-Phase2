use crate::vault::errors::VaultError;
use crate::vault::model::VaultRecord;
use crate::vault::persistence;
use crate::vault::VaultConfig;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

pub const SOFTWARE_WRAP_SCHEME: &str = "software-hkdf";
pub const SOFTWARE_WRAP_KEY_ID: &str = "software-master-v1";
pub const SE050_WRAP_SCHEME: &str = "se050-rsa-oaep";
pub const DEFAULT_SE050_WRAP_KEY_ID: &str = "0x20000110";
pub const VAULT_DEV_MODE_ENV: &str = "SGX_GUARDIAN_VAULT_DEV_MODE";
const SE050_WRAP_ALGORITHM: &str = "RSA-2048-OAEP";
const SE050_WRAP_RSA_BITS: u16 = 2048;
const SE050_WRAP_ENVELOPE_VERSION: u8 = 1;
const SE050_WRAP_OAEP_HASH: &str = "backend-default";
const SE050_WRAP_OAEP_MGF1_HASH: &str = "backend-default";
const SE050_WRAP_OAEP_LABEL_B64: &str = "";
const SE050_WRAP_PAYLOAD_FORMAT: &str = "raw-dek-32";
const SE050_WRAP_CLI_ALGO: &str = "oaep";
const SE050_WRAP_OAEP_HASH_SHA1_ALIAS: &str = "sha1";
const SE050_LEGACY_V1_HEADER_BYTES: usize = 20;
const SE050_LEGACY_V1_PAYLOAD_BYTES: usize = SE050_LEGACY_V1_HEADER_BYTES + 32;
const SE050_LEGACY_V1_VERSION: u32 = 1;
const SE050_LEGACY_V1_HASH_ID_BACKEND_DEFAULT: u32 = 0;
const SE050_LEGACY_V1_HASH_ID_SHA1: u32 = 1;
const SE050_LEGACY_V1_LABEL_LEN_EMPTY: u32 = 0;
const SE050_LEGACY_V1_DEK_LEN: u32 = 32;

pub trait KeyWrapper {
    fn scheme(&self) -> &'static str;
    fn key_id(&self) -> String;
    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, VaultError>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], VaultError>;
}

#[derive(Debug, Clone)]
pub struct SoftwareWrapper {
    master_key: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct HkdfLen(usize);

impl KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl SoftwareWrapper {
    pub fn from_config(config: &VaultConfig) -> Result<Self, VaultError> {
        let path = persistence::master_key_path(config);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = [0_u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut seed);
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, seed)?;
                std::fs::rename(&tmp, &path)?;
                seed.to_vec()
            }
            Err(error) => return Err(error.into()),
        };

        if bytes.len() != 32 {
            return Err(VaultError::InvalidStructure(format!(
                "software wrapper master key must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut master_key = [0_u8; 32];
        master_key.copy_from_slice(&bytes);
        Ok(Self { master_key })
    }

    fn derive_kek(&self) -> Result<[u8; 32], VaultError> {
        let salt = Salt::new(HKDF_SHA256, b"sgx-guardian-vault-wrapper-v1");
        let prk = salt.extract(&self.master_key);
        let okm = prk
            .expand(&[b"aes-256-gcm-kek"], HkdfLen(32))
            .map_err(|_| VaultError::Crypto("hkdf expand failed".to_string()))?;
        let mut derived = [0_u8; 32];
        okm.fill(&mut derived)
            .map_err(|_| VaultError::Crypto("hkdf fill failed".to_string()))?;
        Ok(derived)
    }

    fn make_key(&self) -> Result<LessSafeKey, VaultError> {
        let kek = self.derive_kek()?;
        let key = UnboundKey::new(&AES_256_GCM, &kek)
            .map_err(|_| VaultError::Crypto("invalid AES-256-GCM key".to_string()))?;
        Ok(LessSafeKey::new(key))
    }
}

impl KeyWrapper for SoftwareWrapper {
    fn scheme(&self) -> &'static str {
        SOFTWARE_WRAP_SCHEME
    }

    fn key_id(&self) -> String {
        SOFTWARE_WRAP_KEY_ID.to_string()
    }

    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
        let mut nonce_bytes = [0_u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = self.make_key()?;

        let mut sealed = dek.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut sealed)
            .map_err(|_| VaultError::Crypto("software wrap seal failed".to_string()))?;

        let mut wrapped = nonce_bytes.to_vec();
        wrapped.extend_from_slice(&sealed);
        Ok(wrapped)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], VaultError> {
        if wrapped.len() < 12 + 16 {
            return Err(VaultError::InvalidStructure(format!(
                "wrapped DEK too short: {}",
                wrapped.len()
            )));
        }
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes.copy_from_slice(&wrapped[..12]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = self.make_key()?;

        let mut sealed = wrapped[12..].to_vec();
        let plain = key
            .open_in_place(nonce, Aad::empty(), &mut sealed)
            .map_err(|_| VaultError::Crypto("software wrap open failed".to_string()))?;
        if plain.len() != 32 {
            return Err(VaultError::InvalidStructure(format!(
                "unwrapped DEK must be 32 bytes, got {}",
                plain.len()
            )));
        }
        let mut dek = [0_u8; 32];
        dek.copy_from_slice(plain);
        Ok(dek)
    }
}

#[derive(Clone)]
pub enum ActiveKeyWrapper {
    Software(SoftwareWrapper),
    Se050(Se050Wrapper),
}

impl KeyWrapper for ActiveKeyWrapper {
    fn scheme(&self) -> &'static str {
        match self {
            Self::Software(wrapper) => wrapper.scheme(),
            Self::Se050(wrapper) => wrapper.scheme(),
        }
    }

    fn key_id(&self) -> String {
        match self {
            Self::Software(wrapper) => wrapper.key_id(),
            Self::Se050(wrapper) => wrapper.key_id(),
        }
    }

    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
        match self {
            Self::Software(wrapper) => wrapper.wrap(dek),
            Self::Se050(wrapper) => wrapper.wrap(dek),
        }
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], VaultError> {
        match self {
            Self::Software(wrapper) => wrapper.unwrap(wrapped),
            Self::Se050(wrapper) => wrapper.unwrap(wrapped),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeProfile {
    Production,
    Docker,
    Ci,
    Development,
}

impl RuntimeProfile {
    fn allows_software_wrapper(self) -> bool {
        !matches!(self, Self::Production)
    }
}

pub fn default_wrapper(config: &VaultConfig) -> Result<ActiveKeyWrapper, VaultError> {
    match runtime_profile() {
        RuntimeProfile::Production => Ok(ActiveKeyWrapper::Se050(Se050Wrapper::from_config(
            config, None,
        )?)),
        RuntimeProfile::Docker | RuntimeProfile::Ci | RuntimeProfile::Development => Ok(
            ActiveKeyWrapper::Software(SoftwareWrapper::from_config(config)?),
        ),
    }
}

pub fn wrapper_for_record(
    config: &VaultConfig,
    record: &VaultRecord,
) -> Result<ActiveKeyWrapper, VaultError> {
    wrapper_for_metadata(config, &record.enc.wrap_scheme, &record.enc.wrap_key_id)
}

pub fn wrapper_for_metadata(
    config: &VaultConfig,
    wrap_scheme: &str,
    wrap_key_id: &str,
) -> Result<ActiveKeyWrapper, VaultError> {
    match wrap_scheme {
        SOFTWARE_WRAP_SCHEME => {
            if !runtime_profile().allows_software_wrapper() {
                return Err(VaultError::Crypto(
                    "software-hkdf is restricted to Docker, CI, and explicit development mode"
                        .to_string(),
                ));
            }
            if !wrap_key_id.trim().is_empty() && wrap_key_id != SOFTWARE_WRAP_KEY_ID {
                return Err(VaultError::InvalidStructure(format!(
                    "software wrap key id mismatch: expected {}, got {}",
                    SOFTWARE_WRAP_KEY_ID, wrap_key_id
                )));
            }
            Ok(ActiveKeyWrapper::Software(SoftwareWrapper::from_config(
                config,
            )?))
        }
        SE050_WRAP_SCHEME => {
            if wrap_key_id.trim().is_empty() {
                return Err(VaultError::InvalidStructure(
                    "SE050-wrapped records require wrap_key_id".to_string(),
                ));
            }
            Ok(ActiveKeyWrapper::Se050(Se050Wrapper::from_config(
                config,
                Some(wrap_key_id),
            )?))
        }
        other => Err(VaultError::InvalidStructure(format!(
            "unsupported wrap scheme '{}'",
            other
        ))),
    }
}

#[derive(Clone)]
pub struct Se050Wrapper {
    key_id: String,
    backend: Arc<dyn Se050WrapBackend>,
}

impl Se050Wrapper {
    pub fn from_config(
        config: &VaultConfig,
        key_id_hint: Option<&str>,
    ) -> Result<Self, VaultError> {
        let backend = se050_wrap_backend();
        let key_id = {
            let _guard = se050_wrap_init_lock()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            ensure_se050_wrap_key(config, key_id_hint, backend.as_ref())?
        };

        Ok(Self { key_id, backend })
    }
}

impl KeyWrapper for Se050Wrapper {
    fn scheme(&self) -> &'static str {
        SE050_WRAP_SCHEME
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
        let ciphertext = self
            .backend
            .wrap(&self.key_id, &encode_se050_oaep_payload(dek))?;
        serde_json::to_vec(&Se050WrappedDekEnvelope::new(ciphertext)).map_err(Into::into)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], VaultError> {
        let (params, ciphertext) = match Se050WrappedDekEnvelope::decode(wrapped)? {
            Some(envelope) => envelope.into_validated_ciphertext()?,
            None => (default_se050_oaep_parameters(), wrapped.to_vec()),
        };
        let plain = self.backend.unwrap(&self.key_id, &ciphertext)?;
        let normalized = normalize_se050_unwrap_output(&plain)?;
        decode_se050_oaep_payload(&normalized, &params)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Se050WrapMetadata {
    key_id: String,
    algorithm: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Se050WrappedDekEnvelope {
    version: u8,
    oaep_hash: String,
    oaep_mgf1_hash: String,
    oaep_label_b64: String,
    payload_format: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Se050OaepHash {
    Sha1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Se050PayloadFormat {
    RawDek32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Se050OaepParameters {
    hash: Se050OaepHash,
    mgf1_hash: Se050OaepHash,
    payload_format: Se050PayloadFormat,
}

impl Se050WrappedDekEnvelope {
    fn new(ciphertext: Vec<u8>) -> Self {
        Self {
            version: SE050_WRAP_ENVELOPE_VERSION,
            oaep_hash: SE050_WRAP_OAEP_HASH.to_string(),
            oaep_mgf1_hash: SE050_WRAP_OAEP_MGF1_HASH.to_string(),
            oaep_label_b64: SE050_WRAP_OAEP_LABEL_B64.to_string(),
            payload_format: SE050_WRAP_PAYLOAD_FORMAT.to_string(),
            ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Option<Self>, VaultError> {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Ok(None);
        };
        if !text.trim_start().starts_with('{') {
            return Ok(None);
        }
        let envelope = serde_json::from_str(text).map_err(|error| {
            VaultError::InvalidStructure(format!("invalid SE050 wrapped DEK envelope: {}", error))
        })?;
        Ok(Some(envelope))
    }

    fn into_validated_ciphertext(self) -> Result<(Se050OaepParameters, Vec<u8>), VaultError> {
        if self.version != SE050_WRAP_ENVELOPE_VERSION {
            return Err(VaultError::InvalidStructure(format!(
                "unsupported SE050 wrapped DEK envelope version {}",
                self.version
            )));
        }
        let hash = parse_se050_oaep_hash(&self.oaep_hash, "hash")?;
        let mgf1_hash = parse_se050_oaep_hash(&self.oaep_mgf1_hash, "MGF1 hash")?;
        let label = general_purpose::STANDARD.decode(&self.oaep_label_b64)?;
        if !label.is_empty() {
            return Err(VaultError::InvalidStructure(
                "SE050 OAEP label mismatch".to_string(),
            ));
        }
        let payload_format = parse_se050_payload_format(&self.payload_format)?;
        let ciphertext = general_purpose::STANDARD
            .decode(self.ciphertext_b64)
            .map_err(VaultError::from)?;
        Ok((
            Se050OaepParameters {
                hash,
                mgf1_hash,
                payload_format,
            },
            ciphertext,
        ))
    }
}

fn encode_se050_oaep_payload(dek: &[u8; 32]) -> Vec<u8> {
    dek.to_vec()
}

fn default_se050_oaep_parameters() -> Se050OaepParameters {
    Se050OaepParameters {
        hash: Se050OaepHash::Sha1,
        mgf1_hash: Se050OaepHash::Sha1,
        payload_format: Se050PayloadFormat::RawDek32,
    }
}

fn parse_se050_oaep_hash(value: &str, field: &str) -> Result<Se050OaepHash, VaultError> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        SE050_WRAP_OAEP_HASH | SE050_WRAP_OAEP_HASH_SHA1_ALIAS => Ok(Se050OaepHash::Sha1),
        other => Err(VaultError::InvalidStructure(format!(
            "unsupported SE050 OAEP {} '{}'",
            field, other
        ))),
    }
}

fn parse_se050_payload_format(value: &str) -> Result<Se050PayloadFormat, VaultError> {
    match value {
        SE050_WRAP_PAYLOAD_FORMAT => Ok(Se050PayloadFormat::RawDek32),
        other => Err(VaultError::InvalidStructure(format!(
            "unsupported SE050 payload format '{}'",
            other
        ))),
    }
}

fn decode_se050_oaep_payload(
    payload: &[u8],
    params: &Se050OaepParameters,
) -> Result<[u8; 32], VaultError> {
    if payload.len() != 32 {
        if let Some(dek) = decode_legacy_buggy_se050_payload_v1(payload, params) {
            return Ok(dek);
        }
        if payload.len() == SE050_LEGACY_V1_PAYLOAD_BYTES {
            return Err(VaultError::InvalidStructure(
                "SE050 OAEP payload used malformed legacy v1 52-byte framing".to_string(),
            ));
        }
        return Err(VaultError::InvalidStructure(format!(
            "SE050 OAEP payload must be the raw 32-byte DEK, got {} bytes",
            payload.len()
        )));
    }
    let mut dek = [0_u8; 32];
    dek.copy_from_slice(payload);
    Ok(dek)
}

fn decode_legacy_buggy_se050_payload_v1(
    payload: &[u8],
    params: &Se050OaepParameters,
) -> Option<[u8; 32]> {
    if payload.len() != SE050_LEGACY_V1_PAYLOAD_BYTES
        || params.payload_format != Se050PayloadFormat::RawDek32
    {
        return None;
    }

    for reader in [
        u32::from_le_bytes as fn([u8; 4]) -> u32,
        u32::from_be_bytes as fn([u8; 4]) -> u32,
    ] {
        let version = reader(payload[0..4].try_into().ok()?);
        let hash_id = reader(payload[4..8].try_into().ok()?);
        let mgf1_hash_id = reader(payload[8..12].try_into().ok()?);
        let label_len = reader(payload[12..16].try_into().ok()?);
        let dek_len = reader(payload[16..20].try_into().ok()?);
        if version != SE050_LEGACY_V1_VERSION
            || !legacy_hash_id_matches(hash_id, params.hash)
            || !legacy_hash_id_matches(mgf1_hash_id, params.mgf1_hash)
            || label_len != SE050_LEGACY_V1_LABEL_LEN_EMPTY
            || dek_len != SE050_LEGACY_V1_DEK_LEN
        {
            continue;
        }
        let mut dek = [0_u8; 32];
        dek.copy_from_slice(&payload[SE050_LEGACY_V1_HEADER_BYTES..]);
        return Some(dek);
    }

    None
}

fn legacy_hash_id_matches(value: u32, expected: Se050OaepHash) -> bool {
    match expected {
        Se050OaepHash::Sha1 => matches!(
            value,
            SE050_LEGACY_V1_HASH_ID_BACKEND_DEFAULT | SE050_LEGACY_V1_HASH_ID_SHA1
        ),
    }
}

fn env_true(name: &str) -> bool {
    std::env::var_os(name)
        .map(|value| {
            !matches!(
                value.to_string_lossy().trim().to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "off"
            )
        })
        .unwrap_or(false)
}

pub(crate) trait Se050WrapBackend: Send + Sync {
    fn slot_exists(&self, key_id: &str) -> Result<bool, VaultError>;
    fn provision_key(&self, key_id: &str) -> Result<(), VaultError>;
    fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, VaultError>;
    fn unwrap(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>, VaultError>;
}

#[derive(Default)]
struct SssCliSe050WrapBackend {
    config: crate::secure_element::config::SeConfig,
}

impl SssCliSe050WrapBackend {
    fn connect_cli(&self) -> Result<crate::secure_element::ssscli::SssCli, VaultError> {
        let cli = crate::secure_element::ssscli::SssCli::new(self.config.clone());
        cli.connect().map_err(se050_wrap_error)?;
        Ok(cli)
    }
}

impl Se050WrapBackend for SssCliSe050WrapBackend {
    fn slot_exists(&self, key_id: &str) -> Result<bool, VaultError> {
        crate::secure_element::safe_mode::guard_crypto_operation("vault wrap key probe")
            .map_err(se050_wrap_error)?;
        let storage = crate::secure_element::key_storage::SeKeyStorage::new(&self.config)
            .map_err(se050_wrap_error)?;
        let id_list = storage.list_slots().map_err(se050_wrap_error)?;
        Ok(id_list.to_uppercase().contains(&key_id.to_uppercase()))
    }

    fn provision_key(&self, key_id: &str) -> Result<(), VaultError> {
        crate::secure_element::safe_mode::guard_crypto_operation("vault wrap key provision")
            .map_err(se050_wrap_error)?;
        let cli = self.connect_cli()?;
        cli.generate_rsa_key(key_id, SE050_WRAP_RSA_BITS)
            .map_err(se050_wrap_error)?;
        Ok(())
    }

    fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, VaultError> {
        crate::secure_element::safe_mode::guard_crypto_operation("vault dek wrap")
            .map_err(se050_wrap_error)?;
        let cli = self.connect_cli()?;
        with_temp_io("vault_wrap", plain, |input, output| {
            cli.encrypt(key_id, input, output, SE050_WRAP_CLI_ALGO)
                .map_err(se050_wrap_error)?;
            Ok(())
        })
    }

    fn unwrap(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>, VaultError> {
        crate::secure_element::safe_mode::guard_crypto_operation("vault dek unwrap")
            .map_err(se050_wrap_error)?;
        let cli = self.connect_cli()?;
        with_temp_io("vault_unwrap", wrapped, |input, output| {
            cli.decrypt(key_id, input, output, SE050_WRAP_CLI_ALGO)
                .map_err(se050_wrap_error)?;
            Ok(())
        })
    }
}

fn runtime_profile() -> RuntimeProfile {
    #[cfg(test)]
    if let Some(profile) = test_runtime_profile_override()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .to_owned()
    {
        return profile;
    }

    if std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some() {
        RuntimeProfile::Ci
    } else if Path::new("/.dockerenv").exists() || std::env::var_os("container").is_some() {
        RuntimeProfile::Docker
    } else if env_true(VAULT_DEV_MODE_ENV) || env_true("SGX_FORCE_SOFTWARE_KEYS") {
        RuntimeProfile::Development
    } else {
        RuntimeProfile::Production
    }
}

#[cfg(test)]
pub(crate) fn test_encode_legacy_buggy_se050_payload_v1(dek: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SE050_LEGACY_V1_PAYLOAD_BYTES);
    payload.extend_from_slice(&SE050_LEGACY_V1_VERSION.to_le_bytes());
    payload.extend_from_slice(&SE050_LEGACY_V1_HASH_ID_BACKEND_DEFAULT.to_le_bytes());
    payload.extend_from_slice(&SE050_LEGACY_V1_HASH_ID_BACKEND_DEFAULT.to_le_bytes());
    payload.extend_from_slice(&SE050_LEGACY_V1_LABEL_LEN_EMPTY.to_le_bytes());
    payload.extend_from_slice(&SE050_LEGACY_V1_DEK_LEN.to_le_bytes());
    payload.extend_from_slice(dek);
    payload
}

#[cfg(test)]
pub(crate) fn test_encode_ssscli_utf8_marshaled_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|byte| char::from_u32(*byte as u32).expect("valid byte code point"))
        .collect::<String>()
        .into_bytes()
}

fn ensure_se050_wrap_key(
    config: &VaultConfig,
    key_id_hint: Option<&str>,
    backend: &dyn Se050WrapBackend,
) -> Result<String, VaultError> {
    let metadata_path = se050_wrap_metadata_path(config);
    let requested_key_id = key_id_hint
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_SE050_WRAP_KEY_ID)
        .to_string();

    if let Some(metadata) = load_se050_wrap_metadata(&metadata_path)? {
        if requested_key_id != metadata.key_id {
            return Err(VaultError::InvalidStructure(format!(
                "SE050 wrap key metadata mismatch: expected {}, got {}",
                metadata.key_id, requested_key_id
            )));
        }
        if !backend.slot_exists(&metadata.key_id)? {
            return Err(VaultError::Crypto(format!(
                "SE050 vault wrap key {} missing from hardware",
                metadata.key_id
            )));
        }
        return Ok(metadata.key_id);
    }

    if backend.slot_exists(&requested_key_id)? {
        save_se050_wrap_metadata(&metadata_path, &requested_key_id)?;
        return Ok(requested_key_id);
    }

    if key_id_hint.is_some() {
        return Err(VaultError::Crypto(format!(
            "SE050 vault wrap key {} missing from hardware",
            requested_key_id
        )));
    }

    backend.provision_key(&requested_key_id)?;
    save_se050_wrap_metadata(&metadata_path, &requested_key_id)?;
    Ok(requested_key_id)
}

fn se050_wrap_metadata_path(config: &VaultConfig) -> std::path::PathBuf {
    persistence::wrap_dir(config).join("se050-wrap-key.json")
}

fn load_se050_wrap_metadata(path: &Path) -> Result<Option<Se050WrapMetadata>, VaultError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn save_se050_wrap_metadata(path: &Path, key_id: &str) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let metadata = Se050WrapMetadata {
        key_id: key_id.to_string(),
        algorithm: SE050_WRAP_ALGORITHM.to_string(),
        created_at: Utc::now().to_rfc3339(),
    };
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&metadata)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn normalize_se050_unwrap_output(output: &[u8]) -> Result<Vec<u8>, VaultError> {
    // UTF-8 marshaled output must be checked before the raw-length fast path: a 32-byte DEK
    // with enough bytes >= 0x80 widens to exactly SE050_LEGACY_V1_PAYLOAD_BYTES on the wire,
    // which would otherwise be misread as an (invalid) unmarshaled legacy v1 payload.
    if let Some(recovered) = decode_ssscli_utf8_marshaled_bytes(output)? {
        return Ok(recovered);
    }

    if is_supported_se050_unwrap_payload_len(output.len()) {
        return Ok(output.to_vec());
    }

    if !output.iter().copied().all(is_valid_se050_base64_text_byte) {
        return Err(se050_unwrap_non_text_error(output.len()));
    }

    let text =
        std::str::from_utf8(output).map_err(|_| se050_unwrap_non_text_error(output.len()))?;
    let trimmed = text.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Err(VaultError::InvalidStructure(
            "SE050 unwrap output was empty".to_string(),
        ));
    }

    let decoded = general_purpose::STANDARD.decode(trimmed).map_err(|error| {
        VaultError::InvalidStructure(format!(
            "SE050 unwrap output was neither raw 32/52 bytes nor valid Base64: {}",
            error
        ))
    })?;

    if is_supported_se050_unwrap_payload_len(decoded.len()) {
        return Ok(decoded);
    }

    Err(VaultError::InvalidStructure(format!(
        "SE050 unwrap Base64 decoded to unexpected {} bytes",
        decoded.len()
    )))
}

fn is_supported_se050_unwrap_payload_len(len: usize) -> bool {
    matches!(len, 32 | SE050_LEGACY_V1_PAYLOAD_BYTES)
}

fn se050_unwrap_non_text_error(len: usize) -> VaultError {
    VaultError::InvalidStructure(format!(
        "SE050 unwrap output must be raw 32/52 bytes or Base64 text, got {} bytes of non-text output",
        len
    ))
}

// Upstream ssscli decrypt stringifies each decrypted byte with `chr()` and then writes the
// resulting Python string via UTF-8. Bytes >= 0x80 therefore widen into two-byte UTF-8
// sequences on disk. We only reverse that exact transform when the recovered byte count is a
// supported raw 32-byte DEK or the validated 52-byte legacy payload.
fn decode_ssscli_utf8_marshaled_bytes(output: &[u8]) -> Result<Option<Vec<u8>>, VaultError> {
    let text = match std::str::from_utf8(output) {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };

    let recovered_len = text.chars().count();
    if output.len() <= recovered_len {
        return Ok(None);
    }

    let mut recovered = Vec::with_capacity(recovered_len);
    for ch in text.chars() {
        let value = ch as u32;
        if value > u8::MAX as u32 {
            return Err(VaultError::InvalidStructure(format!(
                "SE050 unwrap UTF-8 output contained unsupported code point U+{:04X}",
                value
            )));
        }
        recovered.push(value as u8);
    }

    if is_supported_se050_unwrap_payload_len(recovered.len()) {
        return Ok(Some(recovered));
    }

    Err(VaultError::InvalidStructure(format!(
        "SE050 unwrap UTF-8 output recovered {} bytes; expected 32 or 52",
        recovered.len()
    )))
}

fn is_valid_se050_base64_text_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'+'
            | b'/'
            | b'='
            | b' '
            | b'\t'
            | b'\r'
            | b'\n'
    )
}

fn with_temp_io<F>(prefix: &str, input: &[u8], f: F) -> Result<Vec<u8>, VaultError>
where
    F: FnOnce(&str, &str) -> Result<(), VaultError>,
{
    let tag = Uuid::new_v4().simple().to_string();
    let input_path = format!("/tmp/guardian_{}_{}_in.bin", prefix, &tag[..8]);
    let output_path = format!("/tmp/guardian_{}_{}_out.bin", prefix, &tag[..8]);

    let result = (|| -> Result<Vec<u8>, VaultError> {
        std::fs::write(&input_path, input)?;
        f(&input_path, &output_path)?;
        Ok(std::fs::read(&output_path)?)
    })();

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&output_path);
    result
}

fn se050_wrap_error(error: impl std::fmt::Display) -> VaultError {
    VaultError::Crypto(format!("SE050 vault wrapper: {}", error))
}

fn se050_wrap_init_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn se050_wrap_backend() -> Arc<dyn Se050WrapBackend> {
    #[cfg(test)]
    if let Some(backend) = test_se050_wrap_backend_override()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
    {
        return Arc::clone(backend);
    }

    Arc::new(SssCliSe050WrapBackend::default())
}

#[cfg(test)]
pub(crate) struct TestRuntimeProfileGuard {
    previous: Option<RuntimeProfile>,
}

#[cfg(test)]
impl Drop for TestRuntimeProfileGuard {
    fn drop(&mut self) {
        let mut slot = test_runtime_profile_override()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *slot = self.previous.take();
    }
}

#[cfg(test)]
pub(crate) fn test_force_runtime_profile(profile: RuntimeProfile) -> TestRuntimeProfileGuard {
    let mut slot = test_runtime_profile_override()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let previous = slot.replace(profile);
    TestRuntimeProfileGuard { previous }
}

#[cfg(test)]
fn test_runtime_profile_override() -> &'static Mutex<Option<RuntimeProfile>> {
    static OVERRIDE: OnceLock<Mutex<Option<RuntimeProfile>>> = OnceLock::new();
    OVERRIDE.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
pub(crate) struct TestSe050WrapBackendGuard {
    previous: Option<Arc<dyn Se050WrapBackend>>,
}

#[cfg(test)]
impl Drop for TestSe050WrapBackendGuard {
    fn drop(&mut self) {
        let mut slot = test_se050_wrap_backend_override()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *slot = self.previous.take();
    }
}

#[cfg(test)]
pub(crate) fn test_override_se050_wrap_backend(
    backend: Arc<dyn Se050WrapBackend>,
) -> TestSe050WrapBackendGuard {
    let mut slot = test_se050_wrap_backend_override()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let previous = slot.replace(backend);
    TestSe050WrapBackendGuard { previous }
}

#[cfg(test)]
fn test_se050_wrap_backend_override() -> &'static Mutex<Option<Arc<dyn Se050WrapBackend>>> {
    static OVERRIDE: OnceLock<Mutex<Option<Arc<dyn Se050WrapBackend>>>> = OnceLock::new();
    OVERRIDE.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_BOARD_SAMPLE_DEK: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
        0x8F, 0x90, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    ];

    #[test]
    fn normalize_se050_unwrap_output_preserves_raw_32_bytes() {
        let raw = [0xA5_u8; 32];
        assert_eq!(normalize_se050_unwrap_output(&raw).unwrap(), raw);
    }

    #[test]
    fn normalize_se050_unwrap_output_preserves_raw_legacy_52_bytes() {
        let raw = test_encode_legacy_buggy_se050_payload_v1(&[0x5A_u8; 32]);
        assert_eq!(normalize_se050_unwrap_output(&raw).unwrap(), raw);
    }

    #[test]
    fn normalize_se050_unwrap_output_decodes_base64_32_with_lf() {
        let raw = [0x11_u8; 32];
        let text = format!("{}\n", general_purpose::STANDARD.encode(raw));
        assert_eq!(normalize_se050_unwrap_output(text.as_bytes()).unwrap(), raw);
    }

    #[test]
    fn normalize_se050_unwrap_output_decodes_base64_32_with_crlf() {
        let raw = [0x22_u8; 32];
        let text = format!("{}\r\n", general_purpose::STANDARD.encode(raw));
        assert_eq!(normalize_se050_unwrap_output(text.as_bytes()).unwrap(), raw);
    }

    #[test]
    fn normalize_se050_unwrap_output_decodes_base64_legacy_52_bytes() {
        let raw = test_encode_legacy_buggy_se050_payload_v1(&[0x33_u8; 32]);
        let text = format!("{}\n", general_purpose::STANDARD.encode(&raw));
        assert_eq!(normalize_se050_unwrap_output(text.as_bytes()).unwrap(), raw);
    }

    #[test]
    fn normalize_se050_unwrap_output_decodes_real_board_49_byte_utf8_sample() {
        let sample = test_encode_ssscli_utf8_marshaled_bytes(&REAL_BOARD_SAMPLE_DEK);
        assert_eq!(sample.len(), 49);
        assert_eq!(
            normalize_se050_unwrap_output(&sample).unwrap(),
            REAL_BOARD_SAMPLE_DEK
        );
    }

    #[test]
    fn normalize_se050_unwrap_output_rejects_raw_31_and_33_bytes() {
        let err31 = normalize_se050_unwrap_output(&[0x10_u8; 31]).unwrap_err();
        assert!(err31.to_string().contains("non-text output"));

        let err33 = normalize_se050_unwrap_output(&[0x10_u8; 33]).unwrap_err();
        assert!(err33.to_string().contains("non-text output"));
    }

    #[test]
    fn normalize_se050_unwrap_output_rejects_malformed_base64() {
        let err = normalize_se050_unwrap_output(b"AA=A\r\n").unwrap_err();
        assert!(err.to_string().contains("valid Base64"));
    }

    #[test]
    fn normalize_se050_unwrap_output_rejects_base64_decoding_to_wrong_length() {
        let text = general_purpose::STANDARD.encode([0x44_u8; 31]);
        let err = normalize_se050_unwrap_output(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("unexpected 31 bytes"));
    }

    #[test]
    fn normalize_se050_unwrap_output_rejects_invalid_text_characters() {
        let err = normalize_se050_unwrap_output(b"not-base64!!!\r\n").unwrap_err();
        assert!(err.to_string().contains("non-text output"));
    }

    #[test]
    fn normalize_se050_unwrap_output_rejects_utf8_marshaled_wrong_length() {
        let sample = test_encode_ssscli_utf8_marshaled_bytes(&[0x80_u8; 31]);
        let err = normalize_se050_unwrap_output(&sample).unwrap_err();
        assert!(err.to_string().contains("recovered 31 bytes"));
    }

    #[test]
    fn normalize_se050_unwrap_output_rejects_utf8_marshaled_non_byte_codepoint() {
        let sample = format!("{}{}", "A".repeat(31), '\u{20AC}').into_bytes();
        let err = normalize_se050_unwrap_output(&sample).unwrap_err();
        assert!(err.to_string().contains("unsupported code point"));
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[derive(Default)]
    struct CountingBackend {
        slot_exists: bool,
        slot_probe_count: Mutex<usize>,
        provision_count: Mutex<usize>,
        wrap_count: Mutex<usize>,
        unwrap_count: Mutex<usize>,
    }

    impl Se050WrapBackend for CountingBackend {
        fn slot_exists(&self, _key_id: &str) -> Result<bool, VaultError> {
            *self
                .slot_probe_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()) += 1;
            Ok(self.slot_exists)
        }

        fn provision_key(&self, _key_id: &str) -> Result<(), VaultError> {
            *self
                .provision_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()) += 1;
            Ok(())
        }

        fn wrap(&self, _key_id: &str, plain: &[u8]) -> Result<Vec<u8>, VaultError> {
            *self
                .wrap_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()) += 1;
            Ok(plain.to_vec())
        }

        fn unwrap(&self, _key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>, VaultError> {
            *self
                .unwrap_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()) += 1;
            Ok(wrapped.to_vec())
        }
    }

    fn temp_config() -> (tempfile::TempDir, VaultConfig) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let config = VaultConfig {
            base_dir: temp.path().join("vault"),
        };
        (temp, config)
    }

    #[tokio::test]
    async fn env_true_accepts_truthy_values_and_rejects_falsey_or_missing_values() {
        let _guard = crate::vault::lock_test_env().await;
        let _missing = EnvVarGuard::remove("SGX_WRAPPER_TEST_ENV_TRUE");
        assert!(!env_true("SGX_WRAPPER_TEST_ENV_TRUE"));

        for value in ["", "0", "false", "False", " OFF "] {
            let _env = EnvVarGuard::set("SGX_WRAPPER_TEST_ENV_TRUE", value);
            assert!(!env_true("SGX_WRAPPER_TEST_ENV_TRUE"), "{value:?}");
        }

        for value in ["1", "true", "yes", "on", "anything"] {
            let _env = EnvVarGuard::set("SGX_WRAPPER_TEST_ENV_TRUE", value);
            assert!(env_true("SGX_WRAPPER_TEST_ENV_TRUE"), "{value:?}");
        }
    }

    #[test]
    fn software_wrapper_creates_persists_and_round_trips_deks() {
        let (_temp, config) = temp_config();
        let wrapper = SoftwareWrapper::from_config(&config).expect("create software wrapper");
        let master_path = persistence::master_key_path(&config);
        assert_eq!(std::fs::read(&master_path).expect("read master").len(), 32);
        assert_eq!(wrapper.scheme(), SOFTWARE_WRAP_SCHEME);
        assert_eq!(wrapper.key_id(), SOFTWARE_WRAP_KEY_ID);

        let dek = [0x42_u8; 32];
        let first = wrapper.wrap(&dek).expect("first wrap");
        let second = wrapper.wrap(&dek).expect("second wrap");
        assert_ne!(first, second, "random nonces should produce different wraps");
        assert_eq!(wrapper.unwrap(&first).expect("unwrap first"), dek);

        let restarted = SoftwareWrapper::from_config(&config).expect("restart wrapper");
        assert_eq!(restarted.unwrap(&second).expect("unwrap after restart"), dek);
    }

    #[test]
    fn software_wrapper_rejects_malformed_master_key_and_wrapped_dek_inputs() {
        let (_temp, config) = temp_config();
        let master_path = persistence::master_key_path(&config);
        std::fs::create_dir_all(master_path.parent().expect("parent")).expect("wrap dir");

        for len in [0_usize, 31, 33] {
            std::fs::write(&master_path, vec![0xA5; len]).expect("write bad master");
            let err = SoftwareWrapper::from_config(&config).expect_err("bad master length");
            assert!(err.to_string().contains("master key must be 32 bytes"));
            assert!(err.to_string().contains(&len.to_string()));
        }

        std::fs::write(&master_path, [0x11_u8; 32]).expect("write valid master");
        let wrapper = SoftwareWrapper::from_config(&config).expect("software wrapper");
        let short = wrapper.unwrap(&[0_u8; 27]).expect_err("short wrapped DEK");
        assert!(short.to_string().contains("wrapped DEK too short"));

        let mut wrapped = wrapper.wrap(&[0x22_u8; 32]).expect("wrap");
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x55;
        let tampered = wrapper.unwrap(&wrapped).expect_err("tampered wrapped DEK");
        assert!(tampered.to_string().contains("software wrap open failed"));
    }

    #[tokio::test]
    async fn wrapper_for_metadata_handles_software_legacy_key_ids_and_unknown_schemes() {
        let _guard = crate::vault::lock_test_env().await;
        let (_temp, config) = temp_config();
        let _profile = test_force_runtime_profile(RuntimeProfile::Docker);

        let blank = wrapper_for_metadata(&config, SOFTWARE_WRAP_SCHEME, "")
            .expect("blank legacy software key id");
        assert_eq!(blank.scheme(), SOFTWARE_WRAP_SCHEME);

        let expected = wrapper_for_metadata(&config, SOFTWARE_WRAP_SCHEME, SOFTWARE_WRAP_KEY_ID)
            .expect("current software key id");
        assert_eq!(expected.key_id(), SOFTWARE_WRAP_KEY_ID);

        let mismatch = match wrapper_for_metadata(&config, SOFTWARE_WRAP_SCHEME, "other") {
            Ok(_) => panic!("mismatched software key id should fail"),
            Err(error) => error,
        };
        assert!(mismatch.to_string().contains("software wrap key id mismatch"));

        let missing_se050_key = match wrapper_for_metadata(&config, SE050_WRAP_SCHEME, " ") {
            Ok(_) => panic!("blank SE050 key id should fail"),
            Err(error) => error,
        };
        assert!(missing_se050_key.to_string().contains("require wrap_key_id"));

        let unknown = match wrapper_for_metadata(&config, "made-up", "key") {
            Ok(_) => panic!("unknown scheme should fail"),
            Err(error) => error,
        };
        assert!(unknown.to_string().contains("unsupported wrap scheme"));
    }

    #[tokio::test]
    async fn se050_wrapper_validates_envelopes_before_backend_unwrap() {
        let _guard = crate::vault::lock_test_env().await;
        let (_temp, config) = temp_config();
        let _profile = test_force_runtime_profile(RuntimeProfile::Production);
        let backend = Arc::new(CountingBackend {
            slot_exists: true,
            ..Default::default()
        });
        let _backend = test_override_se050_wrap_backend(backend.clone());
        let wrapper = default_wrapper(&config).expect("SE050 wrapper");

        for envelope in [
            serde_json::json!({
                "version": 2,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "AA=="
            }),
            serde_json::json!({
                "version": 1,
                "oaep_hash": "sha256",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "AA=="
            }),
            serde_json::json!({
                "version": 1,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "bGFiZWw=",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "AA=="
            }),
            serde_json::json!({
                "version": 1,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "not-raw",
                "ciphertext_b64": "AA=="
            }),
        ] {
            assert!(wrapper.unwrap(envelope.to_string().as_bytes()).is_err());
        }

        let malformed_json = wrapper.unwrap(br#"{"version":"#).unwrap_err();
        assert!(malformed_json
            .to_string()
            .contains("invalid SE050 wrapped DEK envelope"));

        let invalid_ciphertext_b64 = serde_json::json!({
            "version": 1,
            "oaep_hash": "backend-default",
            "oaep_mgf1_hash": "backend-default",
            "oaep_label_b64": "",
            "payload_format": "raw-dek-32",
            "ciphertext_b64": "@@@"
        });
        assert!(wrapper
            .unwrap(invalid_ciphertext_b64.to_string().as_bytes())
            .is_err());

        assert_eq!(
            *backend
                .unwrap_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            0
        );
    }

    #[tokio::test]
    async fn se050_wrapper_uses_existing_or_provisioned_key_metadata_paths() {
        let _guard = crate::vault::lock_test_env().await;

        let (_temp_existing, config_existing) = temp_config();
        let _profile = test_force_runtime_profile(RuntimeProfile::Production);
        let existing_backend = Arc::new(CountingBackend {
            slot_exists: true,
            ..Default::default()
        });
        let _existing_backend = test_override_se050_wrap_backend(existing_backend.clone());
        let existing = default_wrapper(&config_existing).expect("existing key wrapper");
        assert_eq!(existing.key_id(), DEFAULT_SE050_WRAP_KEY_ID);
        assert_eq!(
            *existing_backend
                .provision_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            0
        );
        assert!(persistence::wrap_dir(&config_existing)
            .join("se050-wrap-key.json")
            .exists());
        drop(_existing_backend);

        let (_temp_new, config_new) = temp_config();
        let provision_backend = Arc::new(CountingBackend {
            slot_exists: false,
            ..Default::default()
        });
        let _provision_backend = test_override_se050_wrap_backend(provision_backend.clone());
        let provisioned = default_wrapper(&config_new).expect("provisioned key wrapper");
        assert_eq!(provisioned.key_id(), DEFAULT_SE050_WRAP_KEY_ID);
        assert_eq!(
            *provision_backend
                .provision_count
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            1
        );
    }

    #[test]
    fn with_temp_io_returns_output_and_cleans_up_success_and_error_paths() {
        let paths = Arc::new(Mutex::new(None::<(String, String)>));
        let success_paths = Arc::clone(&paths);
        let output = with_temp_io("unit_success", b"input", move |input, output| {
            assert_eq!(std::fs::read(input)?, b"input");
            *success_paths
                .lock()
                .unwrap_or_else(|error| error.into_inner()) =
                Some((input.to_string(), output.to_string()));
            std::fs::write(output, b"output")?;
            Ok(())
        })
        .expect("temp io success");
        assert_eq!(output, b"output");
        let (input_path, output_path) = paths
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .expect("captured paths");
        assert!(!std::path::Path::new(&input_path).exists());
        assert!(!std::path::Path::new(&output_path).exists());

        let error_paths = Arc::new(Mutex::new(None::<(String, String)>));
        let captured = Arc::clone(&error_paths);
        let err = with_temp_io("unit_error", b"input", move |input, output| {
            *captured.lock().unwrap_or_else(|error| error.into_inner()) =
                Some((input.to_string(), output.to_string()));
            Err(VaultError::Crypto("forced failure".to_string()))
        })
        .expect_err("callback failure should propagate");
        assert!(err.to_string().contains("forced failure"));
        let (input_path, output_path) = error_paths
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .expect("captured error paths");
        assert!(!std::path::Path::new(&input_path).exists());
        assert!(!std::path::Path::new(&output_path).exists());
    }
}
