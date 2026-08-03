use crate::secure_element::key_meta::{DkpKeyHistory, KeyMetadata};
use anyhow::{anyhow, Result};
use p256::pkcs8::EncodePublicKey;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::fs;
use std::path::{Path, PathBuf};

const SOFTHSM_ROOT: &str = "/var/lib/sgx-guardian/softhsm";
const SOFTHSM_CONF_PATH: &str = "/var/lib/sgx-guardian/softhsm2.conf";
const TOKENS_DIR: &str = "/var/lib/sgx-guardian/softhsm/tokens";
const KEYS_DIR: &str = "/var/lib/sgx-guardian/keys";
const DKP_METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";

pub struct VirtualKeyMaterial {
    pub key_path: String,
    pub raw_public_key: Vec<u8>,
    pub spki_public_key: Vec<u8>,
}

fn ensure_layout() -> Result<()> {
    for dir in [SOFTHSM_ROOT, TOKENS_DIR, KEYS_DIR] {
        fs::create_dir_all(dir).map_err(|e| anyhow!("create {}: {}", dir, e))?;
    }
    let _pin = std::env::var("SGX_SOFTHSM_PIN")
        .map_err(|_| anyhow!("SGX_SOFTHSM_PIN is required for virtual-platform startup"))?;
    if !Path::new(SOFTHSM_CONF_PATH).exists() {
        fs::write(
            SOFTHSM_CONF_PATH,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\n",
                TOKENS_DIR
            ),
        )
        .map_err(|e| anyhow!("write {}: {}", SOFTHSM_CONF_PATH, e))?;
    }
    Ok(())
}

fn key_path(node_id: &str, label: &str, version: u32) -> PathBuf {
    Path::new(TOKENS_DIR).join(format!("{}_{}_v{}.pk8", node_id, label, version))
}

fn public_key_export_path(label: &str) -> &'static str {
    match label {
        "dik" => "/var/lib/sgx-guardian/keys/dik_pub.der",
        _ => "/var/lib/sgx-guardian/keys/dkp_pub.der",
    }
}

fn write_private_key(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| anyhow!("create {}: {}", parent.display(), e))?;
    }
    fs::write(path, bytes).map_err(|e| anyhow!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow!("chmod {}: {}", path.display(), e))?;
    }
    Ok(())
}

fn load_or_generate_key(path: &Path) -> Result<EcdsaKeyPair> {
    let rng = SystemRandom::new();
    let pkcs8_bytes = if path.exists() {
        fs::read(path).map_err(|e| anyhow!("read {}: {}", path.display(), e))?
    } else {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("generate virtual keypair"))?;
        write_private_key(path, pkcs8.as_ref())?;
        pkcs8.as_ref().to_vec()
    };
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
        .map_err(|_| anyhow!("load virtual keypair from {}", path.display()))
}

fn build_public_material(keypair: &EcdsaKeyPair) -> Result<(Vec<u8>, Vec<u8>)> {
    let raw = keypair.public_key().as_ref().to_vec();
    let public_key = p256::PublicKey::from_sec1_bytes(&raw)
        .map_err(|e| anyhow!("decode SEC1 public key: {}", e))?;
    let spki = public_key
        .to_public_key_der()
        .map_err(|e| anyhow!("encode SPKI DER: {}", e))?
        .as_bytes()
        .to_vec();
    Ok((raw, spki))
}

pub fn ensure_named_key(node_id: &str, label: &str, version: u32) -> Result<VirtualKeyMaterial> {
    ensure_layout()?;
    let path = key_path(node_id, label, version);
    let keypair = load_or_generate_key(&path)?;
    let (raw_public_key, spki_public_key) = build_public_material(&keypair)?;
    fs::write(public_key_export_path(label), &spki_public_key)
        .map_err(|e| anyhow!("write {}: {}", public_key_export_path(label), e))?;
    Ok(VirtualKeyMaterial {
        key_path: path.to_string_lossy().to_string(),
        raw_public_key,
        spki_public_key,
    })
}

pub fn ensure_virtual_dkp(node_id: &str) -> Result<VirtualKeyMaterial> {
    let history = load_or_create_history(node_id)?;
    let active = history
        .active_key()
        .ok_or_else(|| anyhow!("no active virtual DKP"))?;
    ensure_named_key(node_id, "dkp", active.version)
}

pub fn rotate_virtual_dkp(node_id: &str) -> Result<KeyMetadata> {
    let mut history = load_or_create_history(node_id)?;
    let current = history
        .active_key()
        .cloned()
        .ok_or_else(|| anyhow!("no active virtual DKP"))?;
    let _ = history.deprecate_version(current.version);
    let mut next = KeyMetadata::new(
        &format!("virtual-dkp-v{}", current.version + 1),
        "dkp",
        "ECDSA-P256",
        current.version + 1,
    );
    next.rotated_from = Some(current.key_id.clone());
    next.public_key_path = Some("/var/lib/sgx-guardian/keys/dkp_pub.der".to_string());
    ensure_named_key(node_id, "dkp", next.version)?;
    history.add(next.clone());
    history
        .save(DKP_METADATA_PATH)
        .map_err(|e| anyhow!("save virtual dkp history: {}", e))?;
    Ok(next)
}

fn load_or_create_history(node_id: &str) -> Result<DkpKeyHistory> {
    if let Ok(history) = DkpKeyHistory::load(DKP_METADATA_PATH) {
        return Ok(history);
    }

    let mut first = KeyMetadata::new("virtual-dkp-v1", "dkp", "ECDSA-P256", 1);
    first.public_key_path = Some("/var/lib/sgx-guardian/keys/dkp_pub.der".to_string());
    let history = DkpKeyHistory::new(first);
    history
        .save(DKP_METADATA_PATH)
        .map_err(|e| anyhow!("create virtual dkp history: {}", e))?;
    let _ = ensure_named_key(node_id, "dkp", 1)?;
    Ok(history)
}

pub fn sign_with_key(node_id: &str, label: &str, version: u32, data: &[u8]) -> Result<Vec<u8>> {
    let material = ensure_named_key(node_id, label, version)?;
    let rng = SystemRandom::new();
    let keypair = load_or_generate_key(Path::new(&material.key_path))?;
    let sig = keypair
        .sign(&rng, data)
        .map_err(|_| anyhow!("virtual sign failed"))?;
    Ok(sig.as_ref().to_vec())
}
