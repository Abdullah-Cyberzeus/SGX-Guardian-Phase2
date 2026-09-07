#![allow(dead_code)]

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
#[cfg(feature = "secure-element")]
use crate::secure_element::sign::SeSigner;
use anyhow::{anyhow, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::{fs, path::Path};
use tracing::{info, warn};

/// Write private key bytes to disk, then lock permissions down to 0600
/// (owner read/write only). Every private-key write path in this file must
/// go through this — one earlier fix covered load_or_generate()'s two write
/// sites but missed init_with_se050()'s fallback-key sites, which shipped
/// world/group-readable on the default umask.
fn write_private_key(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    let path = path.as_ref();
    fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Manages the SG-X node identity keypair including generation,
/// secure persistence, loading from disk, and providing signing/public
/// key access for attestation workflows.
/// Signing backend — software (ring) or hardware-backed providers.
pub enum SigningBackend {
    /// Software ECDSA via ring crate (Phase 1 default)
    Software,
    /// Hardware ECDSA via NXP SE050 secure element
    #[cfg(feature = "secure-element")]
    Hardware { signer: SeSigner, key_id: u32 },
    /// Hardware ECDSA via TPM 2.0 persistent handle
    #[cfg(feature = "tpm")]
    Tpm {
        signer: crate::tpm::signer::TpmSigner,
        dkp_handle: u32,
    },
}
pub struct KeyManager {
    keypair: EcdsaKeyPair,
    key_path: String,
    backend: SigningBackend,
}
impl KeyManager {
    /// Loads the identity keypair from disk if it exists, otherwise generates
    /// a new ECDSA P-256 keypair and saves it to the configured path.
    /// Returns a fully initialized `KeyManager` instance.
    pub fn load_or_generate(key_path: &str) -> Result<Self> {
        let rng = SystemRandom::new();
        let key_path_str = key_path;
        let key_path = Path::new(key_path_str);
        fs::create_dir_all("sgx-agent").ok();
        // Ensure parent directory exists BEFORE any read/write attempt
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).ok();
        }

        // Try to load + parse existing key. On ANY parse failure, quarantine the bad
        // file and regenerate — this is the critical fix for the
        // "Failed to load keypair from pkcs8" crash loop observed on the boards.
        let pkcs8_bytes = if key_path.exists() {
            let raw = fs::read(key_path).unwrap_or_default();
            // Probe-parse before committing. If OK, use it; if not, quarantine + regen.
            match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &raw, &rng) {
                Ok(_) => {
                    info!("Loading existing identity key: {}", key_path.display());
                    log_audit(
                        "system",
                        AuditCategory::Identity,
                        AuditSeverity::Info,
                        AuditAction::Loaded,
                        "Existing node identity key loaded from disk",
                    );
                    raw
                }
                Err(_) => {
                    // File exists but is corrupt / wrong-format. Rename it aside and
                    // regenerate. Previously this path called `?` and exited the daemon,
                    // causing the reboot loop.
                    let quarantine = format!(
                        "{}.corrupt.{}",
                        key_path.display(),
                        chrono::Utc::now().timestamp()
                    );
                    let _ = fs::rename(key_path, &quarantine);
                    warn!(
                        "⚠️ Existing identity key was corrupt — quarantined to {} and regenerating",
                        quarantine
                    );
                    log_audit(
                        "system",
                        AuditCategory::Identity,
                        AuditSeverity::Critical,
                        AuditAction::Failed,
                        &format!(
                            "Corrupt identity key quarantined to {} — regenerating",
                            quarantine
                        ),
                    );
                    let pkcs8 =
                        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                            .map_err(|_| anyhow!("Failed to generate keypair"))?;
                    write_private_key(key_path, pkcs8.as_ref())?;
                    pkcs8.as_ref().to_vec()
                }
            }
        } else {
            warn!("⚠️ Identity key not found, generating new one...");
            log_audit(
                "system",
                AuditCategory::Identity,
                AuditSeverity::Critical,
                AuditAction::Created,
                "New node identity key generated",
            );
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| anyhow!("Failed to generate keypair"))?;
            write_private_key(key_path, pkcs8.as_ref())?;
            info!("New identity key generated at {}", key_path.display());
            pkcs8.as_ref().to_vec()
        };

        // Final load — this must succeed because we just wrote or validated the bytes.
        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
                .map_err(|_| anyhow!("Failed to load keypair from pkcs8 after regen"))?;
        // === Save public key as DER file (optional export for CLI/testing) ===
        let pub_der_path = "sgx-agent/device_public.der";
        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Info,
            AuditAction::Exported,
            "Node public key exported in DER format",
        );
        let pub_der = keypair.public_key().as_ref();
        fs::write(pub_der_path, pub_der).ok();
        Ok(Self {
            keypair,
            key_path: key_path_str.to_string(),
            backend: SigningBackend::Software,
        })
    }
    /// Initialize KeyManager with SE050 hardware backend.
    /// DKP is generated/loaded inside the secure element.
    /// Private key NEVER leaves the chip.
    #[cfg(feature = "secure-element")]
    pub fn init_with_se050(
        se_config: &crate::secure_element::config::SeConfig,
        base_path: &str,
        fallback_key_path: &str,
    ) -> Result<Self> {
        use crate::secure_element::dkp::DkpManager;

        info!("Initializing KeyManager with SE050 hardware backend...");

        // Try hardware path first
        match DkpManager::init(se_config, base_path) {
            Ok(dkp) => {
                let key_id = dkp.active_key_id();
                let signer = dkp
                    .create_signer()
                    .map_err(|e| anyhow!("Create SE050 signer: {}", e))?;

                // We still need a software keypair for pubkey_der()
                // Load or generate a software key as reference. This path MUST tolerate
                // a corrupt on-disk fallback (e.g., prior daemon crash mid-write), otherwise
                // the entire daemon aborts and the board enters a reboot loop.
                let rng = SystemRandom::new();
                let fb_path = Path::new(fallback_key_path);
                if let Some(parent) = fb_path.parent() {
                    fs::create_dir_all(parent).ok();
                }

                let pkcs8_bytes = if fb_path.exists() {
                    let raw = fs::read(fb_path).unwrap_or_default();
                    match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &raw, &rng) {
                        Ok(_) => raw,
                        Err(_) => {
                            let quarantine = format!(
                                "{}.corrupt.{}",
                                fallback_key_path,
                                chrono::Utc::now().timestamp()
                            );
                            let _ = fs::rename(fb_path, &quarantine);
                            warn!(
                                "SE050 fallback key corrupt — quarantined to {} and regenerating",
                                quarantine
                            );
                            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                                &ECDSA_P256_SHA256_FIXED_SIGNING,
                                &rng,
                            )
                            .map_err(|_| anyhow!("Generate fallback keypair"))?;
                            write_private_key(fallback_key_path, pkcs8.as_ref())?;
                            write_private_key(fb_path, pkcs8.as_ref())?;
                            pkcs8.as_ref().to_vec()
                        }
                    }
                } else {
                    let pkcs8 =
                        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                            .map_err(|_| anyhow!("Generate fallback keypair"))?;
                    write_private_key(fallback_key_path, pkcs8.as_ref())?;
                    write_private_key(fb_path, pkcs8.as_ref())?;
                    pkcs8.as_ref().to_vec()
                };

                let keypair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
                        .map_err(|_| anyhow!("Load fallback keypair after regen"))?;

                // If SE050 public key is available, use it instead
                let pub_der_path = format!("{}/keys/dkp_pub.der", base_path);
                if Path::new(&pub_der_path).exists() {
                    info!("DKP public key available at {}", pub_der_path);
                }

                log_audit(
                    "system",
                    AuditCategory::Identity,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    &format!(
                        "DKP initialized via SE050 hardware (key={})",
                        dkp.history
                            .active_key()
                            .map(|k| k.key_id.clone())
                            .unwrap_or_else(|| format!("0x{:08X}", key_id))
                    ),
                );

                info!(
                    "KeyManager initialized with SE050 backend (key_id=0x{:08X})",
                    key_id
                );

                Ok(Self {
                    keypair,
                    key_path: fallback_key_path.to_string(),
                    backend: SigningBackend::Hardware { signer, key_id },
                })
            }
            Err(e) => {
                warn!("SE050 DKP init failed: {} — falling back to software", e);
                Self::load_or_generate(fallback_key_path)
            }
        }
    }

    /// Initialize KeyManager with a TPM 2.0 hardware backend.
    #[cfg(feature = "tpm")]
    pub fn init_with_tpm(
        cfg: &crate::tpm::TpmConfig,
        base_path: &str,
        fallback_key_path: &str,
    ) -> Result<Self> {
        use crate::tpm::{dik, dkp::TpmDkpManager, ek};

        info!("Initializing KeyManager with TPM 2.0 hardware backend...");

        let _uid = ek::ensure_uid(cfg).map_err(|e| anyhow!("TPM EK/UID: {}", e))?;
        let _dik_pub = dik::ensure(cfg).map_err(|e| anyhow!("TPM DIK: {}", e))?;
        let dkp = TpmDkpManager::init(cfg, base_path).map_err(|e| anyhow!("TPM DKP: {}", e))?;
        let dkp_handle = dkp.active_handle();
        let dkp_version = dkp.active_version();
        let signer = dkp.create_signer();

        let rng = SystemRandom::new();
        let fb_path = Path::new(fallback_key_path);
        if let Some(parent) = fb_path.parent() {
            fs::create_dir_all(parent).ok();
        }

        let pkcs8_bytes = if fb_path.exists() {
            let raw = fs::read(fb_path).unwrap_or_default();
            match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &raw, &rng) {
                Ok(_) => raw,
                Err(_) => {
                    let quarantine = format!(
                        "{}.corrupt.{}",
                        fallback_key_path,
                        chrono::Utc::now().timestamp()
                    );
                    let _ = fs::rename(fb_path, &quarantine);
                    warn!(
                        "TPM fallback key corrupt — quarantined to {} and regenerating",
                        quarantine
                    );
                    let pkcs8 =
                        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                            .map_err(|_| anyhow!("Generate TPM fallback keypair"))?;
                    write_private_key(fallback_key_path, pkcs8.as_ref())?;
                    pkcs8.as_ref().to_vec()
                }
            }
        } else {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| anyhow!("Generate TPM fallback keypair"))?;
            write_private_key(fallback_key_path, pkcs8.as_ref())?;
            pkcs8.as_ref().to_vec()
        };

        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
                .map_err(|_| anyhow!("Load TPM fallback keypair after regen"))?;

        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Info,
            AuditAction::Loaded,
            &format!(
                "DKP initialized via TPM 2.0 hardware (handle=0x{:08X}, v{})",
                dkp_handle, dkp_version
            ),
        );

        info!(
            "KeyManager initialized with TPM backend (handle=0x{:08X}, version={})",
            dkp_handle, dkp_version
        );

        Ok(Self {
            keypair,
            key_path: fallback_key_path.to_string(),
            backend: SigningBackend::Tpm { signer, dkp_handle },
        })
    }
    /// Signs the provided message bytes using the node’s private ECDSA key.
    /// Returns the raw signature bytes, used in attestation messages.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.backend {
            SigningBackend::Software => {
                let rng = SystemRandom::new();
                let sig = self
                    .keypair
                    .sign(&rng, data)
                    .map_err(|_| anyhow!("Failed to sign data"))?;
                log_audit(
                    "system",
                    AuditCategory::Cryptography,
                    AuditSeverity::Info,
                    AuditAction::Used,
                    "Key used to sign data (software)",
                );
                Ok(sig.as_ref().to_vec())
            }
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { signer, key_id } => {
                crate::secure_element::safe_mode::guard_crypto_operation("sign")?;
                let sig = signer
                    .sign(*key_id, data)
                    .map_err(|e| anyhow!("SE050 sign failed: {}", e))?;
                log_audit(
                    "system",
                    AuditCategory::Cryptography,
                    AuditSeverity::Info,
                    AuditAction::Used,
                    "Key used to sign data (SE050 hardware)",
                );
                Ok(sig)
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { signer, dkp_handle } => {
                let sig = signer
                    .sign(*dkp_handle, data)
                    .map_err(|e| anyhow!("TPM sign failed: {}", e))?;
                log_audit(
                    "system",
                    AuditCategory::Cryptography,
                    AuditSeverity::Info,
                    AuditAction::Used,
                    "Key used to sign data (TPM 2.0 hardware)",
                );
                Ok(sig)
            }
        }
    }

    /// Verify a raw or DER-framed ECDSA P-256 signature against the supplied
    /// message bytes and trusted public key export.
    pub fn verify_signature(data: &[u8], sig: &[u8], public_key_der: &[u8]) -> Result<()> {
        crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(public_key_der, data, sig)
            .map_err(|e| anyhow!("Signature verification failed: {}", e))
    }

    /// Returns the node's public key as raw EC point bytes (65 bytes: 04||x||y).
    /// Software: from ring keypair. Hardware: from exported DKP DER file.
    pub fn pubkey_der(&self) -> Result<Vec<u8>> {
        match &self.backend {
            SigningBackend::Software => {
                // ring returns raw 65-byte EC point directly
                Ok(self.keypair.public_key().as_ref().to_vec())
            }
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware {
                signer: _,
                key_id: _,
            } => {
                let dkp_pub_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
                match std::fs::read(dkp_pub_path) {
                    Ok(der_bytes) => {
                        // SE050 exports SubjectPublicKeyInfo DER (91 bytes).
                        // Extract raw 65-byte EC point starting at offset 26.
                        if der_bytes.len() == 91 {
                            Ok(der_bytes[26..].to_vec())
                        } else if der_bytes.len() == 65 {
                            Ok(der_bytes)
                        } else {
                            Err(anyhow!(
                                "FATAL: DKP pubkey at {} unexpected length {}",
                                dkp_pub_path,
                                der_bytes.len()
                            ))
                        }
                    }
                    Err(e) => Err(anyhow!(
                        "FATAL: Hardware backend active but DKP pubkey missing at {}: {}",
                        dkp_pub_path,
                        e
                    )),
                }
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => {
                let der = std::fs::read(crate::tpm::dkp::DKP_PUB_PATH).map_err(|e| {
                    anyhow!(
                        "TPM DKP pubkey missing at {}: {}",
                        crate::tpm::dkp::DKP_PUB_PATH,
                        e
                    )
                })?;
                if der.len() == 91 {
                    Ok(der[26..].to_vec())
                } else if der.len() == 65 {
                    Ok(der)
                } else {
                    Err(anyhow!("TPM DKP pubkey unexpected length {}", der.len()))
                }
            }
        }
    }

    /// Returns the runtime public key export used for persisted DID artifacts.
    pub fn runtime_public_key_export(&self) -> Result<Vec<u8>> {
        match &self.backend {
            SigningBackend::Software => Ok(self.keypair.public_key().as_ref().to_vec()),
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => {
                std::fs::read("/var/lib/sgx-guardian/keys/dkp_pub.der")
                    .map_err(|e| anyhow!("Read SE050 runtime pubkey export: {}", e))
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => std::fs::read(crate::tpm::dkp::DKP_PUB_PATH)
                .map_err(|e| anyhow!("Read TPM runtime pubkey export: {}", e)),
        }
    }

    pub fn backend_name(&self) -> &str {
        match &self.backend {
            SigningBackend::Software => "Software",
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => "SE050",
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => "TPM2",
        }
    }

    pub fn backend_display_name(&self) -> &str {
        match &self.backend {
            SigningBackend::Software => "software",
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => "SE050",
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => "TPM 2.0",
        }
    }

    pub fn dkp_version(&self) -> u32 {
        match &self.backend {
            SigningBackend::Software => 1,
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { key_id, .. } => {
                key_id.saturating_sub(
                    crate::secure_element::config::SeConfig::default().dkp_key_id_base,
                ) + 1
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { dkp_handle, .. } => {
                dkp_handle.saturating_sub(crate::tpm::TpmConfig::default().dkp_handle_base) + 1
            }
        }
    }

    /// Reload the hardware-backed signer from the currently active DKP slot.
    /// Software backends remain unchanged and return `None`.
    pub fn refresh_for_active_dkp(&self) -> Result<Option<Self>> {
        match &self.backend {
            SigningBackend::Software => Ok(None),
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => {
                let se_config = crate::secure_element::config::SeConfig::default();
                Self::init_with_se050(&se_config, "/var/lib/sgx-guardian", &self.key_path).map(Some)
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => {
                let cfg = crate::tpm::TpmConfig::default();
                Self::init_with_tpm(&cfg, crate::tpm::TPM_BASE_PATH, &self.key_path).map(Some)
            }
        }
    }

    /// Returns the filesystem path where the private key is stored.
    /// Useful for debugging and operational visibility.
    pub fn key_path(&self) -> &str {
        &self.key_path
    }
}

#[cfg(feature = "tpm")]
fn tpm_runtime_candidate() -> Option<crate::tpm::TpmConfig> {
    let cfg = crate::tpm::TpmConfig::default();
    crate::tpm::should_attempt(&cfg).then_some(cfg)
}

pub fn runtime_device_uid_details(
    fallback: &str,
) -> std::result::Result<(String, String, Vec<u8>), String> {
    #[cfg(feature = "tpm")]
    if let Some(cfg) = tpm_runtime_candidate() {
        let uid_bytes = crate::tpm::ek::ensure_uid(&cfg).map_err(|e| e.to_string())?;
        let uid_string = hex::encode(&uid_bytes);
        return Ok((uid_string, "tpm-ek".to_string(), uid_bytes));
    }

    let uid = crate::secure_element::pcr::read_device_uid(fallback);
    if uid.trim().is_empty() {
        return Err("empty uid".to_string());
    }

    let source = if uid.len() >= 20 && uid.chars().all(|c| c.is_ascii_hexdigit()) {
        "ssscli".to_string()
    } else {
        "fallback".to_string()
    };

    Ok((uid.clone(), source, uid_to_bytes(&uid)))
}

pub fn runtime_device_uid(fallback: &str) -> String {
    runtime_device_uid_details(fallback)
        .map(|(uid, _, _)| uid)
        .unwrap_or_else(|_| fallback.to_string())
}

fn uid_to_bytes(uid: &str) -> Vec<u8> {
    let trimmed = uid.trim();
    if trimmed.len().is_multiple_of(2)
        && trimmed.len() >= 2
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        if let Ok(decoded) = hex::decode(trimmed) {
            return decoded;
        }
    }
    trimmed.as_bytes().to_vec()
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    /// Ensures that identity keys persist across reloads and that signing works.
    /// This verifies the correctness of keypair storage + signature generation.
    #[test]
    fn test_key_persistence_and_sign() {
        let test_path = "/tmp/test_device.key";
        let km1 = KeyManager::load_or_generate(test_path).unwrap();
        let km2 = KeyManager::load_or_generate(test_path).unwrap();

        // Public keys must match across reloads (persistent identity)
        assert_eq!(
            general_purpose::STANDARD.encode(km1.pubkey_der().unwrap()),
            general_purpose::STANDARD.encode(km2.pubkey_der().unwrap())
        );

        // Signing + verification placeholder (we’ll add verify later)
        let data = b"guardian test message";
        let sig = km1.sign(data).unwrap();
        assert!(!sig.is_empty());

        // Cleanup test key file
        fs::remove_file(test_path).unwrap();
    }

    #[test]
    fn test_refresh_for_active_dkp_is_noop_for_software() {
        let test_path = "/tmp/test_device_refresh.key";
        let km = KeyManager::load_or_generate(test_path).unwrap();
        assert!(km.refresh_for_active_dkp().unwrap().is_none());
        fs::remove_file(test_path).unwrap();
    }

    /// The crash-loop fix this function's own comment describes: a key file
    /// that exists but does not parse must be moved aside and replaced, not
    /// propagated as an error that takes the daemon down.
    #[test]
    fn a_corrupt_key_file_is_quarantined_and_a_fresh_one_generated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("device.key");
        fs::write(&key_path, b"this is not a pkcs8 document").expect("write corrupt key");

        let km = KeyManager::load_or_generate(key_path.to_str().expect("path"))
            .expect("a corrupt key must not be fatal");
        assert!(!km.pubkey_der().expect("pubkey").is_empty());

        // The replacement is usable...
        let signature = km.sign(b"payload").expect("sign with the regenerated key");
        KeyManager::verify_signature(
            b"payload",
            &signature,
            &km.runtime_public_key_export().expect("export"),
        )
        .expect("the regenerated key verifies its own signature");

        // ...and the bad file was preserved rather than deleted.
        let quarantined: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".corrupt."))
            .collect();
        assert_eq!(
            quarantined.len(),
            1,
            "expected one quarantined file: {quarantined:?}"
        );
    }

    #[test]
    fn a_missing_key_file_is_generated_with_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("nested").join("device.key");

        let km = KeyManager::load_or_generate(key_path.to_str().expect("path"))
            .expect("a missing key is generated");
        assert_eq!(km.key_path(), key_path.to_str().expect("path"));
        assert!(
            key_path.exists(),
            "the parent directory is created as needed"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the private key must not be group/world readable"
            );
        }
    }

    #[test]
    fn verify_signature_rejects_a_tampered_message_and_a_foreign_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let km = KeyManager::load_or_generate(dir.path().join("a.key").to_str().expect("path"))
            .expect("generate");
        let other = KeyManager::load_or_generate(dir.path().join("b.key").to_str().expect("path"))
            .expect("generate");

        let signature = km.sign(b"payload").expect("sign");
        let public_key = km.runtime_public_key_export().expect("export");

        KeyManager::verify_signature(b"payload", &signature, &public_key).expect("valid signature");
        assert!(
            KeyManager::verify_signature(b"tampered", &signature, &public_key).is_err(),
            "a different message must not verify"
        );
        assert!(
            KeyManager::verify_signature(
                b"payload",
                &signature,
                &other.runtime_public_key_export().expect("export")
            )
            .is_err(),
            "another node's key must not verify this signature"
        );
        assert!(
            KeyManager::verify_signature(b"payload", b"not-a-signature", &public_key).is_err(),
            "a malformed signature must not verify"
        );
    }

    #[test]
    fn the_software_backend_reports_its_identity_and_dkp_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let km =
            KeyManager::load_or_generate(dir.path().join("device.key").to_str().expect("path"))
                .expect("generate");

        assert_eq!(km.backend_name(), "Software");
        assert_eq!(km.backend_display_name(), "software");
        assert_eq!(km.dkp_version(), 1, "software identities are always slot 1");

        // Both public-key accessors agree for the software backend.
        assert_eq!(
            km.pubkey_der().expect("pubkey_der"),
            km.runtime_public_key_export().expect("runtime export")
        );
    }

    #[test]
    fn uid_to_bytes_decodes_hex_and_falls_back_to_raw_bytes() {
        // Even-length hex decodes to its bytes.
        assert_eq!(uid_to_bytes("0a0b0c"), vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(uid_to_bytes("  0A0B  "), vec![0x0a, 0x0b]);
        // Odd length, non-hex, and empty all fall back to the raw characters.
        assert_eq!(uid_to_bytes("abc"), b"abc".to_vec());
        assert_eq!(uid_to_bytes("zz"), b"zz".to_vec());
        assert_eq!(uid_to_bytes(""), Vec::<u8>::new());
    }

    #[test]
    fn runtime_device_uid_classifies_its_source_and_falls_back() {
        // No secure element is present here, so the fallback is what comes
        // back — and a fallback that looks like a long hex string is still
        // reported as a fallback only if it is shorter than the ssscli shape.
        let short = runtime_device_uid("node-a");
        assert_eq!(short, "node-a");

        let (uid, source, bytes) =
            runtime_device_uid_details("node-a").expect("a non-empty fallback succeeds");
        assert_eq!(uid, "node-a");
        assert_eq!(source, "fallback");
        assert_eq!(bytes, b"node-a".to_vec());

        // A fallback that is long and fully hexadecimal is indistinguishable
        // from a real device UID, and is reported as such.
        let hex_uid = "0123456789abcdef0123";
        let (uid, source, bytes) =
            runtime_device_uid_details(hex_uid).expect("hex fallback succeeds");
        assert_eq!(uid, hex_uid);
        assert_eq!(source, "ssscli");
        assert_eq!(bytes, hex::decode(hex_uid).expect("decode"));

        // An empty UID is an error, and `runtime_device_uid` turns that back
        // into the caller's fallback string.
        assert!(runtime_device_uid_details("   ").is_err());
        assert_eq!(runtime_device_uid("   "), "   ");
    }

    #[test]
    fn write_private_key_replaces_content_and_restricts_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");

        write_private_key(&path, b"first").expect("first write");
        assert_eq!(fs::read(&path).expect("read"), b"first");

        write_private_key(&path, b"second").expect("second write");
        assert_eq!(fs::read(&path).expect("read"), b"second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // An unwritable location is surfaced as an error rather than panicking.
        assert!(write_private_key(dir.path().join("missing").join("x.bin"), b"x").is_err());
    }
}
