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
/// Signing backend — software (ring) or hardware (SE050)
pub enum SigningBackend {
    /// Software ECDSA via ring crate (Phase 1 default)
    Software,
    /// Hardware ECDSA via NXP SE050 secure element
    #[cfg(feature = "secure-element")]
    Hardware { signer: SeSigner, key_id: u32 },
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
                            pkcs8.as_ref().to_vec()
                        }
                    }
                } else {
                    let pkcs8 =
                        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                            .map_err(|_| anyhow!("Generate fallback keypair"))?;
                    write_private_key(fallback_key_path, pkcs8.as_ref())?;
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
        }
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
        }
    }

    pub fn backend_name(&self) -> &str {
        match &self.backend {
            SigningBackend::Software => "Software",
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => "SE050",
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
        }
    }

    /// Returns the filesystem path where the private key is stored.
    /// Useful for debugging and operational visibility.
    pub fn key_path(&self) -> &str {
        &self.key_path
    }
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
}
