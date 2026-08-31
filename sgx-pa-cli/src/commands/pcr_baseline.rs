use base64::Engine as _;
use clap::Subcommand;
use sgx_guardian_client::key_manager::KeyManager;
use sgx_guardian_client::secure_element::pcr::{
    canonical_baseline_signing_payload, signature_format, verify_baseline_signature_bytes,
    PcrBaseline,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const PCR_DIR: &str = "/var/lib/sgx-guardian/pcr";
const KEY_DIR_ENV: &str = "SGX_GUARDIAN_DEVICE_KEY_DIR";
const DEFAULT_KEY_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";
const SE_BASE_PATH: &str = "/var/lib/sgx-guardian";
const DKP_METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";

fn find_pcr_snapshot() -> Option<(String, String)> {
    if let Ok(entries) = std::fs::read_dir(PCR_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with("_current.json") {
                let node = name.trim_end_matches("_current.json").to_string();
                return Some((entry.path().to_string_lossy().to_string(), node));
            }
        }
    }
    let old = format!("{}/current.json", PCR_DIR);
    if Path::new(&old).exists() {
        Some((old, "unknown".into()))
    } else {
        None
    }
}

fn baseline_path_for(node_id: &str) -> String {
    format!("/etc/sgx-guardian/pcr_{}_baseline.json", node_id)
}

#[derive(Subcommand)]
pub enum PcrBaselineCmd {
    /// Create golden baseline from current PCR snapshot
    Create,
    /// Verify current snapshot against baseline
    Verify,
}

pub fn run_create() {
    println!("=== Create PCR Golden Baseline ===\n");

    let (pcr_path, node_id) = match find_pcr_snapshot() {
        Some(p) => p,
        None => {
            eprintln!("No PCR snapshot. Run daemon first.");
            return;
        }
    };
    println!("  Node: {}\n", node_id);

    let json = match fs::read_to_string(&pcr_path) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Read error: {}", e);
            return;
        }
    };
    let snap: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            return;
        }
    };

    let composite = match snap["composite_digest"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            eprintln!("❌ composite_digest missing from PCR snapshot");
            return;
        }
    };
    let device_uid = match snap["device_uid"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            eprintln!("❌ device_uid missing from PCR snapshot");
            return;
        }
    };
    let created_at = chrono::Utc::now().to_rfc3339();

    let signer = match load_active_baseline_signer(&node_id) {
        Ok(signer) => signer,
        Err(e) => {
            eprintln!("❌ PCR baseline signer unavailable: {}", e);
            return;
        }
    };

    let pcr_values = match serde_json::from_value::<Vec<String>>(snap["pcr_values"].clone()) {
        Ok(values) => values,
        Err(e) => {
            eprintln!("❌ Invalid pcr_values: {}", e);
            return;
        }
    };
    let schema_version = snap["schema_version"].as_u64().unwrap_or(1) as u8;

    let baseline = match create_signed_baseline(
        pcr_values,
        composite,
        created_at,
        device_uid,
        schema_version,
        signer.as_ref(),
    ) {
        Ok(baseline) => baseline,
        Err(e) => {
            eprintln!("❌ Failed to sign PCR baseline: {}", e);
            return;
        }
    };

    let bl_path = baseline_path_for(&node_id);
    if let Some(parent) = Path::new(&bl_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    match baseline.save(&bl_path) {
        Ok(_) => {
            println!("✅ Baseline created and SIGNED at {}", bl_path);
            println!("   Signing backend: {}", signer.backend_display());
            println!("   Device UID: [redacted]");
            println!("   DKP version: {}", signer.dkp_version());
            println!(
                "   Signature format: {}",
                baseline.signature_format.as_deref().unwrap_or("unknown")
            );
        }
        Err(e) => eprintln!("Write error: {}", e),
    };
}

pub fn run_verify() {
    println!("=== Verify PCR Baseline ===\n");
    let (pcr_path, node_id) = match find_pcr_snapshot() {
        Some(p) => p,
        None => {
            eprintln!("No snapshot.");
            return;
        }
    };
    let bl_path = baseline_path_for(&node_id);
    if !Path::new(&bl_path).exists() {
        eprintln!("No baseline. Create first: sgx-pa-cli pcr-baseline create");
        return;
    }

    let baseline: serde_json::Value = match fs::read_to_string(&bl_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            eprintln!("❌ Failed to load baseline from {}", bl_path);
            return;
        }
    };
    let snapshot: serde_json::Value = match fs::read_to_string(&pcr_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            eprintln!("❌ Failed to load snapshot from {}", pcr_path);
            return;
        }
    };

    let signer = match load_active_baseline_signer(&node_id) {
        Ok(signer) => signer,
        Err(e) => {
            eprintln!("❌ PCR baseline signer unavailable: {}", e);
            return;
        }
    };

    // Verify baseline signature first.
    let sig = baseline["baseline_signature"].as_str().unwrap_or("");
    if sig.is_empty() {
        eprintln!("❌ Baseline is NOT SIGNED — tamper protection not active");
        return;
    }
    let created_at = baseline["created_at"].as_str().unwrap_or("");
    let device_uid = baseline["device_uid"].as_str().unwrap_or("");
    let composite = baseline["composite_digest"].as_str().unwrap_or("");
    let payload = match canonical_baseline_signing_payload(composite, created_at, device_uid) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("❌ Invalid baseline signing payload: {}", e);
            return;
        }
    };
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("❌ Invalid baseline signature encoding: {}", e);
            return;
        }
    };
    if !verify_baseline_signature_bytes(&payload, &sig_bytes, signer.public_key()) {
        eprintln!(
            "❌ Baseline signature INVALID for active {} DKP v{}",
            signer.backend_display(),
            signer.dkp_version()
        );
        return;
    }
    println!(
        "  Baseline signature: ✅ verified with active {} DKP v{}",
        signer.backend_display(),
        signer.dkp_version()
    );

    let names = [
        "BIOS/Bootloader",
        "Firmware/DTB",
        "Kernel",
        "RootFS",
        "Configuration",
    ];
    let b_pcrs = baseline["pcr_values"].as_array();
    let s_pcrs = snapshot["pcr_values"].as_array();

    if let (Some(bp), Some(sp)) = (b_pcrs, s_pcrs) {
        if bp.len() != sp.len() {
            eprintln!(
                "PCR count mismatch: baseline={}, current={}",
                bp.len(),
                sp.len()
            );
            return;
        }
        let mut all_match = true;
        for i in 0..bp.len() {
            let name = names.get(i).unwrap_or(&"?");
            if bp[i] == sp[i] {
                println!("  PCR{} [{}]: ✅ MATCH", i, name);
            } else {
                println!("  PCR{} [{}]: ❌ MISMATCH", i, name);
                println!("    Baseline: {}", bp[i].as_str().unwrap_or("?"));
                println!("    Current:  {}", sp[i].as_str().unwrap_or("?"));
                all_match = false;
            }
        }
        if all_match {
            println!("\n  Result: ✅ ALL PCRs MATCH — device integrity verified");
        } else {
            println!("\n  Result: ❌ MISMATCH DETECTED — investigate immediately");
        }
    }
}

trait BaselineSigner {
    fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn public_key(&self) -> &[u8];
    fn dkp_version(&self) -> u32;
    fn backend_display(&self) -> &str;
}

struct KeyManagerBaselineSigner {
    km: KeyManager,
    public_key: Vec<u8>,
}

impl BaselineSigner for KeyManagerBaselineSigner {
    fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.km.sign(payload)
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn dkp_version(&self) -> u32 {
        self.km.dkp_version()
    }

    fn backend_display(&self) -> &str {
        self.km.backend_display_name()
    }
}

fn create_signed_baseline(
    pcr_values: Vec<String>,
    composite_digest: String,
    created_at: String,
    device_uid: String,
    schema_version: u8,
    signer: &dyn BaselineSigner,
) -> anyhow::Result<PcrBaseline> {
    let payload = canonical_baseline_signing_payload(&composite_digest, &created_at, &device_uid)
        .map_err(anyhow::Error::msg)?;
    let sig = signer.sign(&payload)?;
    if !verify_baseline_signature_bytes(&payload, &sig, signer.public_key()) {
        anyhow::bail!(
            "signature self-check failed for {} DKP v{}",
            signer.backend_display(),
            signer.dkp_version()
        );
    }

    Ok(PcrBaseline {
        pcr_values,
        composite_digest,
        baseline_signature: base64::engine::general_purpose::STANDARD.encode(&sig),
        signing_backend: Some(signer.backend_display().to_string()),
        signing_public_key_sha256: Some(hex::encode(Sha256::digest(signer.public_key()))),
        signature_format: Some(signature_format(&sig).to_string()),
        created_at,
        device_uid,
        key_version: signer.dkp_version(),
        schema_version,
    })
}

fn load_active_baseline_signer(node_id: &str) -> anyhow::Result<Box<dyn BaselineSigner>> {
    let key_path = device_key_path(node_id);

    if env_true("SGX_FORCE_SOFTWARE_KEYS") || env_true("SGX_DISABLE_SE050_DKP") {
        return signer_from_key_manager(KeyManager::load_or_generate(&key_path)?);
    }

    #[cfg(feature = "tpm")]
    {
        let tpm_cfg = sgx_guardian_client::tpm::TpmConfig::default();
        if sgx_guardian_client::tpm::should_attempt(&tpm_cfg) {
            let km = KeyManager::init_with_tpm(
                &tpm_cfg,
                sgx_guardian_client::tpm::TPM_BASE_PATH,
                &key_path,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "TPM 2.0 hardware mode selected, but active TPM DKP is unavailable: {}",
                    e
                )
            })?;
            return signer_from_key_manager(km);
        }
    }

    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::config::SeConfig::default();
        let km = KeyManager::init_with_se050(&se_config, SE_BASE_PATH, &key_path)?;
        if km.backend_name() == "SE050" {
            return signer_from_key_manager(km);
        }
        if Path::new(DKP_METADATA_PATH).exists() {
            anyhow::bail!(
                "SE050 DKP metadata exists, but active SE050 DKP signer is unavailable; refusing software fallback"
            );
        }
        signer_from_key_manager(km)
    }

    #[cfg(not(feature = "secure-element"))]
    signer_from_key_manager(KeyManager::load_or_generate(&key_path)?)
}

fn signer_from_key_manager(km: KeyManager) -> anyhow::Result<Box<dyn BaselineSigner>> {
    let public_key = km.pubkey_der()?;
    Ok(Box::new(KeyManagerBaselineSigner { km, public_key }))
}

fn device_key_path(node_id: &str) -> String {
    let key_dir = std::env::var(KEY_DIR_ENV).unwrap_or_else(|_| DEFAULT_KEY_DIR.to_string());
    format!("{}/device_{}.key", key_dir.trim_end_matches('/'), node_id)
}

fn env_true(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    struct RingTestSigner {
        keypair: EcdsaKeyPair,
        public_key: Vec<u8>,
        version: u32,
        backend: &'static str,
    }

    impl RingTestSigner {
        fn new(backend: &'static str, version: u32) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let keypair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let public_key = keypair.public_key().as_ref().to_vec();
            Self {
                keypair,
                public_key,
                version,
                backend,
            }
        }
    }

    impl BaselineSigner for RingTestSigner {
        fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            let rng = SystemRandom::new();
            let sig = self
                .keypair
                .sign(&rng, payload)
                .map_err(|_| anyhow::anyhow!("test sign failed"))?;
            Ok(sig.as_ref().to_vec())
        }

        fn public_key(&self) -> &[u8] {
            &self.public_key
        }

        fn dkp_version(&self) -> u32 {
            self.version
        }

        fn backend_display(&self) -> &str {
            self.backend
        }
    }

    fn make_baseline(signer: &RingTestSigner) -> PcrBaseline {
        create_signed_baseline(
            vec!["00".repeat(32); 5],
            "11".repeat(32),
            "2026-07-19T00:00:00Z".to_string(),
            "device-uid".to_string(),
            1,
            signer,
        )
        .unwrap()
    }

    struct InvalidSigner;

    impl BaselineSigner for InvalidSigner {
        fn sign(&self, _payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0; 64])
        }

        fn public_key(&self) -> &[u8] {
            &[4; 65]
        }

        fn dkp_version(&self) -> u32 {
            99
        }

        fn backend_display(&self) -> &str {
            "invalid-test"
        }
    }

    #[test]
    fn software_container_baseline_signs_verifies_and_rejects_wrong_key() {
        let signer = RingTestSigner::new("software", 1);
        let wrong = RingTestSigner::new("software", 1);
        let baseline = make_baseline(&signer);

        assert_eq!(baseline.signing_backend.as_deref(), Some("software"));
        assert_eq!(baseline.key_version, 1);
        assert!(baseline.verify_signature(signer.public_key()));
        assert!(!baseline.verify_signature(wrong.public_key()));
    }

    #[test]
    fn se050_baseline_preserves_backend_version_and_rejects_wrong_key() {
        let signer = RingTestSigner::new("SE050", 3);
        let wrong = RingTestSigner::new("SE050", 3);
        let baseline = make_baseline(&signer);

        assert_eq!(baseline.signing_backend.as_deref(), Some("SE050"));
        assert_eq!(baseline.key_version, 3);
        assert_eq!(
            baseline.signature_format.as_deref(),
            Some("ecdsa-p256-sha256-fixed")
        );
        assert!(baseline.verify_signature(signer.public_key()));
        assert!(!baseline.verify_signature(wrong.public_key()));
    }

    #[test]
    fn tpm_baseline_preserves_backend_version_and_rejects_wrong_key() {
        let signer = RingTestSigner::new("TPM 2.0", 2);
        let wrong = RingTestSigner::new("TPM 2.0", 2);
        let baseline = make_baseline(&signer);

        assert_eq!(baseline.signing_backend.as_deref(), Some("TPM 2.0"));
        assert_eq!(baseline.key_version, 2);
        assert!(baseline.verify_signature(signer.public_key()));
        assert!(!baseline.verify_signature(wrong.public_key()));
    }

    #[test]
    fn baseline_and_device_paths_handle_node_ids_and_trailing_slashes() {
        assert_eq!(
            baseline_path_for("node-7"),
            "/etc/sgx-guardian/pcr_node-7_baseline.json"
        );

        let old = std::env::var_os(KEY_DIR_ENV);
        std::env::set_var(KEY_DIR_ENV, "/tmp/device-keys///");
        assert_eq!(
            device_key_path("node_A"),
            "/tmp/device-keys/device_node_A.key"
        );
        match old {
            Some(value) => std::env::set_var(KEY_DIR_ENV, value),
            None => std::env::remove_var(KEY_DIR_ENV),
        }
    }

    #[test]
    fn environment_boolean_accepts_only_documented_true_values() {
        let key = "SGX_TEST_PCR_BOOLEAN";
        let old = std::env::var_os(key);
        for value in ["1", "true", "TRUE", "yes", "on"] {
            std::env::set_var(key, value);
            assert!(env_true(key), "{value}");
        }
        for value in ["0", "false", "True", "YES", "off", ""] {
            std::env::set_var(key, value);
            assert!(!env_true(key), "{value}");
        }
        match old {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn baseline_creation_rejects_a_signature_that_fails_self_check() {
        let error = create_signed_baseline(
            vec!["a".repeat(64)],
            "b".repeat(64),
            "2026-08-31T00:00:00Z".into(),
            "device".into(),
            1,
            &InvalidSigner,
        )
        .expect_err("invalid signature");
        assert!(error.to_string().contains("signature self-check failed"));
        assert!(error.to_string().contains("invalid-test DKP v99"));
    }
}
