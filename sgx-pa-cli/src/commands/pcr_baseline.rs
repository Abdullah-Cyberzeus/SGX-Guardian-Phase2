use base64::Engine as _;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
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
const BASELINE_HISTORY_PATH: &str = "/var/log/sgx-guardian/pcr_baseline_history.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineHistoryEntry {
    event_type: String,
    action: String,
    timestamp: String,
    node: String,
    baseline_id: String,
    hash: String,
    previous_hash: Option<String>,
    registers: Vec<String>,
    key_version: u32,
    schema_version: u8,
    signing_backend: Option<String>,
    signature_format: Option<String>,
}

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
    let previous_baseline = PcrBaseline::load(&bl_path).ok();
    if let Some(parent) = Path::new(&bl_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    match baseline.save(&bl_path) {
        Ok(_) => {
            let action = if previous_baseline.is_some() {
                "updated"
            } else {
                "created"
            };
            if let Err(e) =
                append_baseline_history(&node_id, &baseline, previous_baseline.as_ref(), action)
            {
                eprintln!("  ⚠️ Baseline history save failed: {}", e);
            }
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

fn append_baseline_history(
    node_id: &str,
    baseline: &PcrBaseline,
    previous_baseline: Option<&PcrBaseline>,
    action: &str,
) -> anyhow::Result<()> {
    let entry = BaselineHistoryEntry {
        event_type: "baseline".to_string(),
        action: action.to_string(),
        timestamp: baseline.created_at.clone(),
        node: node_id.to_string(),
        baseline_id: format!("pcr-{}-baseline", node_id),
        hash: baseline.composite_digest.clone(),
        previous_hash: previous_baseline.map(|baseline| baseline.composite_digest.clone()),
        registers: baseline.pcr_values.clone(),
        key_version: baseline.key_version,
        schema_version: baseline.schema_version,
        signing_backend: baseline.signing_backend.clone(),
        signature_format: baseline.signature_format.clone(),
    };

    let mut entries: Vec<BaselineHistoryEntry> = fs::read_to_string(BASELINE_HISTORY_PATH)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    entries.push(entry);
    if entries.len() > 100 {
        entries.drain(0..entries.len() - 100);
    }

    if let Some(parent) = Path::new(BASELINE_HISTORY_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        BASELINE_HISTORY_PATH,
        serde_json::to_string_pretty(&entries)?,
    )?;
    Ok(())
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

/// Resolve the signer for baseline creation/verification using only an
/// already-provisioned key. This deliberately never calls a key-manager
/// `init_*`/`load_or_generate` path: those can repair DKP metadata, rotate
/// keys, or provision a brand-new SE050/TPM/software key, any of which would
/// silently change the device's signing identity as a side effect of what
/// should be a read-only "create a baseline" action. Key generation,
/// metadata repair, and key rotation remain separate operations that require
/// explicit confirmation (see the key/DKP management commands).
fn load_active_baseline_signer(node_id: &str) -> anyhow::Result<Box<dyn BaselineSigner>> {
    let key_path = device_key_path(node_id);

    if env_true("SGX_FORCE_SOFTWARE_KEYS") || env_true("SGX_DISABLE_SE050_DKP") {
        return signer_from_key_manager(KeyManager::load_existing(&key_path)?);
    }

    #[cfg(feature = "tpm")]
    {
        let tpm_cfg = sgx_guardian_client::tpm::TpmConfig::default();
        if sgx_guardian_client::tpm::should_attempt(&tpm_cfg) {
            let km = KeyManager::load_active_tpm(&tpm_cfg, sgx_guardian_client::tpm::TPM_BASE_PATH)
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
        if Path::new(DKP_METADATA_PATH).exists() {
            let se_config = sgx_guardian_client::secure_element::config::SeConfig::default();
            signer_from_key_manager(KeyManager::load_active_se050(&se_config, SE_BASE_PATH)?)
        } else {
            signer_from_key_manager(KeyManager::load_existing(&key_path)?)
        }
    }

    #[cfg(not(feature = "secure-element"))]
    signer_from_key_manager(KeyManager::load_existing(&key_path)?)
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
    use std::sync::Mutex;

    // KEY_DIR_ENV is process-global; serialize every test that mutates it so they don't race
    // under the default multi-threaded test runner.
    static KEY_DIR_ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = KEY_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    fn run_create_reports_missing_snapshot_and_does_not_panic() {
        // /var/lib/sgx-guardian/pcr genuinely doesn't exist in this sandbox, so
        // find_pcr_snapshot() deterministically returns None and run_create() returns early
        // (it never calls std::process::exit, so this is safe to call in-process).
        run_create();
    }

    #[test]
    fn run_verify_reports_missing_snapshot_and_does_not_panic() {
        run_verify();
    }

    #[test]
    fn find_pcr_snapshot_returns_none_when_the_pcr_dir_is_absent() {
        assert_eq!(find_pcr_snapshot(), None);
    }

    #[test]
    fn load_active_baseline_signer_uses_a_software_key_when_forced() {
        let _guard = KEY_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key_dir = tempfile::tempdir().expect("tempdir");
        let key_dir_old = std::env::var_os(KEY_DIR_ENV);
        let force_old = std::env::var_os("SGX_FORCE_SOFTWARE_KEYS");
        std::env::set_var(KEY_DIR_ENV, key_dir.path());
        std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");

        // Baseline creation must only ever sign with an already-provisioned
        // key, so the key has to exist up front — provisioning it is a
        // separate, explicit step (not something baseline creation does).
        KeyManager::load_or_generate(&device_key_path("node-test-pcr"))
            .expect("provision a key ahead of baseline creation");

        let signer = load_active_baseline_signer("node-test-pcr").expect("software signer");
        assert!(!signer.public_key().is_empty());
        assert!(signer.dkp_version() >= 1);

        match key_dir_old {
            Some(value) => std::env::set_var(KEY_DIR_ENV, value),
            None => std::env::remove_var(KEY_DIR_ENV),
        }
        match force_old {
            Some(value) => std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", value),
            None => std::env::remove_var("SGX_FORCE_SOFTWARE_KEYS"),
        }
    }

    #[test]
    fn load_active_baseline_signer_refuses_to_provision_a_missing_software_key() {
        let _guard = KEY_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key_dir = tempfile::tempdir().expect("tempdir");
        let key_dir_old = std::env::var_os(KEY_DIR_ENV);
        let force_old = std::env::var_os("SGX_FORCE_SOFTWARE_KEYS");
        std::env::set_var(KEY_DIR_ENV, key_dir.path());
        std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");

        let error = match load_active_baseline_signer("node-missing-key") {
            Err(e) => e,
            Ok(_) => panic!("no key provisioned yet, so baseline creation must refuse"),
        };
        assert!(error.to_string().contains("No identity key found"));
        assert!(
            !Path::new(&device_key_path("node-missing-key")).exists(),
            "baseline creation must not have provisioned a key as a side effect"
        );

        match key_dir_old {
            Some(value) => std::env::set_var(KEY_DIR_ENV, value),
            None => std::env::remove_var(KEY_DIR_ENV),
        }
        match force_old {
            Some(value) => std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", value),
            None => std::env::remove_var("SGX_FORCE_SOFTWARE_KEYS"),
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
