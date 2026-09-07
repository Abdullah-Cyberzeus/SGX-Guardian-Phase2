use once_cell::sync::Lazy;
use tokio::sync::{Mutex, MutexGuard};

static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub async fn async_env_lock() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK.lock().await
}

pub fn blocking_env_lock() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK.blocking_lock()
}

/// Serializes every test that binds the fixed `REGISTRY_SYNC_PORT`.
///
/// `nebula::registry_sync`, `did::tests::resolver_tests` and `api::tests` all
/// stand up a mock CA on that one hardcoded port. Within a single test binary
/// they are otherwise free to overlap — and a listener that is still closing
/// when the next test binds produces a flaky `AddrInUse`. One lock shared by
/// all three call sites is what makes that impossible, so it lives here rather
/// than privately inside any one of them.
static REGISTRY_PORT_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub async fn registry_port_lock() -> MutexGuard<'static, ()> {
    REGISTRY_PORT_LOCK.lock().await
}

/// A fully redirected Guardian state tree — DID documents, VCs, Circles,
/// transfers and Vault — rooted in one temp directory.
///
/// Handler-level tests keep failing at the first authorization hop
/// (`local_active_circle_ids`) unless a real signed identity and a seeded
/// Circle registry exist on disk. Building that by hand in every handler
/// module is what previously kept those code paths untested, so the harness
/// lives here and is shared.
pub mod guardian {
    use crate::did::doc_persistence::{
        save_ca_aggregate, save_peer, save_self, CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV,
        SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
    };
    use crate::did::doc_sign;
    use crate::did::document::{DidDocument, DocBuildInput};
    use crate::did::persistence::{DerivationProof, DidRecord};
    use crate::key_manager::KeyManager;
    use crate::vc::credential::VerifiableCredential;
    use crate::vc::issue;
    use chrono::Utc;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    pub const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";

    /// Every environment variable the harness redirects, paired with the
    /// path (relative to the temp root) it is pointed at.
    const REDIRECTED: &[(&str, &str)] = &[
        (SELF_DOC_PATH_ENV, "did_doc.json"),
        (PEERS_DOC_DIR_ENV, "peers"),
        (CA_AGGREGATE_PATH_ENV, "aggregate.json"),
        (VERSION_COUNTER_PATH_ENV, "version_counter"),
        (DID_PATH_ENV, "did.json"),
    ];

    pub struct GuardianEnv {
        saved: Vec<(&'static str, Option<OsString>)>,
        root: TempDir,
    }

    impl GuardianEnv {
        /// Redirects every Guardian state path into a fresh temp tree.
        /// Callers must hold [`crate::test_support::async_env_lock`] (or the
        /// blocking equivalent) because the process environment is global.
        pub fn new() -> Self {
            let root = TempDir::new().expect("guardian temp root");
            let mut saved = Vec::new();
            let mut redirect = |key: &'static str, path: PathBuf| {
                saved.push((key, std::env::var_os(key)));
                std::env::set_var(key, path);
            };
            for (key, relative) in REDIRECTED {
                redirect(key, root.path().join(relative));
            }
            redirect(
                crate::vc::persistence::VC_BASE_ENV,
                root.path().join("vc"),
            );
            redirect(
                crate::circle::persistence::CIRCLE_BASE_ENV,
                root.path().join("circles"),
            );
            redirect(issue::DEVICE_KEY_DIR_ENV, root.path().join("keys"));
            redirect(
                crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
                root.path().join("virtual-id"),
            );
            redirect(
                crate::xfer::persistence::XFER_BASE_ENV,
                root.path().join("xfer"),
            );
            Self { saved, root }
        }

        pub fn path(&self) -> &Path {
            self.root.path()
        }
    }

    impl Drop for GuardianEnv {
        fn drop(&mut self) {
            for (key, previous) in self.saved.drain(..) {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// The signed local identity produced by [`seed_owner`].
    pub struct SeededOwner {
        pub key_manager: KeyManager,
        pub record: DidRecord,
        pub document: DidDocument,
        pub owner_vc: VerifiableCredential,
    }

    /// Writes a signed DID document, DID record and Owner membership VC for
    /// `did` so Circle registry seeding and every authorization helper that
    /// reads them succeed.
    pub fn seed_owner(node_name: &str, did: &str, overlay_ip_cidr: &str) -> SeededOwner {
        let key_dir = std::env::var(issue::DEVICE_KEY_DIR_ENV).expect("device key dir");
        std::fs::create_dir_all(&key_dir).expect("create key dir");
        let key_path = Path::new(&key_dir).join(format!("device_{}.key", node_name));
        let key_manager =
            KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
        let pubkey = key_manager.pubkey_der().expect("pubkey");
        let parsed = crate::did::Did::parse(did).expect("parse seeded did");
        let now = Utc::now().to_rfc3339();
        let record = DidRecord {
            did: did.to_string(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: parsed.msi().to_string(),
            did_id_hex: hex::encode(parsed.id_bytes()),
            created_at: now.clone(),
            deactivated_at: None,
            derivation: DerivationProof {
                se050_uid: "01".into(),
                se050_uid_source: "test".into(),
                dkp_v1_pubkey_sha256_b16: "01".into(),
                dkp_v1_pubkey_path: "test".into(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "01".into(),
                dik_pubkey_der_b64: None,
            },
            current_dkp_version: 1,
            deriv_signature_b64: String::new(),
        };
        let mut document = DidDocument::build(DocBuildInput {
            did,
            node_name: Some(node_name),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &pubkey,
            overlay_ip_cidr: Some(overlay_ip_cidr),
            attestation_bind: None,
            cert_bootstrap_bind: Some((
                overlay_ip_cidr.split('/').next().unwrap_or("127.0.0.1"),
                50061,
            )),
            revoked: vec![],
            previous_version_id: 0,
            created_at: Some(now),
            status: Some("active".into()),
        })
        .expect("build did document");
        let vm_ref = document
            .verification_method
            .first()
            .expect("verification method")
            .id
            .clone();
        doc_sign::sign_in_place(&mut document, &key_manager, &vm_ref).expect("sign did document");

        record
            .save(&std::env::var(DID_PATH_ENV).expect("did path"))
            .expect("save did record");
        save_self(&document).expect("save self doc");
        save_peer(&document).expect("save peer doc");
        save_ca_aggregate(std::slice::from_ref(&document)).expect("save ca aggregate");
        let owner_vc = issue::ensure_owner_vc(&record, &key_manager).expect("owner vc");

        SeededOwner {
            key_manager,
            record,
            document,
            owner_vc,
        }
    }
}
