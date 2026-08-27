use super::components::{
    assert_no_private_identity_paths, component_manifest, component_paths, gather_files,
};
use super::crypto;
use super::model::Component;
use crate::api::state::AppState;
use crate::backup::create::create_backup;
use crate::backup::errors::BackupError;
use crate::backup::restore::journal::{self, RestoreJournal, RestorePhase};
use crate::backup::restore::{
    destructive_apply_enabled, RestoreAction, RestoreMode, RestorePreflightOptions,
};
use crate::backup::{init, BackupConfig};
use base64::engine::general_purpose;
use base64::Engine as _;
use chrono::Utc;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::sync::Mutex;

#[test]
fn encrypted_bundle_round_trips_and_rejects_wrong_secret_or_tamper() {
    let plaintext = vec![42_u8; 150_000];
    let mut encrypted = Vec::new();
    crypto::encrypt_to_writer(&plaintext, "correct horse battery staple", &mut encrypted)
        .expect("encrypt");

    let decrypted =
        crypto::decrypt_bundle_bytes(&encrypted, "correct horse battery staple").expect("decrypt");
    assert_eq!(decrypted, plaintext);

    assert!(crypto::decrypt_bundle_bytes(&encrypted, "wrong").is_err());
    let last = encrypted.len() - 12;
    encrypted[last] ^= 0x55;
    assert!(crypto::decrypt_bundle_bytes(&encrypted, "correct horse battery staple").is_err());
}

#[test]
fn component_map_excludes_private_identity_key_files() {
    let (_temp, state) = test_state("nodeA");
    let paths = component_paths(&state);
    assert_no_private_identity_paths(&paths).expect("no private identity paths");
    assert!(paths.iter().any(|path| {
        path.component == Component::Tls
            && path.source.to_string_lossy().contains("device_nodeA.key")
    }));
    assert!(paths.iter().any(|path| {
        path.component == Component::IdentityMeta
            && path.source
                == Path::new(&state.keys_dir)
                    .parent()
                    .expect("test data root")
                    .join("identity/did.json")
    }));
    assert!(!paths.iter().any(|path| {
        path.component != Component::Tls && path.source.to_string_lossy().contains("identity.key")
    }));
}

#[test]
fn known_public_key_files_are_allowed_by_backup_filter() {
    let (_temp, state) = test_state("nodeA");
    let paths = component_paths(&state);

    assert_has_source(
        &paths,
        Component::Config,
        "/etc/sgx-guardian/guardian_public.key",
        "config/guardian_public.key",
    );
    assert_has_source(
        &paths,
        Component::Policy,
        "/etc/sgx-guardian/policies/pa_admin_pub.der",
        "policy/pa_admin_pub.der",
    );
    assert_no_private_identity_paths(&paths).expect("public key paths should be accepted");
}

#[test]
fn private_key_files_remain_blocked_by_backup_filter() {
    for source in [
        "/etc/sgx-guardian/guardian_private.key",
        "/etc/sgx-guardian/policies/pa_admin_priv.der",
        "/var/lib/sgx-guardian/identity/identity.key",
        "/var/lib/sgx-guardian/nebula/ca/ca.key",
        "/var/lib/sgx-guardian/nebula/nodes/nodeA.key",
        "/var/lib/sgx-guardian/keys/dkp.key",
        "/var/lib/sgx-guardian/keys/dik.key",
        "/var/lib/sgx-guardian/keys/dkp_private.der",
    ] {
        let path = super::components::ComponentPath {
            component: Component::Config,
            source: source.into(),
            archive_path: "forbidden".to_string(),
            recursive: false,
        };
        assert!(
            assert_no_private_identity_paths(&[path]).is_err(),
            "private key path should be blocked: {source}"
        );
    }
}

#[test]
fn startup_init_creates_missing_backup_storage_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024,
    };

    init::initialize_storage(&config).expect("initialize backup storage");

    assert_required_backup_dirs(&config);
}

#[test]
fn startup_init_completes_partially_existing_backup_storage_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024,
    };
    std::fs::create_dir_all(config.bundles_dir()).expect("precreate bundles");

    init::initialize_storage(&config).expect("initialize partial backup storage");

    assert_required_backup_dirs(&config);
}

#[test]
fn startup_init_preserves_existing_backup_data() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024,
    };
    std::fs::create_dir_all(config.bundles_dir()).expect("bundles dir");
    std::fs::write(config.bundle_path("bak-existing"), b"bundle-bytes").expect("bundle");
    std::fs::write(config.history_path(), b"{\"records\":[]}").expect("history");

    init::initialize_storage(&config).expect("initialize existing backup storage");

    assert_eq!(
        std::fs::read(config.bundle_path("bak-existing")).expect("read bundle"),
        b"bundle-bytes"
    );
    assert_eq!(
        std::fs::read(config.history_path()).expect("read history"),
        b"{\"records\":[]}"
    );
}

#[cfg(unix)]
#[test]
fn startup_init_corrects_backup_directory_permissions_to_0700() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024,
    };
    for dir in required_backup_dirs(&config) {
        std::fs::create_dir_all(&dir).expect("create insecure dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod insecure dir");
    }

    init::initialize_storage(&config).expect("initialize permissions");

    for dir in required_backup_dirs(&config) {
        assert_mode(dir, 0o700);
    }
}

#[cfg(unix)]
#[test]
fn startup_init_fails_when_backup_storage_cannot_be_created() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let readonly_parent = temp.path().join("readonly");
    std::fs::create_dir(&readonly_parent).expect("readonly parent");
    std::fs::set_permissions(&readonly_parent, std::fs::Permissions::from_mode(0o500))
        .expect("chmod readonly parent");
    let config = BackupConfig {
        base_dir: readonly_parent.join("backup"),
        max_bundle_bytes: 1024,
    };

    let result = init::initialize_storage(&config);

    std::fs::set_permissions(&readonly_parent, std::fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions");
    assert!(
        result.is_err(),
        "initialization should fail on permission denied storage"
    );
}

#[test]
fn component_map_uses_node_specific_yaml_without_peer_node_configs() {
    let (temp, state) = test_state("nodeA");
    let paths = component_paths(&state);
    let config_dir = temp.path().join("config");

    assert_has_source(
        &paths,
        Component::Config,
        config_dir.join("nodeA.yaml"),
        "config/nodeA.yaml",
    );
    assert!(!paths
        .iter()
        .any(|path| path.source == config_dir.join("nodeB.yaml")));
    assert!(!paths
        .iter()
        .any(|path| path.source == config_dir.join("nodeC.yaml")));
}

#[test]
fn component_map_includes_runtime_state_identity_credentials_and_nebula() {
    let (temp, state) = test_state("nodeA");
    let paths = component_paths(&state);

    assert_has_source(
        &paths,
        Component::Config,
        temp.path().join("discovery-config/nmap.yaml"),
        "config/discovery/nmap.yaml",
    );
    assert_has_source(
        &paths,
        Component::Config,
        temp.path().join("discovery-config/whitelist.yaml"),
        "config/discovery/whitelist.yaml",
    );
    assert_has_source(
        &paths,
        Component::State,
        temp.path().join("pcr_nodeA_baseline.json"),
        "state/pcr/pcr_nodeA_baseline.json",
    );
    assert_has_source(
        &paths,
        Component::State,
        temp.path().join("pcr/nodeA_current.json"),
        "state/pcr/nodeA_current.json",
    );
    assert_has_source(
        &paths,
        Component::IdentityMeta,
        temp.path().join("identity/did_doc.json"),
        "identity/did_doc.json",
    );
    assert_has_tree(
        &paths,
        Component::IdentityMeta,
        temp.path().join("identity/peers"),
        "identity/peers",
    );
    assert_has_tree(
        &paths,
        Component::Credentials,
        temp.path().join("identity/vc/issued"),
        "credentials/vc/issued",
    );
    assert_has_tree(
        &paths,
        Component::Credentials,
        temp.path().join("identity/vc/own"),
        "credentials/vc/own",
    );
    assert_has_tree(
        &paths,
        Component::Credentials,
        temp.path().join("identity/vc/peers"),
        "credentials/vc/peers",
    );
    assert_has_source(
        &paths,
        Component::Credentials,
        temp.path().join("cot/members.json"),
        "credentials/cot/members.json",
    );
    assert_has_source(
        &paths,
        Component::State,
        temp.path().join("logs/trusted_peers_nodeA.json"),
        "state/trusted_peers_nodeA.json",
    );
    assert_has_source(
        &paths,
        Component::Nebula,
        temp.path().join("nebula/overlay_registry.json"),
        "nebula/overlay_registry.json",
    );
    assert_has_source(
        &paths,
        Component::Nebula,
        temp.path().join("nebula/lighthouse_registry.json"),
        "nebula/lighthouse_registry.json",
    );
    assert_has_source(
        &paths,
        Component::Nebula,
        temp.path().join("nebula/relay_registry.json"),
        "nebula/relay_registry.json",
    );
}

#[tokio::test]
async fn gathered_manifest_includes_required_runtime_components_and_excludes_private_keys() {
    let (temp, state) = test_state("nodeA");
    let root = temp.path();

    for (path, body) in [
        ("config/nodeA.yaml", "node_id: nodeA"),
        ("discovery-config/nmap.yaml", "enabled: true"),
        ("discovery-config/whitelist.yaml", "devices: []"),
        ("pcr_nodeA_baseline.json", "{}"),
        ("pcr/nodeA_current.json", "{}"),
        ("discovery-state/inventory.json", "{}"),
        ("identity/did.json", "{}"),
        ("identity/did_doc.json", "{}"),
        ("identity/circle_did_docs.json", "[]"),
        ("identity/peers/did_doc_peer.json", "{}"),
        ("identity/vc/issued/vc1.json", "{}"),
        ("identity/vc/own/vc2.json", "{}"),
        ("identity/vc/peers/vc3.json", "{}"),
        ("identity/vc/status_list.json", "{}"),
        ("identity/crl/crl.json", "{}"),
        ("identity/crl/entries/revoke1.json", "{}"),
        ("cot/members.json", "{}"),
        ("nebula/overlay_registry.json", "{}"),
        ("nebula/lighthouse_registry.json", "{}"),
        ("nebula/relay_registry.json", "{}"),
        ("nebula/ca/ca.crt", "CERT"),
        ("nebula/nodes/nodeA.crt", "CERT"),
        ("logs/trusted_peers.json", "[]"),
        ("logs/trusted_peers_nodeA.json", "[]"),
        ("logs/last_attestation.json", "{}"),
        ("logs/attestation_results.json", "[]"),
        ("sgx-agent/device_nodeA.key", "TLS-KEY"),
        ("sgx-agent/device_nodeA_cert.der", "TLS-CERT"),
    ] {
        write_seed(root.join(path), body);
    }

    for (path, body) in [
        ("identity/vc/own/private.key", "DO-NOT-BACKUP"),
        ("identity/peers/identity.key", "DO-NOT-BACKUP"),
        ("discovery-state/pa_admin_priv.der", "DO-NOT-BACKUP"),
        ("nebula/ca/ca.key", "DO-NOT-BACKUP"),
        ("nebula/nodes/nodeA.key", "DO-NOT-BACKUP"),
    ] {
        write_seed(root.join(path), body);
    }

    let files = gather_files(&state).await.expect("gather files");
    let archive_paths = files
        .iter()
        .map(|file| file.archive_path.as_str())
        .collect::<BTreeSet<_>>();
    let manifest = component_manifest(&files);
    let components = manifest
        .iter()
        .map(|entry| entry.component)
        .collect::<Vec<_>>();

    for component in [
        Component::Config,
        Component::Nebula,
        Component::IdentityMeta,
        Component::Tls,
        Component::Credentials,
        Component::Crl,
        Component::State,
    ] {
        assert!(
            components.contains(&component),
            "missing manifest component: {:?}",
            component
        );
    }

    for expected in [
        "config/nodeA.yaml",
        "config/discovery/nmap.yaml",
        "state/pcr/pcr_nodeA_baseline.json",
        "state/pcr/nodeA_current.json",
        "state/discovery/inventory.json",
        "state/trusted_peers.json",
        "state/trusted_peers_nodeA.json",
        "state/attestation/last_attestation.json",
        "state/attestation/attestation_results.json",
        "identity/did.json",
        "identity/did_doc.json",
        "identity/peers/did_doc_peer.json",
        "credentials/vc/issued/vc1.json",
        "credentials/vc/own/vc2.json",
        "credentials/vc/peers/vc3.json",
        "credentials/cot/members.json",
        "crl/crl.json",
        "crl/entries/revoke1.json",
        "nebula/overlay_registry.json",
        "nebula/lighthouse_registry.json",
        "nebula/relay_registry.json",
        "nebula/ca/ca.crt",
        "nebula/nodes/nodeA.crt",
        "tls/device_nodeA.key",
        "tls/device_nodeA_cert.der",
    ] {
        assert!(
            archive_paths.contains(expected),
            "missing archive path: {expected}"
        );
    }

    for forbidden in [
        "identity/peers/identity.key",
        "credentials/vc/own/private.key",
        "state/discovery/pa_admin_priv.der",
        "nebula/ca/ca.key",
        "nebula/nodes/nodeA.key",
    ] {
        assert!(
            !archive_paths.contains(forbidden),
            "private path leaked into backup: {forbidden}"
        );
    }

    assert!(!archive_paths.contains("config/nodeB.yaml"));
    assert!(!archive_paths.contains("config/nodeC.yaml"));
    assert!(!archive_paths.contains("nebula/nodes/nodeB.crt"));
    assert!(!archive_paths.contains("nebula/nodes/nodeC.crt"));
}

#[cfg(unix)]
#[tokio::test]
async fn backup_creation_applies_secure_filesystem_permissions() {
    let (temp, state) = test_state("nodeA");
    write_seed(temp.path().join("config/nodeA.yaml"), "node_id: nodeA");
    write_seed(temp.path().join("sgx-agent/device_nodeA.key"), "TLS-KEY");
    write_seed(
        temp.path().join("sgx-agent/device_nodeA_cert.der"),
        "TLS-CERT",
    );

    let backup_base = temp.path().join("backup");
    let config = BackupConfig {
        base_dir: backup_base.clone(),
        max_bundle_bytes: 1024 * 1024,
    };

    let record = create_backup(
        state,
        config.clone(),
        "correct horse battery staple".to_string(),
        true,
    )
    .await
    .expect("create backup");

    for dir in [
        backup_base.clone(),
        config.bundles_dir(),
        config.staging_dir(),
        config.pre_restore_dir(),
    ] {
        assert_mode(dir, 0o700);
    }

    assert_mode(config.history_path(), 0o600);
    assert_mode(Path::new(&record.bundle_path), 0o600);
    assert!(
        !config.history_path().with_extension("tmp").exists(),
        "history temp file should be atomically renamed away"
    );
}

#[tokio::test]
async fn restore_preflight_reports_new_device_skips_and_merge_actions() {
    let (temp, source_state) = test_state("nodeA");
    write_seed(temp.path().join("config/nodeA.yaml"), "node_id: nodeA");
    write_seed(temp.path().join("identity/did.json"), "{}");
    write_seed(temp.path().join("identity/vc/own/vc.json"), "{}");
    write_seed(temp.path().join("identity/crl/crl.json"), "{}");
    write_seed(temp.path().join("nebula/overlay_registry.json"), "{}");
    write_seed(temp.path().join("sgx-agent/device_nodeA.key"), "TLS-KEY");
    write_seed(
        temp.path().join("sgx-agent/device_nodeA_cert.der"),
        "TLS-CERT",
    );

    let backup_config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024 * 1024,
    };
    let record = create_backup(
        source_state,
        backup_config.clone(),
        "correct horse battery staple".to_string(),
        true,
    )
    .await
    .expect("create backup");

    let (_target_temp, target_state) = test_state("nodeB");
    let report = crate::backup::restore::validate_restore(
        target_state,
        backup_config,
        &record.id,
        "correct horse battery staple".to_string(),
        RestorePreflightOptions::default(),
    )
    .await
    .expect("restore preflight");

    assert_eq!(report.mode, RestoreMode::NewDeviceMigration);
    assert_plan_action(&report.plan, Component::IdentityMeta, RestoreAction::Skip);
    assert_plan_action(&report.plan, Component::Tls, RestoreAction::Skip);
    assert_plan_action(&report.plan, Component::Nebula, RestoreAction::Skip);
    assert_plan_action(&report.plan, Component::Credentials, RestoreAction::Merge);
    assert_plan_action(&report.plan, Component::Crl, RestoreAction::Merge);
}

#[test]
fn destructive_restore_is_enabled_by_default_without_environment_gate() {
    assert!(destructive_apply_enabled());
}

#[tokio::test(flavor = "current_thread")]
async fn restore_apply_is_available_by_default_and_requires_confirm_then_commits() {
    let _lock = policy_env_lock().lock().await;
    let (temp, state) = test_state("nodeA");
    write_seed(
        temp.path().join("identity/crl/crl.json"),
        "{\"sequence\":2,\"entries\":[]}\n",
    );
    write_seed(temp.path().join("sgx-agent/device_nodeA.key"), "TLS-KEY");
    write_seed(
        temp.path().join("sgx-agent/device_nodeA_cert.der"),
        "TLS-CERT",
    );
    let backup_config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024 * 1024,
    };
    let record = create_backup(
        state.clone(),
        backup_config.clone(),
        "correct horse battery staple".to_string(),
        true,
    )
    .await
    .expect("create backup");
    std::fs::remove_file(temp.path().join("identity/crl/crl.json")).expect("remove CRL");

    let missing_confirm = crate::backup::restore::apply_restore(
        state.clone(),
        backup_config.clone(),
        &record.id,
        "correct horse battery staple".to_string(),
        RestorePreflightOptions {
            components: vec![Component::Crl],
            allow_policy_rollback: false,
        },
        false,
    )
    .await
    .expect_err("apply should require confirm");
    assert!(matches!(
        missing_confirm,
        crate::backup::errors::BackupError::InvalidRequest(_)
    ));

    let report = crate::backup::restore::validate_restore(
        state.clone(),
        backup_config.clone(),
        &record.id,
        "correct horse battery staple".to_string(),
        RestorePreflightOptions {
            components: vec![Component::Crl],
            allow_policy_rollback: false,
        },
    )
    .await
    .expect("validate restore");
    assert!(report.destructive_apply_enabled);

    let applied = crate::backup::restore::apply_restore(
        state,
        backup_config,
        &record.id,
        "correct horse battery staple".to_string(),
        RestorePreflightOptions {
            components: vec![Component::Crl],
            allow_policy_rollback: false,
        },
        true,
    )
    .await
    .expect("restore apply");
    assert_eq!(applied.status, "committed");
    assert_eq!(
        std::fs::read_to_string(temp.path().join("identity/crl/crl.json")).expect("read CRL"),
        "{\"sequence\":2,\"entries\":[]}\n"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn restore_apply_denies_policy_rollback_as_atomic_skip() {
    let _lock = policy_env_lock().lock().await;
    let case = policy_restore_case("1.0.0", "1.0.1")
        .await
        .expect("policy restore case");
    let originals = policy_file_contents(&case.policy_dir);

    let report = apply_policy_restore(&case, false)
        .await
        .expect("restore apply");

    assert_eq!(report.status, "committed_policy_skipped");
    assert!(report.message.contains("applied 0 files"));
    assert!(report.message.contains("policy skipped"));
    assert_eq!(policy_file_contents(&case.policy_dir), originals);

    let journal = journal::load_current(&case.backup_config)
        .expect("load journal")
        .expect("journal present");
    let journal_message = journal.message.expect("journal message");
    assert!(journal_message.contains("policy skipped"));
    assert!(journal_message.contains("1.0.0"));
    assert!(journal_message.contains("1.0.1"));
}

#[tokio::test(flavor = "current_thread")]
async fn restore_apply_allows_same_policy_version() {
    let _lock = policy_env_lock().lock().await;
    let case = policy_restore_case("1.0.1", "1.0.1")
        .await
        .expect("policy restore case");

    let report = apply_policy_restore(&case, false)
        .await
        .expect("restore apply");

    assert_eq!(report.status, "committed");
    assert!(report.message.contains("applied 4 files"));
    assert_policy_restored(&case);
}

#[tokio::test(flavor = "current_thread")]
async fn restore_apply_allows_authorised_policy_rollback() {
    let _lock = policy_env_lock().lock().await;
    let case = policy_restore_case("1.0.0", "1.0.1")
        .await
        .expect("policy restore case");

    let report = apply_policy_restore(&case, true)
        .await
        .expect("restore apply");

    assert_eq!(report.status, "committed");
    assert!(report.message.contains("applied 4 files"));
    assert_policy_restored(&case);
}

#[test]
fn interrupted_restore_journal_is_marked_rolled_back_on_recovery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024,
    };
    let journal = RestoreJournal {
        restore_id: "restore-1".to_string(),
        bundle_id: "bundle-1".to_string(),
        node_id: "nodeA".to_string(),
        phase: RestorePhase::Swapping,
        component_index: Some(2),
        snapshot_path: Some(
            config
                .pre_restore_dir()
                .join("restore-1")
                .display()
                .to_string(),
        ),
        updated_at: Utc::now().to_rfc3339(),
        message: None,
    };
    journal::write_journal(&config, &journal).expect("write journal");

    let recovered = journal::recover_if_interrupted_inner(&config, "nodeA")
        .expect("recover")
        .expect("interrupted journal");

    assert_eq!(recovered.phase, RestorePhase::RolledBack);
    let status = journal::status(&config).expect("status");
    assert_eq!(
        status.journal.expect("journal").phase,
        RestorePhase::RolledBack
    );
}

fn test_state(node_id: &str) -> (tempfile::TempDir, std::sync::Arc<AppState>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let state = AppState::for_tests(
        temp.path(),
        node_id,
        temp.path().join("config").display().to_string(),
    );
    (temp, state)
}

struct EnvVarGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = self.prev.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct SignedPolicyFixture {
    yaml: String,
    envelope: String,
    pubkey: Vec<u8>,
}

struct PolicyRestoreCase {
    _temp: tempfile::TempDir,
    _policy_dir_guard: EnvVarGuard,
    state: std::sync::Arc<AppState>,
    backup_config: BackupConfig,
    backup_id: String,
    policy_dir: PathBuf,
    backup_policy: SignedPolicyFixture,
    backup_backup_yaml: String,
}

fn policy_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn policy_restore_case(
    backup_version: &str,
    active_version: &str,
) -> Result<PolicyRestoreCase, BackupError> {
    let (temp, state) = test_state("nodeA");
    let policy_dir = temp.path().join("policies");
    let policy_dir_guard = EnvVarGuard::set("SGX_GUARDIAN_POLICY_DIR", &policy_dir);
    let backup_policy = signed_policy_fixture(backup_version, "backup");
    let active_policy = signed_policy_fixture(active_version, "active");
    let backup_backup_yaml = policy_yaml(backup_version, "backup-previous");

    write_seed(policy_dir.join("active_policy.yaml"), &backup_policy.yaml);
    write_seed(policy_dir.join("backup_policy.yaml"), &backup_backup_yaml);
    write_seed(policy_dir.join("policy.sig"), &backup_policy.envelope);
    write_seed_bytes(policy_dir.join("pa_admin_pub.der"), &backup_policy.pubkey);

    let backup_config = BackupConfig {
        base_dir: temp.path().join("backup"),
        max_bundle_bytes: 1024 * 1024,
    };
    let record = create_backup(
        state.clone(),
        backup_config.clone(),
        "correct horse battery staple".to_string(),
        true,
    )
    .await?;

    write_seed(policy_dir.join("active_policy.yaml"), &active_policy.yaml);
    write_seed(
        policy_dir.join("backup_policy.yaml"),
        &policy_yaml(active_version, "active-previous"),
    );
    write_seed(policy_dir.join("policy.sig"), &active_policy.envelope);
    write_seed_bytes(policy_dir.join("pa_admin_pub.der"), &active_policy.pubkey);

    Ok(PolicyRestoreCase {
        _temp: temp,
        _policy_dir_guard: policy_dir_guard,
        state,
        backup_config,
        backup_id: record.id,
        policy_dir,
        backup_policy,
        backup_backup_yaml,
    })
}

async fn apply_policy_restore(
    case: &PolicyRestoreCase,
    allow_policy_rollback: bool,
) -> Result<crate::backup::model::RestoreReport, BackupError> {
    crate::backup::restore::apply_restore(
        case.state.clone(),
        case.backup_config.clone(),
        &case.backup_id,
        "correct horse battery staple".to_string(),
        RestorePreflightOptions {
            components: vec![Component::Policy],
            allow_policy_rollback,
        },
        true,
    )
    .await
}

fn assert_policy_restored(case: &PolicyRestoreCase) {
    assert_eq!(
        std::fs::read_to_string(case.policy_dir.join("active_policy.yaml"))
            .expect("read active policy"),
        case.backup_policy.yaml
    );
    assert_eq!(
        std::fs::read_to_string(case.policy_dir.join("policy.sig")).expect("read policy sig"),
        case.backup_policy.envelope
    );
    assert_eq!(
        std::fs::read_to_string(case.policy_dir.join("backup_policy.yaml"))
            .expect("read backup policy"),
        case.backup_backup_yaml
    );
    assert_eq!(
        std::fs::read(case.policy_dir.join("pa_admin_pub.der")).expect("read policy pubkey"),
        case.backup_policy.pubkey
    );
}

fn policy_file_contents(policy_dir: &Path) -> Vec<Vec<u8>> {
    [
        "active_policy.yaml",
        "backup_policy.yaml",
        "policy.sig",
        "pa_admin_pub.der",
    ]
    .iter()
    .map(|name| std::fs::read(policy_dir.join(name)).expect("read policy file"))
    .collect()
}

fn signed_policy_fixture(version: &str, id_suffix: &str) -> SignedPolicyFixture {
    let yaml = policy_yaml(version, id_suffix);
    let signing_key = SigningKey::random(&mut OsRng);
    let digest = Sha256::digest(yaml.as_bytes());
    let signature: Signature = signing_key.sign(&digest);
    let pubkey = signing_key.verifying_key().to_encoded_point(false);
    let pubkey_bytes = pubkey.as_bytes().to_vec();
    let envelope = serde_json::json!({
        "version": 1,
        "policy_b64": general_purpose::STANDARD.encode(yaml.as_bytes()),
        "digest_hex": hex::encode(digest),
        "signature_b64": general_purpose::STANDARD.encode(signature.to_der().as_bytes()),
        "signing_pubkey_b64": general_purpose::STANDARD.encode(&pubkey_bytes)
    })
    .to_string();

    SignedPolicyFixture {
        yaml,
        envelope,
        pubkey: pubkey_bytes,
    }
}

fn policy_yaml(version: &str, id_suffix: &str) -> String {
    format!(
        "policy_id: \"policy-{id_suffix}\"\nversion: \"{version}\"\nrules:\n  - id: \"allow-{id_suffix}\"\n    action: \"ALLOW\"\n    src: \"10.0.0.0/24\"\n    dst: \"0.0.0.0/0\"\n    protocol: \"TCP\"\n    port: 443\n"
    )
}

fn assert_has_source(
    paths: &[super::components::ComponentPath],
    component: Component,
    source: impl AsRef<Path>,
    archive_path: &str,
) {
    let source = source.as_ref();
    assert!(
        paths.iter().any(|path| {
            path.component == component
                && path.source == source
                && path.archive_path == archive_path
                && !path.recursive
        }),
        "missing component path: {:?} {} -> {}",
        component,
        source.display(),
        archive_path
    );
}

fn assert_has_tree(
    paths: &[super::components::ComponentPath],
    component: Component,
    source: impl AsRef<Path>,
    archive_path: &str,
) {
    let source = source.as_ref();
    assert!(
        paths.iter().any(|path| {
            path.component == component
                && path.source == source
                && path.archive_path == archive_path
                && path.recursive
        }),
        "missing component tree: {:?} {} -> {}",
        component,
        source.display(),
        archive_path
    );
}

fn assert_plan_action(
    plan: &[crate::backup::restore::PlannedComponent],
    component: Component,
    action: RestoreAction,
) {
    let planned = plan
        .iter()
        .find(|entry| entry.component == component)
        .unwrap_or_else(|| panic!("missing restore plan component: {:?}", component));
    assert_eq!(planned.action, action);
}

fn write_seed(path: impl AsRef<Path>, body: &str) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("seed parent");
    }
    std::fs::write(path, body).expect("seed file");
}

fn write_seed_bytes(path: impl AsRef<Path>, body: &[u8]) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("seed parent");
    }
    std::fs::write(path, body).expect("seed file");
}

fn required_backup_dirs(config: &BackupConfig) -> Vec<std::path::PathBuf> {
    vec![
        config.base_dir.clone(),
        config.bundles_dir(),
        config.staging_dir(),
        config.restore_dir(),
        config.pre_restore_dir(),
    ]
}

fn assert_required_backup_dirs(config: &BackupConfig) {
    for dir in required_backup_dirs(config) {
        assert!(dir.is_dir(), "missing backup directory {}", dir.display());
        #[cfg(unix)]
        assert_mode(dir, 0o700);
    }
}

#[cfg(unix)]
fn assert_mode(path: impl AsRef<Path>, expected: u32) {
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_ref();
    let mode = std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        expected,
        "unexpected permissions for {}",
        path.display()
    );
}
