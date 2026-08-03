use crate::backup::errors::BackupError;
use crate::backup::model::{Component, RestoreReport, ValidateReport};
use crate::backup::restore::journal::{RestoreJournal, RestorePhase};
use crate::backup::BackupConfig;
use chrono::Utc;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

pub mod journal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMode {
    SameDevice,
    NewDeviceMigration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreAction {
    VerifyOnly,
    Replace,
    Merge,
    Skip,
    Derived,
    PolicyLast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedComponent {
    pub component: Component,
    pub action: RestoreAction,
    pub reason: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePreflightReport {
    pub status: String,
    pub backup: ValidateReport,
    pub mode: RestoreMode,
    pub plan: Vec<PlannedComponent>,
    pub destructive_apply_enabled: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RestorePreflightOptions {
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub allow_policy_rollback: bool,
}

pub fn destructive_apply_enabled() -> bool {
    true
}

pub async fn validate_restore(
    state: Arc<crate::api::state::AppState>,
    config: BackupConfig,
    id: &str,
    passphrase: String,
    options: RestorePreflightOptions,
) -> Result<RestorePreflightReport, BackupError> {
    let backup = crate::backup::validate::validate_backup(state, config, id, passphrase).await?;
    let mode = if backup.same_device_identity {
        RestoreMode::SameDevice
    } else {
        RestoreMode::NewDeviceMigration
    };
    let selective = !options.components.is_empty();
    let mut warnings = backup.warnings.clone();
    if !options.allow_policy_rollback {
        warnings.push(
            "policy rollback is not authorised; older policy sequences will be skipped during apply"
                .to_string(),
        );
    }

    let plan = backup
        .components
        .iter()
        .filter(|component| !selective || options.components.contains(&component.component))
        .map(|component| {
            let (action, reason) = plan_component(component.component, mode);
            PlannedComponent {
                component: component.component,
                action,
                reason: reason.to_string(),
                paths: component.paths.clone(),
            }
        })
        .collect();

    Ok(RestorePreflightReport {
        status: "ok".to_string(),
        backup,
        mode,
        plan,
        destructive_apply_enabled: destructive_apply_enabled(),
        warnings,
    })
}

pub async fn restore_backup() -> Result<RestoreReport, BackupError> {
    Err(BackupError::RestoreUnavailable(
        "legacy /backup/restore is not used; call /api/v1/restore/validate and /api/v1/restore/apply with confirm=true".to_string(),
    ))
}

pub async fn apply_restore(
    state: Arc<crate::api::state::AppState>,
    config: BackupConfig,
    id: &str,
    passphrase: String,
    options: RestorePreflightOptions,
    confirm: bool,
) -> Result<RestoreReport, BackupError> {
    if !confirm {
        return Err(BackupError::InvalidRequest(
            "restore apply requires confirm=true".to_string(),
        ));
    }
    let _restore_guard = restore_lock().try_lock().map_err(|_| {
        BackupError::InvalidRequest("restore operation already in progress".to_string())
    })?;
    reject_in_flight_restore(&config)?;

    let preflight = validate_restore(
        state.clone(),
        config.clone(),
        id,
        passphrase.clone(),
        options.clone(),
    )
    .await?;
    let decoded = crate::backup::validate::decode_backup_by_id(&config, id, &passphrase).await?;
    let restore_id = format!("restore-{}", Uuid::new_v4());
    let snapshot_path = config.pre_restore_dir().join(&restore_id);
    let staging_path = journal::restore_staging_dir(&config).join(&restore_id);
    create_secure_dir_all(&snapshot_path).await?;
    create_secure_dir_all(&staging_path).await?;

    let mut journal = RestoreJournal {
        restore_id: restore_id.clone(),
        bundle_id: id.to_string(),
        node_id: state.node_id.clone(),
        phase: RestorePhase::Prepared,
        component_index: None,
        snapshot_path: Some(snapshot_path.to_string_lossy().to_string()),
        updated_at: Utc::now().to_rfc3339(),
        message: Some("restore transaction prepared".to_string()),
    };
    journal::write_journal(&config, &journal)?;

    let mut entries = build_apply_entries(&state, &preflight, &decoded.files, &options)?;
    let policy_decision = validate_policy_entries(&mut entries, options.allow_policy_rollback)?;
    entries.sort_by_key(|entry| restore_order(entry.component));
    let rollback = snapshot_targets(&entries, &snapshot_path).await?;
    journal.phase = RestorePhase::Snapshotted;
    journal.updated_at = Utc::now().to_rfc3339();
    journal.message = Some(match &policy_decision {
        PolicyRestoreDecision::Skipped { reason } => {
            format!("pre-restore snapshot captured; policy skipped: {}", reason)
        }
        _ => "pre-restore snapshot captured".to_string(),
    });
    journal::write_journal(&config, &journal)?;

    stage_entries(&entries, &staging_path).await?;
    journal.phase = RestorePhase::Staged;
    journal.updated_at = Utc::now().to_rfc3339();
    journal.message = Some("restore files staged".to_string());
    journal::write_journal(&config, &journal)?;

    let pre_crl_count = count_crl_entries(&state).await?;
    let mut applied = Vec::new();
    let result = async {
        for (idx, entry) in entries.iter().enumerate() {
            journal.phase = RestorePhase::Swapping;
            journal.component_index = Some(idx);
            journal.updated_at = Utc::now().to_rfc3339();
            journal.message = Some(format!("applying {}", entry.archive_path));
            journal::write_journal(&config, &journal)?;
            apply_entry(entry).await?;
            applied.push(entry.target.clone());
        }
        journal.phase = RestorePhase::Swapped;
        journal.updated_at = Utc::now().to_rfc3339();
        journal.message = Some("all selected restore files swapped".to_string());
        journal::write_journal(&config, &journal)?;

        journal.phase = RestorePhase::Verifying;
        journal.updated_at = Utc::now().to_rfc3339();
        journal.message = Some("verifying restore invariants".to_string());
        journal::write_journal(&config, &journal)?;
        verify_after_apply(&state, pre_crl_count).await?;
        Ok::<(), BackupError>(())
    }
    .await;

    if let Err(error) = result {
        journal.phase = RestorePhase::RollingBack;
        journal.updated_at = Utc::now().to_rfc3339();
        journal.message = Some(format!("restore failed; rolling back: {}", error));
        journal::write_journal(&config, &journal)?;
        rollback_targets(&rollback).await?;
        journal.phase = RestorePhase::RolledBack;
        journal.updated_at = Utc::now().to_rfc3339();
        journal.message = Some(format!("restore rolled back after failure: {}", error));
        journal::write_journal(&config, &journal)?;
        return Err(error);
    }

    journal.phase = RestorePhase::Committed;
    journal.updated_at = Utc::now().to_rfc3339();
    journal.message = Some(format!(
        "restore committed; applied {} files{}",
        applied.len(),
        policy_decision.journal_suffix()
    ));
    journal::write_journal(&config, &journal)?;
    Ok(RestoreReport {
        status: match &policy_decision {
            PolicyRestoreDecision::Skipped { .. } => "committed_policy_skipped".to_string(),
            _ => "committed".to_string(),
        },
        message: format!(
            "restore {} committed; applied {} files{}; restart required for in-memory state",
            restore_id,
            applied.len(),
            policy_decision.report_suffix()
        ),
        restart_required: true,
    })
}

pub async fn undo_restore(
    config: BackupConfig,
    confirm: bool,
) -> Result<RestoreReport, BackupError> {
    if !confirm {
        return Err(BackupError::InvalidRequest(
            "restore undo requires confirm=true".to_string(),
        ));
    }
    let _restore_guard = restore_lock().try_lock().map_err(|_| {
        BackupError::InvalidRequest("restore operation already in progress".to_string())
    })?;
    let Some(mut journal) = journal::load_current(&config)? else {
        return Err(BackupError::NotFound("restore journal".to_string()));
    };
    let Some(snapshot_path) = journal.snapshot_path.clone() else {
        return Err(BackupError::InvalidRequest(
            "restore journal does not contain a snapshot path".to_string(),
        ));
    };
    let rollback = load_snapshot_records(Path::new(&snapshot_path)).await?;
    rollback_targets(&rollback).await?;
    journal.phase = RestorePhase::RolledBack;
    journal.updated_at = Utc::now().to_rfc3339();
    journal.message = Some("restore undone from pre-restore snapshot".to_string());
    journal::write_journal(&config, &journal)?;
    Ok(RestoreReport {
        status: "undone".to_string(),
        message: format!("restore {} undone from snapshot", journal.restore_id),
        restart_required: true,
    })
}

fn restore_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn reject_in_flight_restore(config: &BackupConfig) -> Result<(), BackupError> {
    if let Some(journal) = journal::load_current(config)? {
        if !journal.phase.is_terminal() {
            return Err(BackupError::InvalidRequest(format!(
                "restore operation already in progress: {} is {:?}",
                journal.restore_id, journal.phase
            )));
        }
    }
    Ok(())
}

fn plan_component(component: Component, mode: RestoreMode) -> (RestoreAction, &'static str) {
    match (component, mode) {
        (Component::IdentityMeta, RestoreMode::SameDevice) => (
            RestoreAction::VerifyOnly,
            "same-device restore verifies DID/DKP metadata but never writes identity",
        ),
        (Component::IdentityMeta, RestoreMode::NewDeviceMigration) => (
            RestoreAction::Skip,
            "new-device migration keeps the target device DID",
        ),
        (Component::Tls, RestoreMode::NewDeviceMigration)
        | (Component::Nebula, RestoreMode::NewDeviceMigration) => (
            RestoreAction::Skip,
            "component is DID-bound and must be regenerated by re-enrolment",
        ),
        (Component::Nftables, _) => (
            RestoreAction::Derived,
            "nftables state is derived from policy and is not restored directly",
        ),
        (Component::Credentials, _) => (
            RestoreAction::Merge,
            "credentials are merged; revocation/status-list state must never be cleared",
        ),
        (Component::Crl, _) => (
            RestoreAction::Merge,
            "CRL restores by union so revocations are never lost",
        ),
        (Component::Policy, _) => (
            RestoreAction::PolicyLast,
            "policy applies last and must preserve monotonic sequence/signature checks",
        ),
        (Component::State, RestoreMode::NewDeviceMigration) => (
            RestoreAction::Skip,
            "runtime state is regenerated on a new device",
        ),
        (Component::Config | Component::FeatureState | Component::Vault, _) => (
            RestoreAction::Replace,
            "component can be atomically replaced after preflight",
        ),
        (Component::Tls | Component::Nebula | Component::State, RestoreMode::SameDevice) => (
            RestoreAction::Replace,
            "same-device restore can atomically replace this component",
        ),
    }
}

#[derive(Debug, Clone)]
struct ApplyEntry {
    component: Component,
    archive_path: String,
    target: PathBuf,
    bytes: Vec<u8>,
    merge_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyRestoreDecision {
    NotSelected,
    Applied,
    Skipped { reason: String },
}

impl PolicyRestoreDecision {
    fn journal_suffix(&self) -> String {
        match self {
            Self::Skipped { reason } => format!("; policy skipped: {}", reason),
            _ => String::new(),
        }
    }

    fn report_suffix(&self) -> String {
        match self {
            Self::Skipped { reason } => format!("; policy skipped ({})", reason),
            _ => String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicySemver(Version);

impl fmt::Display for PolicySemver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotRecord {
    target: String,
    snapshot_file: Option<String>,
}

fn build_apply_entries(
    state: &crate::api::state::AppState,
    preflight: &RestorePreflightReport,
    files: &[crate::backup::validate::DecodedFile],
    _options: &RestorePreflightOptions,
) -> Result<Vec<ApplyEntry>, BackupError> {
    let mut out = Vec::new();
    for planned in &preflight.plan {
        let allowed = match planned.action {
            RestoreAction::VerifyOnly | RestoreAction::Skip | RestoreAction::Derived => false,
            RestoreAction::Replace | RestoreAction::Merge => true,
            RestoreAction::PolicyLast => true,
        };
        if !allowed {
            continue;
        }
        for archive_path in &planned.paths {
            let Some(file) = files.iter().find(|file| &file.archive_path == archive_path) else {
                continue;
            };
            let Some(target) = target_for_archive_path(state, archive_path) else {
                continue;
            };
            out.push(ApplyEntry {
                component: planned.component,
                archive_path: archive_path.clone(),
                target,
                bytes: file.bytes.clone(),
                merge_only: is_merge_only_path(planned.component, archive_path),
            });
        }
    }
    Ok(out)
}

fn validate_policy_entries(
    entries: &mut Vec<ApplyEntry>,
    allow_policy_rollback: bool,
) -> Result<PolicyRestoreDecision, BackupError> {
    if !entries
        .iter()
        .any(|entry| entry.component == Component::Policy)
    {
        return Ok(PolicyRestoreDecision::NotSelected);
    }
    let sig_entry = entries
        .iter()
        .find(|entry| entry.archive_path == "policy/policy.sig")
        .ok_or_else(|| {
            BackupError::InvalidRequest(
                "policy restore requires signed policy envelope policy/policy.sig".to_string(),
            )
        })?;
    let verified = verify_policy_signature(&sig_entry.bytes)?;
    if let Some(reason) =
        denied_policy_rollback_reason(verified.policy_yaml.as_bytes(), allow_policy_rollback)?
    {
        entries.retain(|entry| entry.component != Component::Policy);
        return Ok(PolicyRestoreDecision::Skipped { reason });
    }

    for entry in entries
        .iter_mut()
        .filter(|entry| entry.archive_path == "policy/active_policy.yaml")
    {
        entry.bytes = verified.policy_yaml.as_bytes().to_vec();
    }
    Ok(PolicyRestoreDecision::Applied)
}

fn verify_policy_signature(
    policy_sig: &[u8],
) -> Result<crate::policy_manager::VerifiedPolicy, BackupError> {
    let dir = tempfile::tempdir().map_err(BackupError::Io)?;
    let path = dir.path().join("policy.sig");
    std::fs::write(&path, policy_sig)?;
    crate::policy_manager::verify_signed_policy(&path.to_string_lossy()).map_err(|error| {
        BackupError::Integrity(format!("policy signature validation failed: {}", error))
    })
}

fn restore_order(component: Component) -> u8 {
    match component {
        Component::IdentityMeta => 0,
        Component::Config => 10,
        Component::Tls => 20,
        Component::Nebula => 30,
        Component::Credentials => 40,
        Component::Crl => 50,
        Component::State => 60,
        Component::FeatureState => 70,
        Component::Vault => 80,
        Component::Nftables => 90,
        Component::Policy => 100,
    }
}

fn target_for_archive_path(
    state: &crate::api::state::AppState,
    archive_path: &str,
) -> Option<PathBuf> {
    let data_root = data_root_from_state(state);
    let strip = |prefix: &str| archive_path.strip_prefix(prefix).map(PathBuf::from);
    if let Some(rest) = strip("config/discovery/") {
        return Some(Path::new(&state.discovery_config_dir).join(rest));
    }
    if let Some(rest) = strip("config/") {
        if rest == Path::new("guardian_public.key") {
            return Some(PathBuf::from("/etc/sgx-guardian/guardian_public.key"));
        }
        return Some(Path::new(&state.config_dir).join(rest));
    }
    if let Some(rest) = strip("policy/") {
        let policy_dir = crate::policy_state::active_policy_file_path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(crate::policy_state::POLICY_DIR));
        return Some(policy_dir.join(rest));
    }
    if let Some(rest) = strip("tls/") {
        return Some(data_root.join("sgx-agent").join(rest));
    }
    if let Some(rest) = strip("nebula/") {
        return Some(data_root.join("nebula").join(rest));
    }
    if let Some(rest) = strip("identity/keys/") {
        return Some(Path::new(&state.keys_dir).join(rest));
    }
    if archive_path == "identity/self_version_counter" {
        return Some(data_root.join("did/self_version_counter"));
    }
    if let Some(rest) = strip("identity/") {
        return Some(data_root.join("identity").join(rest));
    }
    if let Some(rest) = strip("credentials/vc/") {
        return Some(data_root.join("identity/vc").join(rest));
    }
    if let Some(rest) = strip("credentials/cot/") {
        return Some(data_root.join("cot").join(rest));
    }
    if let Some(rest) = strip("crl/") {
        return Some(data_root.join("identity/crl").join(rest));
    }
    if let Some(rest) = strip("state/pcr/") {
        let rest_str = rest.to_string_lossy();
        if rest_str.contains("_baseline") {
            return Some(Path::new(&state.pcr_baseline_dir).join(rest));
        }
        return Some(Path::new(&state.pcr_dir).join(rest));
    }
    if let Some(rest) = strip("state/discovery/") {
        return Some(Path::new(&state.discovery_state_dir).join(rest));
    }
    if let Some(rest) = strip("state/boot/") {
        return Some(Path::new(&state.boot_dir).join(rest));
    }
    if let Some(rest) = strip("state/attestation/fallback_") {
        return Some(Path::new(&state.log_dir_fallback).join(rest));
    }
    if let Some(rest) = strip("state/attestation/") {
        return Some(Path::new(&state.log_dir_primary).join(rest));
    }
    if let Some(rest) = strip("state/fallback_") {
        return Some(Path::new(&state.log_dir_fallback).join(rest));
    }
    if let Some(rest) = strip("state/") {
        return Some(Path::new(&state.log_dir_primary).join(rest));
    }
    None
}

fn data_root_from_state(state: &crate::api::state::AppState) -> PathBuf {
    Path::new(&state.keys_dir)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/var/lib/sgx-guardian"))
}

fn is_merge_only_path(component: Component, archive_path: &str) -> bool {
    matches!(component, Component::Crl)
        || archive_path == "credentials/vc/status_list.json"
        || archive_path == "credentials/vc/status_list_index.json"
}

async fn stage_entries(entries: &[ApplyEntry], staging_path: &Path) -> Result<(), BackupError> {
    for entry in entries {
        let path = staging_path.join(&entry.archive_path);
        write_atomic_bytes(&path, &entry.bytes).await?;
    }
    Ok(())
}

async fn snapshot_targets(
    entries: &[ApplyEntry],
    snapshot_path: &Path,
) -> Result<Vec<SnapshotRecord>, BackupError> {
    create_secure_dir_all(snapshot_path).await?;
    let mut records = Vec::new();
    for entry in entries {
        let snapshot_file = if tokio::fs::try_exists(&entry.target).await? {
            let snapshot_file = snapshot_path.join(format!(
                "{}.bak",
                hex::encode(Sha256::digest(entry.target.to_string_lossy().as_bytes()))
            ));
            if let Some(parent) = snapshot_file.parent() {
                create_secure_dir_all(parent).await?;
            }
            tokio::fs::copy(&entry.target, &snapshot_file).await?;
            set_secure_file_permissions(&snapshot_file).await?;
            Some(snapshot_file.to_string_lossy().to_string())
        } else {
            None
        };
        records.push(SnapshotRecord {
            target: entry.target.to_string_lossy().to_string(),
            snapshot_file,
        });
    }
    save_snapshot_records(snapshot_path, &records).await?;
    Ok(records)
}

async fn save_snapshot_records(
    snapshot_path: &Path,
    records: &[SnapshotRecord],
) -> Result<(), BackupError> {
    write_atomic_bytes(
        &snapshot_path.join("targets.json"),
        &serde_json::to_vec_pretty(records)?,
    )
    .await
}

async fn load_snapshot_records(snapshot_path: &Path) -> Result<Vec<SnapshotRecord>, BackupError> {
    Ok(serde_json::from_slice(
        &tokio::fs::read(snapshot_path.join("targets.json")).await?,
    )?)
}

async fn apply_entry(entry: &ApplyEntry) -> Result<(), BackupError> {
    if entry.merge_only && tokio::fs::try_exists(&entry.target).await? {
        return Ok(());
    }
    write_atomic_bytes(&entry.target, &entry.bytes).await
}

async fn rollback_targets(records: &[SnapshotRecord]) -> Result<(), BackupError> {
    for record in records.iter().rev() {
        let target = PathBuf::from(&record.target);
        if let Some(snapshot_file) = &record.snapshot_file {
            if let Some(parent) = target.parent() {
                create_secure_dir_all(parent).await?;
            }
            tokio::fs::copy(snapshot_file, &target).await?;
            set_secure_file_permissions(&target).await?;
        } else if tokio::fs::try_exists(&target).await? {
            tokio::fs::remove_file(&target).await?;
        }
    }
    Ok(())
}

async fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    if let Some(parent) = path.parent() {
        create_secure_dir_all(parent).await?;
    }
    let tmp = path.with_extension("restore-tmp");
    tokio::fs::write(&tmp, bytes).await?;
    set_secure_file_permissions(&tmp).await?;
    tokio::fs::rename(&tmp, path).await?;
    set_secure_file_permissions(path).await?;
    Ok(())
}

async fn create_secure_dir_all(path: &Path) -> Result<(), BackupError> {
    tokio::fs::create_dir_all(path).await?;
    set_secure_dir_permissions(path).await
}

#[cfg(unix)]
async fn set_secure_dir_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| permission_error("set restore directory permissions", path, error))?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_secure_dir_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[cfg(unix)]
async fn set_secure_file_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|error| permission_error("set restore file permissions", path, error))?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_secure_file_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

fn permission_error(action: &str, path: &Path, error: std::io::Error) -> BackupError {
    BackupError::Io(std::io::Error::new(
        error.kind(),
        format!("{} for {}: {}", action, path.display(), error),
    ))
}

async fn count_crl_entries(state: &crate::api::state::AppState) -> Result<usize, BackupError> {
    let dir = data_root_from_state(state).join("identity/crl/entries");
    let mut count = 0;
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return Ok(0);
    };
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

async fn verify_after_apply(
    state: &crate::api::state::AppState,
    pre_crl_count: usize,
) -> Result<(), BackupError> {
    let post_crl_count = count_crl_entries(state).await?;
    if post_crl_count < pre_crl_count {
        return Err(BackupError::Integrity(format!(
            "CRL entry count decreased during restore: {} < {}",
            post_crl_count, pre_crl_count
        )));
    }
    Ok(())
}

fn denied_policy_rollback_reason(
    restored_policy: &[u8],
    allow_policy_rollback: bool,
) -> Result<Option<String>, BackupError> {
    if allow_policy_rollback {
        return Ok(None);
    }
    let restored_version = policy_version(restored_policy)?;
    let active = std::fs::read(crate::policy_state::active_policy_file_path()).ok();
    let active_version = active.as_deref().map(policy_version).transpose()?.flatten();
    if let (Some(restored), Some(active)) = (restored_version, active_version) {
        if restored.0 < active.0 {
            return Ok(Some(format!(
                "backup policy version {} is older than active policy version {}; rollback not authorised",
                restored, active
            )));
        }
    }
    Ok(None)
}

fn policy_version(bytes: &[u8]) -> Result<Option<PolicySemver>, BackupError> {
    let value: serde_yaml::Value = serde_yaml::from_slice(bytes)
        .map_err(|error| BackupError::InvalidRequest(error.to_string()))?;
    let Some(version) = value.get("version").and_then(|version| version.as_str()) else {
        return Ok(None);
    };
    Version::parse(version)
        .map(PolicySemver)
        .map(Some)
        .map_err(|error| {
            BackupError::InvalidRequest(format!(
                "policy version '{}' is not valid semantic version: {}",
                version, error
            ))
        })
}
