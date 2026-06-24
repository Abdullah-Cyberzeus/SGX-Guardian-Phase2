//! Sprint 6 Task 2: Session-bound Virtual Identity.
//!
//! VirtualID = SHA-256(
//!     DID || CurrentDKP_PubKey || PCR_values ||
//!     policy_digest || Nonce_I || Nonce_R
//! )
//!
//! DID is the persistent identity anchor (Sprint 5 Task 1).
//! VirtualID is the session-scoped credential: it rotates whenever
//! DKP, PCR, policy, or session nonces change.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const VID_NONCE_REFRESH_SECS: i64 = 60;

const DEFAULT_VID_STATE_DIR: &str = "/var/lib/sgx-guardian/identity";
const DKP_P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

static RUNTIME_VID_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeVirtualIdInputs {
    pub node: String,
    pub state_path: Option<String>,
    pub did: String,
    pub dkp_pubkey_der: Vec<u8>,
    pub dkp_version: u32,
    pub pcr_values: Vec<String>,
    pub pcr_digest: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeVirtualIdStatus {
    pub node: String,
    pub did: String,
    pub dkp_bytes: usize,
    pub dkp_version: u32,
    pub pcr_digest: String,
    pub policy_digest: String,
    pub nonce_i: String,
    pub nonce_r: String,
    pub virtual_id: String,
    pub change_reason: String,
    pub session_expires_at: String,
    pub session_ttl: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedRuntimeVirtualIdState {
    #[serde(alias = "dkp_pubkey_sha256")]
    dkp_pubkey_hash: String,
    dkp_version: u32,
    pcr_digest: String,
    policy_digest: String,
    nonce_i: String,
    nonce_r: String,
    #[serde(default)]
    virtual_id: String,
    session_expires_at: String,
    #[serde(default = "default_runtime_change_reason")]
    change_reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeVirtualIdChangeReason {
    InitialObservation,
    DkpRotated,
    PcrChanged,
    PolicyChanged,
    NonceRefreshed,
    Unchanged,
}

impl RuntimeVirtualIdChangeReason {
    fn as_str(self) -> &'static str {
        match self {
            RuntimeVirtualIdChangeReason::InitialObservation => "initial_observation",
            RuntimeVirtualIdChangeReason::DkpRotated => "dkp_rotated",
            RuntimeVirtualIdChangeReason::PcrChanged => "pcr_changed",
            RuntimeVirtualIdChangeReason::PolicyChanged => "policy_changed",
            RuntimeVirtualIdChangeReason::NonceRefreshed => "nonce_refreshed",
            RuntimeVirtualIdChangeReason::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedRuntimeVirtualIdInputs {
    node: String,
    state_path: Option<String>,
    did: String,
    dkp_pubkey_bytes: Vec<u8>,
    dkp_pubkey_hash: String,
    dkp_version: u32,
    pcr_material: Vec<u8>,
    pcr_digest: String,
    policy_digest: String,
    policy_digest_bytes: Vec<u8>,
}

/// Inputs to VirtualID computation. Use this struct to make call sites explicit
/// and avoid positional-argument mistakes.
#[derive(Debug, Clone)]
pub struct VirtualIdInputs<'a> {
    pub did: &'a str,
    pub dkp_pubkey_der: &'a [u8],
    pub pcr_values: &'a [u8],
    pub policy_digest: &'a [u8],
    pub nonce_i: &'a [u8],
    pub nonce_r: &'a [u8],
}

impl<'a> VirtualIdInputs<'a> {
    /// Build the exact byte sequence required by the VID formula.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            self.did.len()
                + self.dkp_pubkey_der.len()
                + self.pcr_values.len()
                + self.policy_digest.len()
                + self.nonce_i.len()
                + self.nonce_r.len(),
        );
        buf.extend_from_slice(self.did.as_bytes());
        buf.extend_from_slice(self.dkp_pubkey_der);
        buf.extend_from_slice(self.pcr_values);
        buf.extend_from_slice(self.policy_digest);
        buf.extend_from_slice(self.nonce_i);
        buf.extend_from_slice(self.nonce_r);
        buf
    }

    pub fn compute(&self) -> [u8; 32] {
        let out = Sha256::digest(self.canonical_bytes());
        let mut id = [0u8; 32];
        id.copy_from_slice(&out[..32]);
        id
    }

    /// Domain-separation tag for the stable (no-nonce) classifier component.
    pub const STABLE_DOMAIN_TAG: &'static [u8] = b"SGX-VID-STABLE-v1\0";

    /// Compute the 32-byte stable component of this VID. Excludes nonces.
    /// Used by `VirtualIdCache` to classify rotations as nonce-only vs
    /// security-state (DKP/PCR/policy) changes.
    pub fn stable_component(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(
            Self::STABLE_DOMAIN_TAG.len()
                + 4
                + self.did.len()
                + 4
                + self.dkp_pubkey_der.len()
                + 4
                + self.pcr_values.len()
                + 4
                + self.policy_digest.len(),
        );
        buf.extend_from_slice(Self::STABLE_DOMAIN_TAG);
        write_lp(&mut buf, self.did.as_bytes());
        write_lp(&mut buf, self.dkp_pubkey_der);
        write_lp(&mut buf, self.pcr_values);
        write_lp(&mut buf, self.policy_digest);
        let out = Sha256::digest(&buf);
        let mut id = [0u8; 32];
        id.copy_from_slice(&out[..32]);
        id
    }
}

pub fn canonical_dkp_pubkey_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == DKP_P256_SPKI_PREFIX.len() + 65 && bytes.starts_with(DKP_P256_SPKI_PREFIX) {
        return bytes[DKP_P256_SPKI_PREFIX.len()..].to_vec();
    }

    bytes.to_vec()
}

pub fn observe_runtime_virtual_id(
    inputs: RuntimeVirtualIdInputs,
) -> Result<RuntimeVirtualIdStatus> {
    let now = Utc::now();
    let prepared = PreparedRuntimeVirtualIdInputs::try_from(inputs)?;
    let _guard = RUNTIME_VID_STATE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("runtime VID state lock poisoned");
    let state_path = runtime_vid_state_path(&prepared.node, prepared.state_path.as_deref());
    let previous = load_runtime_vid_state(&state_path)?;
    let mut current = derive_runtime_vid_state(previous.as_ref(), &prepared, now)?;
    current.change_reason = classify_runtime_change(previous.as_ref(), &current)
        .as_str()
        .to_string();

    if previous.as_ref() != Some(&current) {
        save_runtime_vid_state(&state_path, &current)?;
    }

    build_runtime_virtual_id_status(&prepared, &current, now)
}

pub fn pcr_values_material(pcr_values: &[String], pcr_digest: &str) -> Vec<u8> {
    let decoded_values: Option<Vec<Vec<u8>>> = pcr_values
        .iter()
        .map(|value| hex::decode(value).ok())
        .collect();

    if let Some(decoded_values) = decoded_values {
        if !decoded_values.is_empty() {
            let total_len: usize = decoded_values.iter().map(Vec::len).sum();
            let mut material = Vec::with_capacity(total_len);
            for value in decoded_values {
                material.extend_from_slice(&value);
            }
            return material;
        }
    }

    hex::decode(pcr_digest).unwrap_or_default()
}

impl TryFrom<RuntimeVirtualIdInputs> for PreparedRuntimeVirtualIdInputs {
    type Error = anyhow::Error;

    fn try_from(inputs: RuntimeVirtualIdInputs) -> Result<Self> {
        let dkp_pubkey_bytes = canonical_dkp_pubkey_bytes(&inputs.dkp_pubkey_der);
        let policy_digest_bytes = hex::decode(&inputs.policy_digest)
            .with_context(|| format!("invalid policy digest hex for node {}", inputs.node))?;

        Ok(Self {
            node: inputs.node,
            state_path: inputs.state_path,
            did: inputs.did,
            dkp_pubkey_hash: hex::encode(Sha256::digest(&dkp_pubkey_bytes)),
            dkp_pubkey_bytes,
            dkp_version: inputs.dkp_version,
            pcr_material: pcr_values_material(&inputs.pcr_values, &inputs.pcr_digest),
            pcr_digest: inputs.pcr_digest,
            policy_digest: inputs.policy_digest,
            policy_digest_bytes,
        })
    }
}

fn classify_runtime_change(
    previous: Option<&PersistedRuntimeVirtualIdState>,
    current: &PersistedRuntimeVirtualIdState,
) -> RuntimeVirtualIdChangeReason {
    let Some(previous) = previous else {
        return RuntimeVirtualIdChangeReason::InitialObservation;
    };

    if previous.dkp_version != current.dkp_version
        || previous.dkp_pubkey_hash != current.dkp_pubkey_hash
    {
        return RuntimeVirtualIdChangeReason::DkpRotated;
    }
    if previous.pcr_digest != current.pcr_digest {
        return RuntimeVirtualIdChangeReason::PcrChanged;
    }
    if previous.policy_digest != current.policy_digest {
        return RuntimeVirtualIdChangeReason::PolicyChanged;
    }
    if previous.nonce_i != current.nonce_i || previous.nonce_r != current.nonce_r {
        return RuntimeVirtualIdChangeReason::NonceRefreshed;
    }

    RuntimeVirtualIdChangeReason::Unchanged
}

fn build_runtime_virtual_id_status(
    inputs: &PreparedRuntimeVirtualIdInputs,
    state: &PersistedRuntimeVirtualIdState,
    now: DateTime<Utc>,
) -> Result<RuntimeVirtualIdStatus> {
    Ok(RuntimeVirtualIdStatus {
        node: inputs.node.clone(),
        did: inputs.did.clone(),
        dkp_bytes: inputs.dkp_pubkey_bytes.len(),
        dkp_version: inputs.dkp_version,
        pcr_digest: inputs.pcr_digest.clone(),
        policy_digest: inputs.policy_digest.clone(),
        nonce_i: state.nonce_i.clone(),
        nonce_r: state.nonce_r.clone(),
        virtual_id: state.virtual_id.clone(),
        change_reason: state.change_reason.clone(),
        session_expires_at: state.session_expires_at.clone(),
        session_ttl: session_ttl(state, now),
    })
}

fn derive_runtime_vid_state(
    previous: Option<&PersistedRuntimeVirtualIdState>,
    inputs: &PreparedRuntimeVirtualIdInputs,
    now: DateTime<Utc>,
) -> Result<PersistedRuntimeVirtualIdState> {
    let session_expired = previous
        .map(|state| runtime_vid_session_expired(state, now))
        .unwrap_or(true);
    let (nonce_i, nonce_r, session_expires_at) = match previous {
        Some(previous) if !session_expired => (
            previous.nonce_i.clone(),
            previous.nonce_r.clone(),
            previous.session_expires_at.clone(),
        ),
        _ => (
            random_nonce_hex()?,
            random_nonce_hex()?,
            (now + Duration::seconds(VID_NONCE_REFRESH_SECS)).to_rfc3339(),
        ),
    };

    let nonce_i_bytes = hex::decode(&nonce_i).context("invalid current nonce_i hex")?;
    let nonce_r_bytes = hex::decode(&nonce_r).context("invalid current nonce_r hex")?;
    let virtual_id = hex::encode(
        VirtualIdInputs {
            did: &inputs.did,
            dkp_pubkey_der: &inputs.dkp_pubkey_bytes,
            pcr_values: &inputs.pcr_material,
            policy_digest: &inputs.policy_digest_bytes,
            nonce_i: &nonce_i_bytes,
            nonce_r: &nonce_r_bytes,
        }
        .compute(),
    );

    Ok(PersistedRuntimeVirtualIdState {
        dkp_pubkey_hash: inputs.dkp_pubkey_hash.clone(),
        dkp_version: inputs.dkp_version,
        pcr_digest: inputs.pcr_digest.clone(),
        policy_digest: inputs.policy_digest.clone(),
        nonce_i,
        nonce_r,
        virtual_id,
        session_expires_at,
        change_reason: previous
            .map(|state| state.change_reason.clone())
            .unwrap_or_else(default_runtime_change_reason),
    })
}

fn runtime_vid_session_expired(state: &PersistedRuntimeVirtualIdState, now: DateTime<Utc>) -> bool {
    let Some(expires_at) = parse_rfc3339_utc(&state.session_expires_at) else {
        return true;
    };

    now >= expires_at || !runtime_vid_nonces_are_valid(state)
}

fn runtime_vid_nonces_are_valid(state: &PersistedRuntimeVirtualIdState) -> bool {
    hex::decode(&state.nonce_i).is_ok() && hex::decode(&state.nonce_r).is_ok()
}

fn session_ttl(state: &PersistedRuntimeVirtualIdState, now: DateTime<Utc>) -> i64 {
    parse_rfc3339_utc(&state.session_expires_at)
        .map(|expires_at| {
            expires_at
                .signed_duration_since(now)
                .num_seconds()
                .clamp(0, VID_NONCE_REFRESH_SECS)
        })
        .unwrap_or(0)
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn default_runtime_change_reason() -> String {
    RuntimeVirtualIdChangeReason::InitialObservation
        .as_str()
        .to_string()
}

fn runtime_vid_state_path(node: &str, explicit: Option<&str>) -> PathBuf {
    explicit
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(DEFAULT_VID_STATE_DIR).join(runtime_vid_state_file_name(node)))
}

fn runtime_vid_state_file_name(node: &str) -> String {
    let mut sanitized = String::with_capacity(node.len());
    for ch in node.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }

    if sanitized.is_empty() {
        sanitized.push_str("default");
    }

    format!("virtual_id_session_{}.json", sanitized)
}

fn load_runtime_vid_state(path: &Path) -> Result<Option<PersistedRuntimeVirtualIdState>> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse VID session state at {}", path.display()))
            .map(Some),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read VID session state at {}", path.display())),
    }
}

fn save_runtime_vid_state(path: &Path, state: &PersistedRuntimeVirtualIdState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create VID session dir {}", parent.display()))?;
    }

    let json =
        serde_json::to_string_pretty(state).context("failed to serialize VID session state")?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json)
        .with_context(|| format!("failed to write VID session temp file {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to replace VID session state {} with {}",
            path.display(),
            tmp.display()
        )
    })?;
    Ok(())
}

fn random_nonce_hex() -> Result<String> {
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("failed to generate VirtualID nonce"))?;
    Ok(hex::encode(nonce))
}

/// Length-prefixed write: 4-byte big-endian length, then bytes.
pub(crate) fn write_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

/// Backward-compatible wrapper for transition-only callers.
#[deprecated(note = "use VirtualIdInputs::compute; DID-less signature removed in v1.1")]
pub fn compute_virtual_id_legacy(
    device_pubkey_der: &[u8],
    pcr_digest: &[u8],
    policy_digest: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
) -> [u8; 32] {
    VirtualIdInputs {
        did: "",
        dkp_pubkey_der: device_pubkey_der,
        pcr_values: pcr_digest,
        policy_digest,
        nonce_i,
        nonce_r,
    }
    .compute()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use sha2::Sha256;
    use std::path::Path;
    use tempfile::tempdir;

    fn sample_inputs<'a>() -> VirtualIdInputs<'a> {
        VirtualIdInputs {
            did: "did:guardian:abc",
            dkp_pubkey_der: &[0u8; 91],
            pcr_values: &[1u8; 32],
            policy_digest: &[2u8; 32],
            nonce_i: &[3u8; 32],
            nonce_r: &[4u8; 32],
        }
    }

    #[test]
    fn vid_001_deterministic_for_same_inputs() {
        let inp = sample_inputs();
        assert_eq!(inp.compute(), inp.compute());
    }

    #[test]
    fn vid_002_changes_when_did_changes() {
        let inp = sample_inputs();
        let changed = VirtualIdInputs {
            did: "did:guardian:xyz",
            ..inp.clone()
        };
        assert_ne!(inp.compute(), changed.compute());
    }

    #[test]
    fn vid_006_cross_session_unlinkability_from_nonces() {
        let inp = sample_inputs();
        let changed = VirtualIdInputs {
            nonce_i: &[9u8; 32],
            ..inp.clone()
        };
        assert_ne!(inp.compute(), changed.compute());
    }

    #[test]
    fn vid_009_changes_when_pcr_values_change() {
        let a = VirtualIdInputs {
            did: "did:guardian:AB",
            dkp_pubkey_der: b"CD",
            pcr_values: &[0u8; 32],
            policy_digest: &[0u8; 32],
            nonce_i: &[0u8; 32],
            nonce_r: &[0u8; 32],
        };
        let b = VirtualIdInputs {
            pcr_values: &[1u8; 32],
            ..a.clone()
        };
        assert_ne!(a.compute(), b.compute());
    }

    #[test]
    fn vid_010_exact_formula_has_no_domain_tag_or_length_prefixes() {
        let inp = sample_inputs();
        let canonical = inp.canonical_bytes();
        let expected_len = inp.did.len()
            + inp.dkp_pubkey_der.len()
            + inp.pcr_values.len()
            + inp.policy_digest.len()
            + inp.nonce_i.len()
            + inp.nonce_r.len();
        assert_eq!(canonical.len(), expected_len);
        assert!(canonical.starts_with(inp.did.as_bytes()));
    }

    #[test]
    fn vid_011_matches_exact_requirement_formula() {
        let inp = sample_inputs();
        let mut manual = Vec::new();
        manual.extend_from_slice(inp.did.as_bytes());
        manual.extend_from_slice(inp.dkp_pubkey_der);
        manual.extend_from_slice(inp.pcr_values);
        manual.extend_from_slice(inp.policy_digest);
        manual.extend_from_slice(inp.nonce_i);
        manual.extend_from_slice(inp.nonce_r);
        let expected = Sha256::digest(&manual);

        assert_eq!(inp.compute().as_slice(), &expected[..32]);
    }

    fn state_path(dir: &Path, node: &str) -> String {
        dir.join(format!("{node}.json"))
            .to_string_lossy()
            .into_owned()
    }

    fn runtime_inputs(node: &str, state_path: &str) -> RuntimeVirtualIdInputs {
        RuntimeVirtualIdInputs {
            node: node.to_string(),
            state_path: Some(state_path.to_string()),
            did: format!("did:guardian:{node}"),
            dkp_pubkey_der: vec![1, 2, 3, 4],
            dkp_version: 1,
            pcr_values: vec!["aa".repeat(32), "bb".repeat(32)],
            pcr_digest: "cc".repeat(32),
            policy_digest: "dd".repeat(32),
        }
    }

    fn spki_from_raw_p256_pubkey(raw_pubkey: &[u8]) -> Vec<u8> {
        let mut spki = DKP_P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(raw_pubkey);
        spki
    }

    #[test]
    fn runtime_virtual_id_uses_initial_observation_then_nonce_refresh() {
        let td = tempdir().expect("create temp dir");
        let node = "vid-runtime-refresh";
        let state_path = state_path(td.path(), node);
        let first = observe_runtime_virtual_id(runtime_inputs(node, &state_path))
            .expect("first runtime VID");
        assert_eq!(first.change_reason, "initial_observation");
        assert_eq!(first.session_ttl, VID_NONCE_REFRESH_SECS);

        let persisted = load_runtime_vid_state(Path::new(&state_path))
            .expect("load persisted VID state")
            .expect("persisted state should exist");
        assert_eq!(persisted.dkp_version, 1);
        assert_eq!(persisted.pcr_digest, "cc".repeat(32));
        assert_eq!(persisted.policy_digest, "dd".repeat(32));
        assert_eq!(persisted.virtual_id, first.virtual_id);

        let second = observe_runtime_virtual_id(runtime_inputs(node, &state_path))
            .expect("second runtime VID");
        assert_eq!(second.virtual_id, first.virtual_id);
        assert_eq!(second.nonce_i, first.nonce_i);
        assert_eq!(second.nonce_r, first.nonce_r);
        assert_eq!(second.session_expires_at, first.session_expires_at);
        assert_eq!(second.change_reason, "unchanged");

        let mut persisted = load_runtime_vid_state(Path::new(&state_path))
            .expect("load persisted VID state")
            .expect("persisted state should exist");
        persisted.session_expires_at = (Utc::now() - ChronoDuration::seconds(1)).to_rfc3339();
        save_runtime_vid_state(Path::new(&state_path), &persisted).expect("save expired state");

        let refreshed = observe_runtime_virtual_id(runtime_inputs(node, &state_path))
            .expect("refreshed runtime VID");
        assert_eq!(refreshed.change_reason, "nonce_refreshed");
        assert_ne!(refreshed.virtual_id, first.virtual_id);
        assert_ne!(refreshed.nonce_i, first.nonce_i);
        assert_ne!(refreshed.nonce_r, first.nonce_r);
        assert_ne!(refreshed.session_expires_at, first.session_expires_at);
        assert_eq!(refreshed.session_ttl, VID_NONCE_REFRESH_SECS);

        let unchanged = observe_runtime_virtual_id(runtime_inputs(node, &state_path))
            .expect("unchanged runtime VID");
        assert_eq!(unchanged.change_reason, "unchanged");
        assert_eq!(unchanged.virtual_id, refreshed.virtual_id);
    }

    #[test]
    fn runtime_virtual_id_reports_dkp_policy_and_pcr_changes() {
        let td = tempdir().expect("create temp dir");
        let dkp_node = "vid-runtime-dkp";
        let dkp_state_path = state_path(td.path(), dkp_node);
        let first = observe_runtime_virtual_id(runtime_inputs(dkp_node, &dkp_state_path))
            .expect("seed dkp runtime VID");
        let mut dkp_rotated = runtime_inputs(dkp_node, &dkp_state_path);
        dkp_rotated.dkp_pubkey_der = vec![9, 9, 9, 9];
        dkp_rotated.dkp_version = 2;
        let dkp_status = observe_runtime_virtual_id(dkp_rotated).expect("rotated dkp runtime VID");
        assert_eq!(dkp_status.change_reason, "dkp_rotated");
        assert_eq!(dkp_status.nonce_i, first.nonce_i);
        assert_eq!(dkp_status.nonce_r, first.nonce_r);
        assert_eq!(dkp_status.session_expires_at, first.session_expires_at);

        let policy_node = "vid-runtime-policy";
        let policy_state_path = state_path(td.path(), policy_node);
        let first = observe_runtime_virtual_id(runtime_inputs(policy_node, &policy_state_path))
            .expect("seed policy runtime VID");
        let mut policy_changed = runtime_inputs(policy_node, &policy_state_path);
        policy_changed.policy_digest = "ee".repeat(32);
        let policy_status =
            observe_runtime_virtual_id(policy_changed).expect("policy changed runtime VID");
        assert_eq!(policy_status.change_reason, "policy_changed");
        assert_eq!(policy_status.nonce_i, first.nonce_i);
        assert_eq!(policy_status.nonce_r, first.nonce_r);
        assert_eq!(policy_status.session_expires_at, first.session_expires_at);

        let pcr_node = "vid-runtime-pcr";
        let pcr_state_path = state_path(td.path(), pcr_node);
        let first = observe_runtime_virtual_id(runtime_inputs(pcr_node, &pcr_state_path))
            .expect("seed pcr runtime VID");
        let mut pcr_changed = runtime_inputs(pcr_node, &pcr_state_path);
        pcr_changed.pcr_digest = "ff".repeat(32);
        let pcr_status = observe_runtime_virtual_id(pcr_changed).expect("pcr changed runtime VID");
        assert_eq!(pcr_status.change_reason, "pcr_changed");
        assert_eq!(pcr_status.nonce_i, first.nonce_i);
        assert_eq!(pcr_status.nonce_r, first.nonce_r);
        assert_eq!(pcr_status.session_expires_at, first.session_expires_at);
    }

    #[test]
    fn runtime_virtual_id_normalizes_spki_and_raw_public_keys() {
        let td = tempdir().expect("create temp dir");
        let node = "vid-runtime-spki";
        let state_path = state_path(td.path(), node);
        let raw_pubkey = {
            let mut bytes = vec![0x04];
            bytes.extend(1u8..=64u8);
            bytes
        };

        let mut spki_inputs = runtime_inputs(node, &state_path);
        spki_inputs.dkp_pubkey_der = spki_from_raw_p256_pubkey(&raw_pubkey);
        let first = observe_runtime_virtual_id(spki_inputs).expect("seed spki runtime VID");

        let mut raw_inputs = runtime_inputs(node, &state_path);
        raw_inputs.dkp_pubkey_der = raw_pubkey;
        let second = observe_runtime_virtual_id(raw_inputs).expect("raw runtime VID");

        assert_eq!(second.change_reason, "unchanged");
        assert_eq!(second.virtual_id, first.virtual_id);
        assert_eq!(second.nonce_i, first.nonce_i);
        assert_eq!(second.nonce_r, first.nonce_r);
        assert_eq!(second.session_expires_at, first.session_expires_at);
        assert_eq!(second.dkp_bytes, 65);
    }

    #[test]
    fn runtime_virtual_id_prefers_security_change_over_expired_nonce() {
        let td = tempdir().expect("create temp dir");
        let node = "vid-runtime-priority";
        let state_path = state_path(td.path(), node);
        let first = observe_runtime_virtual_id(runtime_inputs(node, &state_path))
            .expect("seed runtime VID");

        let mut persisted = load_runtime_vid_state(Path::new(&state_path))
            .expect("load persisted VID state")
            .expect("persisted state should exist");
        persisted.session_expires_at = (Utc::now() - ChronoDuration::seconds(1)).to_rfc3339();
        save_runtime_vid_state(Path::new(&state_path), &persisted).expect("save expired state");

        let mut dkp_changed = runtime_inputs(node, &state_path);
        dkp_changed.dkp_version = 2;
        dkp_changed.dkp_pubkey_der = vec![8, 7, 6, 5];
        let refreshed = observe_runtime_virtual_id(dkp_changed).expect("priority runtime VID");

        assert_eq!(refreshed.change_reason, "dkp_rotated");
        assert_ne!(refreshed.nonce_i, first.nonce_i);
        assert_ne!(refreshed.nonce_r, first.nonce_r);
        assert_ne!(refreshed.session_expires_at, first.session_expires_at);
    }
}
