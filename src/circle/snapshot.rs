use crate::circle::errors::CircleError;
use crate::circle::members::{CircleMember, MemberLifecycleState};
use crate::circle::model::verify_signed_proof;
use crate::circle::persistence;
use crate::did::document::Proof;
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use crate::vc::credential::{sort_json_keys, MembershipStatus};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};
use std::time::Duration;

static SNAPSHOT_CACHE: Lazy<RwLock<HashMap<String, CircleMemberSnapshot>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircleMemberSnapshot {
    pub circle_id: String,
    pub version: u64,
    pub owner_did: String,
    pub members: Vec<CircleMember>,
    pub updated_at: String,
    #[serde(default)]
    pub proof: Proof,
}

impl CircleMemberSnapshot {
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }

    pub fn sign(&mut self, km: &KeyManager, vm_ref: &str) -> Result<(), CircleError> {
        let canonical = self.canonical_bytes_for_sign()?;
        crate::did::doc_sign::sign_in_place_generic(&mut self.proof, &canonical, km, vm_ref)?;
        Ok(())
    }

    pub async fn verify_owner_signature(&self, resolver: &Resolver) -> Result<(), CircleError> {
        let resolved = resolver.resolve(&self.owner_did).await?;
        let public_key = general_purpose::STANDARD.decode(resolved.public_key_der_b64)?;
        let canonical = self.canonical_bytes_for_sign()?;
        verify_signed_proof(&self.proof, &canonical, &public_key)
    }
}

pub fn load(circle_id: &str) -> Result<Option<CircleMemberSnapshot>, CircleError> {
    if let Ok(guard) = SNAPSHOT_CACHE.read() {
        if let Some(snapshot) = guard.get(circle_id) {
            return Ok(Some(snapshot.clone()));
        }
    }
    let path = persistence::snapshot_path(circle_id);
    if !path.exists() {
        return Ok(None);
    }
    let snapshot: CircleMemberSnapshot = serde_json::from_slice(&fs::read(path)?)?;
    cache(snapshot.clone());
    Ok(Some(snapshot))
}

pub fn save(snapshot: &CircleMemberSnapshot) -> Result<(), CircleError> {
    persistence::write_atomic(
        &persistence::snapshot_path(&snapshot.circle_id),
        &serde_json::to_vec_pretty(snapshot)?,
    )?;
    cache(snapshot.clone());
    Ok(())
}

pub fn cache(snapshot: CircleMemberSnapshot) {
    if let Ok(mut guard) = SNAPSHOT_CACHE.write() {
        guard.insert(snapshot.circle_id.clone(), snapshot);
    }
}

pub async fn accept_from_owner(
    snapshot: CircleMemberSnapshot,
    resolver: &Resolver,
) -> Result<CircleMemberSnapshot, CircleError> {
    if snapshot.circle_id.trim().is_empty() {
        return Err(CircleError::Invalid(
            "snapshot circle_id is required".into(),
        ));
    }
    if snapshot.owner_did.trim().is_empty() {
        return Err(CircleError::Invalid(
            "snapshot owner_did is required".into(),
        ));
    }
    if !snapshot.members.iter().any(|member| {
        member.did == snapshot.owner_did
            && member.membership_status == MembershipStatus::Active
            && member.lifecycle_state == MemberLifecycleState::Active
    }) {
        return Err(CircleError::Invalid(
            "snapshot must include active owner membership".into(),
        ));
    }
    if snapshot
        .members
        .iter()
        .any(|member| member.lifecycle_state != MemberLifecycleState::Active)
    {
        return Err(CircleError::Invalid(
            "snapshot may only contain active members".into(),
        ));
    }
    snapshot.verify_owner_signature(resolver).await?;
    if let Some(existing) = load(&snapshot.circle_id)? {
        if snapshot.version <= existing.version {
            return Err(CircleError::Conflict(format!(
                "stale circle member snapshot version {} <= {}",
                snapshot.version, existing.version
            )));
        }
    }
    save(&snapshot)?;
    Ok(snapshot)
}

pub fn build_authoritative(
    circle_id: &str,
    owner: &DidRecord,
    km: &Arc<KeyManager>,
    members: Vec<CircleMember>,
) -> Result<CircleMemberSnapshot, CircleError> {
    let mut active_members = members
        .into_iter()
        .filter(|member| {
            member.membership_status == MembershipStatus::Active
                && member.lifecycle_state == MemberLifecycleState::Active
        })
        .collect::<Vec<_>>();
    active_members.sort_by(|left, right| left.did.cmp(&right.did));
    let version = load(circle_id)?
        .map(|snapshot| snapshot.version + 1)
        .unwrap_or(1);
    let mut snapshot = CircleMemberSnapshot {
        circle_id: circle_id.to_string(),
        version,
        owner_did: owner.did.clone(),
        members: active_members,
        updated_at: Utc::now().to_rfc3339(),
        proof: Proof::default(),
    };
    let vm_ref = format!("{}#dkp-v{}", owner.did, owner.current_dkp_version.max(1));
    snapshot.sign(km, &vm_ref)?;
    save(&snapshot)?;
    Ok(snapshot)
}

pub fn spawn(node_id: String, resolver: Resolver) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            if let Err(err) = pull_latest_for_joined_circles(&node_id, &resolver).await {
                tracing::debug!("Circle member snapshot pull skipped: {}", err);
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

pub async fn pull_latest_for_joined_circles(
    node_id: &str,
    resolver: &Resolver,
) -> Result<usize, CircleError> {
    let local_did = crate::did::DidRecord::load(&crate::did::DEFAULT_DID_PATH)
        .map(|record| record.did)
        .unwrap_or_default();
    let registry = crate::circle::store::load_or_seed(node_id)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| CircleError::Invalid(format!("circle snapshot pull client: {}", err)))?;
    let mut applied = 0usize;

    for circle in registry.circles.into_iter() {
        if circle.is_mesh() || circle.owner_did == local_did {
            continue;
        }
        let endpoint = match crate::circle::invite::resolve_circle_endpoint(&circle.owner_did, resolver).await {
            Ok(endpoint) => Some(endpoint),
            Err(err) => {
                tracing::debug!(
                    "Circle snapshot owner endpoint unavailable circle={} owner={} error={}",
                    circle.circle_id,
                    circle.owner_did,
                    err
                );
                crate::crl::gossip::engine::active_gossip_peers(&local_did)
                    .into_iter()
                    .find(|peer| peer.did == circle.owner_did)
                    .map(|peer| format!("http://{}:8443", peer.overlay_ip))
            }
        };
        let Some(endpoint) = endpoint else {
            continue;
        };
        let response = client
            .get(format!(
                "{}/api/v1/circles/{}/members/snapshot",
                endpoint.trim_end_matches('/'),
                circle.circle_id
            ))
            .send()
            .await;
        let response = match response {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                tracing::debug!(
                    "Circle snapshot pull rejected circle={} owner={} status={}",
                    circle.circle_id,
                    circle.owner_did,
                    response.status()
                );
                continue;
            }
            Err(err) => {
                tracing::debug!(
                    "Circle snapshot pull failed circle={} owner={} error={}",
                    circle.circle_id,
                    circle.owner_did,
                    err
                );
                continue;
            }
        };
        let snapshot = match response.json::<CircleMemberSnapshot>().await {
            Ok(snapshot) => snapshot,
            Err(err) => {
                tracing::debug!(
                    "Circle snapshot pull parse failed circle={} owner={} error={}",
                    circle.circle_id,
                    circle.owner_did,
                    err
                );
                continue;
            }
        };
        match accept_from_owner(snapshot, resolver).await {
            Ok(_) => applied += 1,
            Err(CircleError::Conflict(_)) => {}
            Err(err) => {
                tracing::warn!(
                    "Circle snapshot pull apply failed circle={} owner={} error={}",
                    circle.circle_id,
                    circle.owner_did,
                    err
                );
            }
        }
    }

    Ok(applied)
}
