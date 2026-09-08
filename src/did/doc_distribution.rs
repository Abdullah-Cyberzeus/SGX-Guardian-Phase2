use crate::did::doc_persistence::{
    list_peer_docs, load_ca_aggregate, save_ca_aggregate, save_peer,
};
use crate::did::doc_sign::verify_with_replay_protection;
use crate::did::document::DidDocument;
use crate::did::errors::DidError;
use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const REQ_TIMEOUT_SECS: u64 = 10;

pub async fn publish_to_ca(
    ca_host: &str,
    node_name: &str,
    doc: &DidDocument,
) -> Result<(), DidError> {
    let json = serde_json::to_string(doc)?;
    let req = RegistryRequest {
        action: "publish_did_doc".into(),
        node_name: node_name.to_string(),
        pubkey_prefix: None,
        did_doc_json: Some(json),
        did_query: None,
        status_list_body: None,
    };
    let resp = send_request(ca_host, &req).await?;
    if !resp.success {
        return Err(DidError::InvalidFormat(format!(
            "CA rejected DID document: {}",
            resp.error.unwrap_or_default()
        )));
    }
    Ok(())
}

pub async fn pull_and_apply_aggregate(ca_host: &str) -> Result<Vec<String>, DidError> {
    let req = RegistryRequest {
        action: "snapshot_did_doc".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    };
    let resp = send_request(ca_host, &req).await?;
    if !resp.success {
        return Err(DidError::InvalidFormat(format!(
            "snapshot_did_doc failed: {}",
            resp.error.unwrap_or_default()
        )));
    }

    let raw = resp.did_doc_aggregate_json.unwrap_or_else(|| "[]".into());
    apply_aggregate_json(&raw)
}

/// Verify and cache a signed CA DID-document snapshot already obtained over
/// another authenticated/bootstrap transport (for example the VPS broker).
pub fn apply_aggregate_json(raw: &str) -> Result<Vec<String>, DidError> {
    let docs: Vec<DidDocument> = serde_json::from_str(&raw)?;
    let mut updated_dids = Vec::new();
    for doc in docs {
        let floor = local_floor_version(&doc);
        match verify_with_replay_protection(&doc, floor) {
            Ok(()) => {
                if save_peer(&doc).is_ok() {
                    updated_dids.push(doc.id.clone());
                }
            }
            Err(e) => {
                tracing::warn!("Rejecting DID document {}: {}", doc.id, e);
            }
        }
    }
    Ok(updated_dids)
}

pub async fn ca_ingest_published(payload: &str) -> Result<(), DidError> {
    let doc: DidDocument = serde_json::from_str(payload)?;
    let existing = crate::did::doc_persistence::load_peer(&doc.did()?)?;

    // SECURITY: external ingest cannot rotate keys. verify_with_replay_protection
    // only checks that the document's embedded proof is internally consistent
    // (signed by the key embedded in the SAME document) — it never checks
    // that doc.id actually belongs to that key. A version-number check alone
    // is bypassable: an attacker publishing a forged doc for an existing DID
    // just sets sgx_version_id to existing+1 and signs with their OWN key,
    // which passes both verify_with_replay_protection (self-consistent) and
    // a "version increased" check. Legitimate key rotation for an
    // already-known DID must go through the daemon's own DID refresh path,
    // which has access to the old key to prove continuity; this path has no
    // way to verify that continuity, so it only accepts a key for a DID it
    // has never recorded before (first-time ingest / bootstrapping).
    if let Some(existing) = &existing {
        let existing_key = existing
            .verification_method
            .first()
            .map(|vm| (vm.public_key_jwk.x.clone(), vm.public_key_jwk.y.clone()));
        let incoming_key = doc
            .verification_method
            .first()
            .map(|vm| (vm.public_key_jwk.x.clone(), vm.public_key_jwk.y.clone()));

        if existing_key != incoming_key {
            return Err(DidError::InvalidFormat(format!(
                "key change rejected for {}: external ingest cannot rotate keys",
                doc.id
            )));
        }
    }

    let floor = existing.map(|e| e.sgx_version_id).unwrap_or(0);
    verify_with_replay_protection(&doc, floor)?;
    save_peer(&doc)?;
    let aggregate = list_peer_docs()?;
    save_ca_aggregate(&aggregate)?;
    Ok(())
}

pub async fn ca_export_aggregate() -> Result<String, DidError> {
    let docs = load_ca_aggregate()?;
    Ok(serde_json::to_string(&docs)?)
}

pub async fn send_request(
    ca_host: &str,
    req: &RegistryRequest,
) -> Result<RegistryResponse, DidError> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(REQ_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| {
        DidError::Io(std::io::Error::other(format!(
            "timeout connecting {}",
            addr
        )))
    })?
    .map_err(|e| DidError::Io(std::io::Error::other(format!("connect {}: {}", addr, e))))?;

    let (reader, mut writer) = stream.into_split();
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| DidError::Io(std::io::Error::other(format!("write: {}", e))))?;

    let mut br = BufReader::new(reader);
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(REQ_TIMEOUT_SECS),
        br.read_line(&mut line),
    )
    .await
    .map_err(|_| DidError::Io(std::io::Error::other("read timeout")))?
    .map_err(|e| DidError::Io(std::io::Error::other(format!("read: {}", e))))?;

    let resp: RegistryResponse = serde_json::from_str(line.trim())?;
    Ok(resp)
}

fn local_floor_version(doc: &DidDocument) -> u32 {
    if let Ok(Some(self_doc)) = crate::did::doc_persistence::load_self() {
        if self_doc.id == doc.id {
            return crate::did::doc_persistence::read_self_floor_version();
        }
    }
    match doc.did() {
        Ok(did) => crate::did::doc_persistence::load_peer(&did)
            .ok()
            .flatten()
            .map(|existing| existing.sgx_version_id)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::doc_persistence::{self, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV};
    use crate::did::document::DocBuildInput;
    use crate::did::{doc_sign, Did};
    use crate::key_manager::KeyManager;
    use tempfile::TempDir;

    fn signed_doc(did: &str, km: &KeyManager, version: u32) -> DidDocument {
        let der = km.pubkey_der().expect("pubkey der");
        let mut doc = DidDocument::build(DocBuildInput {
            did,
            node_name: Some("node-test"),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &der,
            overlay_ip_cidr: None,
            attestation_bind: None,
            cert_bootstrap_bind: None,
            revoked: vec![],
            previous_version_id: version.saturating_sub(1),
            created_at: None,
            status: None,
        })
        .expect("build did doc");
        let vm_ref = doc.verification_method[0].id.clone();
        doc_sign::sign_in_place(&mut doc, km, &vm_ref).expect("sign did doc");
        doc
    }

    // Held across .await deliberately: this test mutates process-wide env
    // vars (SELF_DOC_PATH_ENV etc.) that the async ca_ingest_published() call
    // reads, so the lock must serialize the whole test, not just setup,
    // against other tests running in parallel threads. #[tokio::test] here
    // defaults to a current-thread runtime, so there's no cross-thread guard
    // hand-off for this to deadlock.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn ca_ingest_rejects_key_change_at_same_or_lower_version() {
        let _lock = doc_persistence::lock_test_env();
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        std::env::set_var(SELF_DOC_PATH_ENV, &self_doc_path);
        std::env::set_var(PEERS_DOC_DIR_ENV, &peers_dir);

        let did = Did::from_id_bytes(&[41u8; 32]).to_string();
        let owner_km =
            KeyManager::load_or_generate(td.path().join("owner.key").to_str().unwrap()).unwrap();
        let attacker_km =
            KeyManager::load_or_generate(td.path().join("attacker.key").to_str().unwrap()).unwrap();

        let genuine = signed_doc(&did, &owner_km, 1);
        doc_persistence::save_peer(&genuine).expect("save genuine peer doc");

        // Attacker claims the SAME DID, signs with their OWN key, at the same version.
        let forged = signed_doc(&did, &attacker_km, 1);
        let payload = serde_json::to_string(&forged).expect("forged payload");

        let err = ca_ingest_published(&payload)
            .await
            .expect_err("key change at same version must be rejected");
        assert!(matches!(err, DidError::InvalidFormat(msg) if msg.contains("key change")));

        // The genuine peer doc must be untouched.
        let stored = doc_persistence::load_peer(&Did::parse(&did).unwrap())
            .expect("load peer")
            .expect("peer doc still present");
        assert!(stored.substantively_equal(&genuine));

        std::env::remove_var(SELF_DOC_PATH_ENV);
        std::env::remove_var(PEERS_DOC_DIR_ENV);
    }

    // Held across .await deliberately: see
    // ca_ingest_rejects_key_change_at_same_or_lower_version above.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn ca_ingest_rejects_key_change_even_at_higher_version() {
        let _lock = doc_persistence::lock_test_env();
        let td = TempDir::new().expect("tempdir");
        let self_doc_path = td.path().join("identity").join("did_doc.json");
        let peers_dir = td.path().join("identity").join("peers");
        std::env::set_var(SELF_DOC_PATH_ENV, &self_doc_path);
        std::env::set_var(PEERS_DOC_DIR_ENV, &peers_dir);

        let did = Did::from_id_bytes(&[42u8; 32]).to_string();
        let owner_km =
            KeyManager::load_or_generate(td.path().join("owner2.key").to_str().unwrap()).unwrap();
        let attacker_km =
            KeyManager::load_or_generate(td.path().join("attacker2.key").to_str().unwrap())
                .unwrap();

        let genuine = signed_doc(&did, &owner_km, 1);
        doc_persistence::save_peer(&genuine).expect("save genuine peer doc");

        // Attacker claims the SAME DID with their OWN key, but at a HIGHER
        // version than the genuine doc — the exact bypass the plain
        // version-number check missed (Round 3): a version bump alone was
        // being accepted as sufficient proof of a legitimate rotation.
        let forged = signed_doc(&did, &attacker_km, 2);
        let payload = serde_json::to_string(&forged).expect("forged payload");

        let err = ca_ingest_published(&payload)
            .await
            .expect_err("key change at a higher version must still be rejected");
        assert!(matches!(err, DidError::InvalidFormat(msg) if msg.contains("key change")));

        let stored = doc_persistence::load_peer(&Did::parse(&did).unwrap())
            .expect("load peer")
            .expect("peer doc still present");
        assert!(stored.substantively_equal(&genuine));

        std::env::remove_var(SELF_DOC_PATH_ENV);
        std::env::remove_var(PEERS_DOC_DIR_ENV);
    }
}
