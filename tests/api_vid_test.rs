use axum::extract::State;
use base64::{Engine as _, engine::general_purpose};

use sgx_guardian_client::api::handlers::vid::peers;
use sgx_guardian_client::api::state::AppState;
use sgx_guardian_client::did::Did;
use sgx_guardian_client::did::doc_persistence;
use sgx_guardian_client::did::document::{DidDocument, Jwk, VerificationMethod};
use sgx_guardian_client::virtual_id_cache::ObservationContext;
use std::ffi::OsString;
use tempfile::TempDir;

struct EnvGuard {
    vars: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn new(mappings: &[(&'static str, &str)]) -> Self {
        let mut vars = Vec::new();
        for (key, value) in mappings {
            vars.push((*key, std::env::var_os(*key)));
            std::env::set_var(key, value);
        }
        Self { vars }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            if let Some(previous) = value {
                std::env::set_var(key, previous);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

fn peer_doc(did: &str, node_name: Option<&str>) -> DidDocument {
    let vm_id = format!("{}#dkp-v1", did);
    DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: did.to_string(),
        controller: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: vm_id.clone(),
            vm_type: "JsonWebKey2020".to_string(),
            controller: did.to_string(),
            public_key_jwk: Jwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
                y: general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
                kid: "dkp-v1".to_string(),
            },
        }],
        authentication: vec![vm_id.clone()],
        assertion_method: vec![vm_id],
        service: vec![],
        sgx_node_name: node_name.map(str::to_string),
        sgx_created: "2026-01-01T00:00:00Z".to_string(),
        sgx_updated: "2026-01-01T00:00:00Z".to_string(),
        sgx_version_id: 1,
        sgx_method_spec_version: "1.0".to_string(),
        sgx_status: Some("active".to_string()),
        sgx_revoked_vm: vec![],
        proof: None,
    }
}

#[tokio::test]
async fn test_vid_peers_handler() {
    let temp_dir = TempDir::new().expect("tempdir");
    let peers_dir = temp_dir.path().join("identity").join("peers");
    std::fs::create_dir_all(&peers_dir).expect("peers dir");
    let _env_guard = EnvGuard::new(&[(
        "SGX_GUARDIAN_DID_PEERS_DIR",
        peers_dir.to_str().expect("peers path"),
    )]);
    let config_dir = temp_dir.path().join("config").to_string_lossy().to_string();
    let app_state = AppState::for_tests(temp_dir.path(), "test-node-1", config_dir);
    let mapped_did = Did::from_id_bytes(&[7u8; 32]).as_str().to_string();
    doc_persistence::save_peer(&peer_doc(&mapped_did, Some("nodeB"))).expect("save peer doc");

    // Node 1
    let ctx1 = ObservationContext {
        peer_did: &mapped_did,
        peer_ip_hint: "",
        new_vid_hex: "abcd1234efgh5678",
        new_stable_hex: "stable1",
        new_dkp_verification_method_id: "vm1",
        new_dkp_kid: "kid1",
        new_dkp_fp: "fp1",
        new_pcr_digest: "pcr1",
        new_policy_digest: "pol1",
    };
    app_state.vid_cache.observe_rich(&ctx1);

    // Node 2 has no trusted DID registry mapping, so the API must not guess.
    let ctx2 = ObservationContext {
        peer_did: "did:guardian:unmapped-peer",
        peer_ip_hint: "",
        new_vid_hex: "9876zyxw5432vuts",
        new_stable_hex: "stable2",
        new_dkp_verification_method_id: "vm2",
        new_dkp_kid: "kid2",
        new_dkp_fp: "fp2",
        new_pcr_digest: "pcr2",
        new_policy_digest: "pol2",
    };
    app_state.vid_cache.observe_rich(&ctx2);

    let response = peers(State(app_state)).await;
    assert!(response.is_ok());

    let json_response = response.unwrap().0;
    let peers_list = json_response.peers;

    assert_eq!(peers_list.len(), 2);

    let mapped = peers_list
        .iter()
        .find(|peer| peer.did == mapped_did)
        .expect("mapped peer");
    assert_eq!(mapped.node_name.as_deref(), Some("nodeB"));
    assert_eq!(mapped.virtual_id, "abcd1234efgh5678");
    assert_eq!(
        mapped.last_rotation_reason,
        Some("initial_observation".to_string())
    );

    let unmapped = peers_list
        .iter()
        .find(|peer| peer.did == "did:guardian:unmapped-peer")
        .expect("unmapped peer");
    assert_eq!(unmapped.node_name, None);
    assert_eq!(unmapped.virtual_id, "9876zyxw5432vuts");
    assert_eq!(
        unmapped.last_rotation_reason,
        Some("initial_observation".to_string())
    );
}

#[tokio::test]
async fn test_vid_show_handler_error_path() {
    let temp_dir = TempDir::new().expect("tempdir");
    let config_dir = temp_dir.path().join("config").to_string_lossy().to_string();
    // read_runtime_virtual_id_status looks up the node's runtime status by node_id,
    // which has no backing file for this never-provisioned node id, so it fails.
    let app_state = AppState::for_tests(temp_dir.path(), "test-node-missing", config_dir);

    let response = sgx_guardian_client::api::handlers::vid::show(State(app_state)).await;
    // It should return an ApiError::Internal because the status file is missing
    assert!(response.is_err());

    // We expect the error to contain "VID show"
    match response {
        Err(e) => {
            let error_str = format!("{:?}", e);
            assert!(error_str.contains("VID show"));
        }
        _ => panic!("Expected error"),
    }
}
