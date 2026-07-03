use axum::extract::State;


use sgx_guardian_client::api::handlers::vid::peers;
use sgx_guardian_client::api::state::AppState;
use sgx_guardian_client::did::Resolver;
use sgx_guardian_client::virtual_id_cache::ObservationContext;

#[tokio::test]
async fn test_vid_peers_handler() {
    let resolver = Resolver::new(Default::default());
    let app_state = AppState::from_env("test-node-1".to_string(), resolver);


    // Node 1
    let ctx1 = ObservationContext {
        peer_did: "did:guardian:node1",
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

    // Node 2
    let ctx2 = ObservationContext {
        peer_did: "did:guardian:node2",
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

    // Should be sorted by DID
    assert_eq!(peers_list[0].did, "did:guardian:node1");
    assert_eq!(peers_list[0].virtual_id, "abcd1234efgh5678");
    assert_eq!(peers_list[0].last_rotation_reason, Some("initial_observation".to_string()));

    assert_eq!(peers_list[1].did, "did:guardian:node2");
    assert_eq!(peers_list[1].virtual_id, "9876zyxw5432vuts");
    assert_eq!(peers_list[1].last_rotation_reason, Some("initial_observation".to_string()));
}

#[tokio::test]
async fn test_vid_show_handler_error_path() {
    let resolver = Resolver::new(Default::default());
    // Create an AppState with paths that don't exist to force `read_runtime_virtual_id_status` to fail.
    // read_runtime_virtual_id_status looks for `/var/lib/sgx-guardian/virtual_id/...` or `state.pcr_dir` depending on implementation.
    let app_state = AppState::from_env("test-node-missing".to_string(), resolver);

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
