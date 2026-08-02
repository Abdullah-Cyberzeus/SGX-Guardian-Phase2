use sgx_guardian_client::call::CallState;

#[test]
fn test_all_state_transitions_are_exhaustive() {
    let all_states = vec![
        CallState::Idle,
        CallState::LocalPolicyCheck,
        CallState::OfferSent,
        CallState::OfferReceived,
        CallState::Verifying,
        CallState::Authorizing,
        CallState::Accepted,
        CallState::MediaNegotiation,
        CallState::Connected,
        CallState::EndCall,
    ];

    for state in &all_states {
        let reachable = state.reachable_from();
        if *state != CallState::EndCall {
            assert!(
                !reachable.is_empty(),
                "State {} should have at least one outgoing path",
                state
            );
        } else {
            assert!(reachable.is_empty(), "EndCall should be terminal");
        }

        for next in &all_states {
            let result = state.validate_transition(*next);
            let expecting = reachable.contains(next);
            if expecting {
                assert!(
                    result.is_ok(),
                    "Valid transition from {} to {} was rejected",
                    state,
                    next
                );
            } else if *state != CallState::EndCall || *next != CallState::EndCall {
                assert!(
                    result.is_err(),
                    "Invalid transition from {} to {} was accepted",
                    state,
                    next
                );
            }
        }
    }
}

#[test]
fn test_terminal_state_reachability() {
    assert!(CallState::EndCall.is_terminal());
    assert!(!CallState::Connected.is_terminal());
}
