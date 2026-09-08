use sgx_guardian_client::api::handlers::pwa::{
    guardian_fingerprint, MemberApprovalStatusQuery, MemberApprovalStatusResponse,
    MemberEnrollmentListResponse, MemberEnrollmentView, MemberInvitePreviewRequest,
    MemberInvitePreviewResponse, MemberJoinRequest, MemberJoinResponse,
    MintMemberEnrollmentRequest, MintMemberEnrollmentResponse, OnboardingCircleSummary,
    OnboardingResponse, PwaContact, PwaContactsResponse, PwaHealthResponse, PwaIdentityResponse,
    RegistrationRemovalResponse,
};

fn enrollment(state: &str) -> MemberEnrollmentView {
    MemberEnrollmentView {
        approval_id: "approval".into(),
        circle_id: "circle".into(),
        circle_name: "Circle".into(),
        member_did: "did:member".into(),
        state: state.into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2026-01-02T00:00:00Z".into(),
        name: Some("Name".into()),
        email: Some("n@example.test".into()),
        decided_at: None,
    }
}

#[test]
fn guardian_fingerprint_is_grouped_80_bit_text() {
    let fp = guardian_fingerprint(b"public-key");
    assert_eq!(fp.len(), 19);
    assert_eq!(fp.matches('-').count(), 3);
}

#[test]
fn guardian_fingerprint_is_deterministic() {
    assert_eq!(guardian_fingerprint(b"same"), guardian_fingerprint(b"same"));
}

#[test]
fn guardian_fingerprint_changes_with_key() {
    assert_ne!(guardian_fingerprint(b"a"), guardian_fingerprint(b"b"));
}

#[test]
fn pwa_contact_omits_none_optionals() {
    let contact = PwaContact {
        peer_id: "p".into(),
        display_name: "Peer".into(),
        full_name: None,
        device_name: "Device".into(),
        did: None,
        ip: String::new(),
        status: "active".into(),
        role: "member".into(),
        member_type: "guardian".into(),
        join_date: None,
        last_seen: String::new(),
        online: false,
        presence_status: "offline".into(),
        presence_stale: true,
        presence_expires_at: None,
        heartbeat_interval_seconds: 30,
        call_available: false,
        call_unavailable_reason: None,
    };
    let json = serde_json::to_string(&contact).unwrap();
    assert!(json.contains("peerId"));
    assert!(!json.contains("fullName"));
}

#[test]
fn pwa_contacts_response_serializes_totals() {
    let response = PwaContactsResponse {
        contacts: vec![],
        total: 0,
        timestamp: "t".into(),
        presence_heartbeat_seconds: 30,
        presence_expiry_seconds: 90,
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["presenceExpirySeconds"],
        90
    );
}

#[test]
fn pwa_identity_response_serializes_did() {
    assert_eq!(
        serde_json::to_value(PwaIdentityResponse {
            did: "did:g".into()
        })
        .unwrap()["did"],
        "did:g"
    );
}

#[test]
fn pwa_health_response_uses_camel_case() {
    let value = serde_json::to_value(PwaHealthResponse {
        status: "ok",
        guardian_did: "did:g".into(),
        actor_id: "actor".into(),
        role: "member".into(),
        circle_ids: vec!["c".into()],
        server_time: 1,
    })
    .unwrap();
    assert_eq!(value["guardianDid"], "did:g");
}

#[test]
fn onboarding_response_serializes_circle_summaries() {
    let response = OnboardingResponse {
        guardian_did: "did:g".into(),
        guardian_name: "node".into(),
        fingerprint: "AAAA-BBBB-CCCC-DDDD".into(),
        fingerprint_algorithm: "alg",
        fingerprint_bits: 80,
        circles: vec![OnboardingCircleSummary {
            id: "c".into(),
            name: "Circle".into(),
        }],
        internet_required: false,
        multiple_guardian_note: "note",
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["circles"][0]["id"],
        "c"
    );
}

#[test]
fn preview_request_accepts_owner_host() {
    let req: MemberInvitePreviewRequest =
        serde_json::from_str(r#"{"inviteToken":"t","ownerHost":"http://owner"}"#).unwrap();
    assert_eq!(req.owner_host.as_deref(), Some("http://owner"));
}

#[test]
fn preview_request_defaults_owner_host() {
    let req: MemberInvitePreviewRequest = serde_json::from_str(r#"{"inviteToken":"t"}"#).unwrap();
    assert!(req.owner_host.is_none());
}

#[test]
fn preview_response_serializes_role() {
    let response = MemberInvitePreviewResponse {
        valid: true,
        circle_id: "c".into(),
        circle_name: "Circle".into(),
        issuer_did: "did:g".into(),
        expires_at: "t".into(),
        role: "member",
        approval_required: true,
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["approvalRequired"],
        true
    );
}

#[test]
fn member_join_request_deserializes_required_fields() {
    let req: MemberJoinRequest = serde_json::from_str(
        r#"{"name":"N","email":"e@example.test","password":"Pass!123","inviteToken":"t","acceptedFingerprint":"fp","fingerprintConfirmed":true}"#,
    )
    .unwrap();
    assert!(req.fingerprint_confirmed);
}

#[test]
fn member_join_response_round_trips_pending_fields() {
    let response = MemberJoinResponse {
        token: "tok".into(),
        user_id: "u".into(),
        email: "e".into(),
        role: "member".into(),
        scopes: vec!["call".into()],
        guardian_did: "did:g".into(),
        guardian_fingerprint: "fp".into(),
        circle_ids: vec!["c".into()],
        browser_registration_id: "r".into(),
        browser_member_did: "did:m".into(),
        expires_at: 1,
        registration_expires_at: 2,
        status: "pending".into(),
        approval_id: Some("a".into()),
        approval_claim: Some("claim".into()),
    };
    let parsed: MemberJoinResponse =
        serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
    assert_eq!(parsed.approval_id.as_deref(), Some("a"));
}

#[test]
fn registration_removal_response_serializes_status() {
    assert_eq!(
        serde_json::to_value(RegistrationRemovalResponse {
            status: "removed",
            revoked_sessions: 2
        })
        .unwrap()["revokedSessions"],
        2
    );
}

#[test]
fn mint_request_defaults_expiry() {
    let req: MintMemberEnrollmentRequest =
        serde_json::from_str(r#"{"baseUrl":"http://local"}"#).unwrap();
    assert!(req.expires_in_minutes.is_none());
}

#[test]
fn mint_response_round_trips_enrollment() {
    let response = MintMemberEnrollmentResponse {
        link: "http://join".into(),
        expires_at: "t".into(),
        enrollment: enrollment("pending"),
    };
    assert_eq!(
        serde_json::from_str::<MintMemberEnrollmentResponse>(
            &serde_json::to_string(&response).unwrap()
        )
        .unwrap()
        .enrollment
        .state,
        "pending"
    );
}

#[test]
fn enrollment_list_serializes_empty() {
    assert_eq!(
        serde_json::to_value(MemberEnrollmentListResponse {
            enrollments: vec![]
        })
        .unwrap()["enrollments"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn approval_status_query_deserializes_claim() {
    let query: MemberApprovalStatusQuery = serde_json::from_str(r#"{"claim":"a.b"}"#).unwrap();
    assert_eq!(query.claim, "a.b");
}

#[test]
fn approval_status_response_serializes_state() {
    let response = MemberApprovalStatusResponse {
        approval_id: "a".into(),
        state: "issued".into(),
        circle_name: "Circle".into(),
        member_did: "did:m".into(),
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["circleName"],
        "Circle"
    );
}

macro_rules! enrollment_view_cases {
    ($($name:ident => $state:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let value = serde_json::to_value(enrollment($state)).unwrap();
            assert_eq!(value["state"], $state);
            assert_eq!(value["approvalId"], "approval");
        }
    )+};
}

enrollment_view_cases! {
    enrollment_pending => "pending",
    enrollment_issued => "issued",
    enrollment_approved => "approved",
    enrollment_rejected => "rejected",
    enrollment_expired => "expired",
    enrollment_unknown => "custom",
}
