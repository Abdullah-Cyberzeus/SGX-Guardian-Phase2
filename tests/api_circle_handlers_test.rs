use sgx_guardian_client::api::handlers::circle::{
    AddMemberRequest, ChangeRoleRequest, CircleDeleteResponse, CircleDetailResponse,
    CircleListResponse, CircleMutationResponse, CircleSnapshotSyncResponse, CreateCircleRequest,
    EditCircleRequest, InviteDeleteResponse, InviteListResponse, JoinCircleRequest,
    JoinPreviewRequest, JoinPreviewResponse, MemberListResponse, MemberRemoveResponse,
    MintInviteRequest,
};
use sgx_guardian_client::circle::model::{Circle, CircleKind, CircleStatus};

fn circle(id: &str) -> Circle {
    Circle {
        circle_id: id.into(),
        name: "Circle".into(),
        description: "Desc".into(),
        owner_did: "did:owner".into(),
        kind: CircleKind::Comms,
        status: CircleStatus::Active,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn create_circle_request_defaults_empty() {
    let req = CreateCircleRequest::default();
    assert!(req.name.is_none());
    assert!(req.days.is_none());
}

#[test]
fn create_circle_request_deserializes_all_fields() {
    let req: CreateCircleRequest =
        serde_json::from_str(r#"{"name":"N","description":"D","circle_id":"c","days":7}"#).unwrap();
    assert_eq!(req.name.as_deref(), Some("N"));
    assert_eq!(req.days, Some(7));
}

#[test]
fn edit_circle_request_defaults_empty() {
    assert!(EditCircleRequest::default().name.is_none());
}

#[test]
fn edit_circle_request_accepts_description_only() {
    let req: EditCircleRequest = serde_json::from_str(r#"{"description":"D"}"#).unwrap();
    assert_eq!(req.description.as_deref(), Some("D"));
}

#[test]
fn add_member_request_defaults_empty() {
    assert!(AddMemberRequest::default().did.is_none());
}

#[test]
fn add_member_request_deserializes_role_days() {
    let req: AddMemberRequest =
        serde_json::from_str(r#"{"did":"did:m","role":"member","days":30}"#).unwrap();
    assert_eq!(req.role.as_deref(), Some("member"));
}

#[test]
fn change_role_request_defaults_empty() {
    assert!(ChangeRoleRequest::default().role.is_none());
}

#[test]
fn change_role_request_deserializes_owner() {
    let req: ChangeRoleRequest = serde_json::from_str(r#"{"role":"owner","days":1}"#).unwrap();
    assert_eq!(req.days, Some(1));
}

#[test]
fn mint_invite_request_defaults_empty() {
    assert!(MintInviteRequest::default().target_did.is_none());
}

#[test]
fn mint_invite_request_deserializes_delivery() {
    let req: MintInviteRequest = serde_json::from_str(r#"{"target_did":"did:m","role":"member","expires_in_minutes":5,"max_uses":2,"owner_host":"http://h","deliver":true}"#).unwrap();
    assert_eq!(req.max_uses, Some(2));
    assert_eq!(req.deliver, Some(true));
}

#[test]
fn join_preview_request_deserializes_token() {
    let req: JoinPreviewRequest = serde_json::from_str(r#"{"token_b64":"abc"}"#).unwrap();
    assert_eq!(req.token_b64, "abc");
}

#[test]
fn join_circle_request_deserializes_owner_host() {
    let req: JoinCircleRequest =
        serde_json::from_str(r#"{"token_b64":"abc","owner_host":"http://owner"}"#).unwrap();
    assert_eq!(req.owner_host.as_deref(), Some("http://owner"));
}

#[test]
fn circle_list_response_serializes_count() {
    let response = CircleListResponse {
        status: "ok".into(),
        count: 1,
        circles: vec![circle("c")],
    };
    assert_eq!(serde_json::to_value(response).unwrap()["count"], 1);
}

#[test]
fn circle_detail_response_serializes_circle_id() {
    let response = CircleDetailResponse {
        status: "ok".into(),
        circle: circle("c"),
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["circle"]["circleId"],
        "c"
    );
}

#[test]
fn circle_mutation_response_round_trips() {
    let response = CircleMutationResponse {
        status: "ok".into(),
        message: "created".into(),
        circle: circle("c"),
    };
    let parsed: CircleMutationResponse =
        serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
    assert_eq!(parsed.message, "created");
}

#[test]
fn circle_delete_response_serializes_revoked_ids() {
    let response = CircleDeleteResponse {
        status: "ok".into(),
        message: "deleted".into(),
        circle_id: "c".into(),
        revoked_vc_ids: vec!["vc".into()],
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["revoked_vc_ids"][0],
        "vc"
    );
}

#[test]
fn member_list_response_serializes_empty_members() {
    let response = MemberListResponse {
        status: "ok".into(),
        count: 0,
        members: vec![],
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn snapshot_sync_response_serializes_applied_count() {
    let response = CircleSnapshotSyncResponse {
        status: "ok".into(),
        snapshots_applied: 3,
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["snapshots_applied"],
        3
    );
}

#[test]
fn member_remove_response_serializes_revoked_ids() {
    let response = MemberRemoveResponse {
        status: "ok".into(),
        message: "removed".into(),
        revoked_vc_ids: vec!["a".into(), "b".into()],
    };
    assert_eq!(
        serde_json::to_value(response).unwrap()["revoked_vc_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn invite_list_response_serializes_empty() {
    let response = InviteListResponse {
        status: "ok".into(),
        count: 0,
        invites: vec![],
    };
    assert_eq!(serde_json::to_value(response).unwrap()["count"], 0);
}

#[test]
fn invite_delete_response_serializes_id() {
    let response = InviteDeleteResponse {
        status: "ok".into(),
        message: "revoked".into(),
        invite_id: "i".into(),
    };
    assert_eq!(serde_json::to_value(response).unwrap()["invite_id"], "i");
}

#[test]
fn join_preview_response_serializes_role_and_uses() {
    let response = JoinPreviewResponse {
        status: "ok".into(),
        circle_id: "c".into(),
        circle_name: "Circle".into(),
        issuer_did: "did:g".into(),
        role: "member".into(),
        expires_at: "t".into(),
        max_uses: 1,
    };
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["role"], "member");
    assert_eq!(value["max_uses"], 1);
}

macro_rules! circle_kind_status_cases {
    ($($name:ident => $kind:expr, $status:expr, $mesh:expr, $archived:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let mut c = circle("c");
            c.kind = $kind;
            c.status = $status;
            assert_eq!(c.is_mesh(), $mesh);
            assert_eq!(c.is_archived(), $archived);
        }
    )+};
}

circle_kind_status_cases! {
    comms_active_flags => CircleKind::Comms, CircleStatus::Active, false, false,
    mesh_active_flags => CircleKind::Mesh, CircleStatus::Active, true, false,
    comms_archived_flags => CircleKind::Comms, CircleStatus::Archived, false, true,
    mesh_archived_flags => CircleKind::Mesh, CircleStatus::Archived, true, true,
}
