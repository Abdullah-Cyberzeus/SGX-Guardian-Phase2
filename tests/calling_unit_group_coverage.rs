use chrono::{Duration, Utc};
use sgx_guardian_client::call::{
    CallHistoryStore, GroupCallState, GroupMemberState, GroupParticipant, GroupRole,
    GroupSessionManager, GroupWireMessage, MediaType, ModerationAction, MAX_GROUP_PARTICIPANTS,
};
use std::sync::Arc;
use tempfile::tempdir;

fn participant(device_id: &str, ip: &str) -> GroupParticipant {
    GroupParticipant {
        device_id: device_id.into(),
        virtual_id: format!("vid-{device_id}"),
        nebula_ip: ip.into(),
        role: GroupRole::Member,
        state: GroupMemberState::Invited,
        audio_allowed: true,
        video_allowed: true,
        media_ready: false,
        joined_at: None,
        last_seen_at: None,
        is_local_browser: false,
    }
}

#[tokio::test]
async fn group_creation_validates_shape_duplicates_addresses_and_size() {
    let dir = tempdir().unwrap();
    let manager = GroupSessionManager::new(dir.path().join("group.log"));
    let host = participant("host", "192.168.100.1");
    assert!(manager
        .create("x".into(), host.clone(), vec![], vec![MediaType::Audio])
        .await
        .is_err());
    assert!(manager
        .create(
            "x".into(),
            host.clone(),
            vec![participant("member", "bad-ip")],
            vec![MediaType::Audio]
        )
        .await
        .is_err());
    assert!(manager
        .create(
            "x".into(),
            host.clone(),
            vec![participant("host", "192.168.100.2")],
            vec![MediaType::Audio]
        )
        .await
        .is_err());
    assert!(manager
        .create(
            "x".into(),
            host.clone(),
            vec![participant("member", "192.168.100.2")],
            vec![]
        )
        .await
        .is_err());

    let too_many = (1..=MAX_GROUP_PARTICIPANTS)
        .map(|index| {
            participant(
                &format!("member-{index}"),
                &format!("192.168.100.{}", index + 1),
            )
        })
        .collect();
    assert!(manager
        .create("x".into(), host, too_many, vec![MediaType::Audio])
        .await
        .is_err());
}

#[tokio::test]
async fn group_lifecycle_emits_events_enforces_roles_and_records_history() {
    let dir = tempdir().unwrap();
    let history = Arc::new(CallHistoryStore::new(dir.path().join("history.json")));
    let manager =
        GroupSessionManager::with_history_store(dir.path().join("group.log"), history.clone());
    let mut events = manager.subscribe();
    let created = manager
        .create(
            "Team call".into(),
            participant("host", "192.168.100.1"),
            vec![participant("member", "192.168.100.2")],
            vec![MediaType::Audio, MediaType::Video],
        )
        .await
        .unwrap();
    assert_eq!(events.recv().await.unwrap().event, "group_created");
    assert_eq!(created.state, GroupCallState::Ringing);
    assert_eq!(manager.active_for("member").await.len(), 1);

    let joined = manager
        .join(&created.group_id, "member", "192.168.100.2")
        .await
        .unwrap();
    assert_eq!(joined.state, GroupCallState::Active);
    assert_eq!(events.recv().await.unwrap().event, "group_joined");
    let ready = manager
        .mark_media_ready(&created.group_id, "member", true, "192.168.100.2")
        .await
        .unwrap();
    assert!(ready.participants["member"].media_ready);

    assert!(manager
        .moderate(
            &created.group_id,
            "member",
            ModerationAction::SetAudio {
                device_id: "host".into(),
                allowed: false
            },
        )
        .await
        .is_err());
    let muted = manager
        .moderate(
            &created.group_id,
            "host",
            ModerationAction::SetAudio {
                device_id: "member".into(),
                allowed: false,
            },
        )
        .await
        .unwrap();
    assert!(!muted.participants["member"].audio_allowed);
    let video = manager
        .moderate(
            &created.group_id,
            "host",
            ModerationAction::SetVideo {
                device_id: "member".into(),
                allowed: false,
            },
        )
        .await
        .unwrap();
    assert!(!video.participants["member"].video_allowed);
    assert!(manager.end(&created.group_id, "member").await.is_err());
    let ended = manager.end(&created.group_id, "host").await.unwrap();
    assert_eq!(ended.state, GroupCallState::Ended);
    assert_eq!(history.list()[0].outcome, "completed");
    manager.remove_ended(&created.group_id).await;
    assert!(manager.get(&created.group_id).await.is_err());
}

#[tokio::test]
async fn decline_leave_kick_and_heartbeat_rules_fail_closed() {
    let dir = tempdir().unwrap();
    let manager = GroupSessionManager::new(dir.path().join("rules.log"));
    let created = manager
        .create(
            "Rules".into(),
            participant("host", "192.168.100.1"),
            vec![
                participant("decliner", "192.168.100.2"),
                participant("member", "192.168.100.3"),
            ],
            vec![MediaType::Audio],
        )
        .await
        .unwrap();
    let declined = manager
        .decline(&created.group_id, "decliner", "192.168.100.2")
        .await
        .unwrap();
    assert_eq!(
        declined.participants["decliner"].state,
        GroupMemberState::Declined
    );
    assert!(manager
        .heartbeat(&created.group_id, "decliner", "192.168.100.2")
        .await
        .is_err());
    assert!(manager
        .mark_media_ready(&created.group_id, "decliner", true, "192.168.100.2")
        .await
        .is_err());

    manager
        .join(&created.group_id, "member", "192.168.100.3")
        .await
        .unwrap();
    let left = manager
        .leave(&created.group_id, "member", "192.168.100.3")
        .await
        .unwrap();
    assert_eq!(left.participants["member"].state, GroupMemberState::Left);
    assert!(manager
        .leave(&created.group_id, "host", "192.168.100.1")
        .await
        .is_err());
    manager
        .join(&created.group_id, "member", "192.168.100.3")
        .await
        .unwrap();
    let kicked = manager
        .moderate(
            &created.group_id,
            "host",
            ModerationAction::Kick {
                device_id: "member".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        kicked.participants["member"].state,
        GroupMemberState::Kicked
    );
    assert!(manager
        .heartbeat(&created.group_id, "member", "192.168.100.3")
        .await
        .is_err());
    assert!(manager
        .join(&created.group_id, "member", "192.168.100.3")
        .await
        .is_err());
}

#[tokio::test]
async fn stale_presence_moves_through_reconnecting_and_disconnected() {
    let dir = tempdir().unwrap();
    let manager = GroupSessionManager::new(dir.path().join("presence.log"));
    let created = manager
        .create(
            "Presence".into(),
            participant("host", "192.168.100.1"),
            vec![participant("member", "192.168.100.2")],
            vec![MediaType::Audio],
        )
        .await
        .unwrap();
    let mut snapshot = manager
        .join(&created.group_id, "member", "192.168.100.2")
        .await
        .unwrap();
    snapshot
        .participants
        .get_mut("member")
        .unwrap()
        .last_seen_at = Some(Utc::now() - Duration::seconds(25));
    snapshot.updated_at = Utc::now() + Duration::milliseconds(1);
    manager
        .apply_snapshot(snapshot, "host", "192.168.100.1")
        .await
        .unwrap();
    let changed = manager.expire_stale_for_host("host").await;
    assert_eq!(
        changed[0].participants["member"].state,
        GroupMemberState::Reconnecting
    );
    manager
        .heartbeat(&created.group_id, "member", "192.168.100.2")
        .await
        .unwrap();
    assert_eq!(
        manager.get(&created.group_id).await.unwrap().participants["member"].state,
        GroupMemberState::Joined
    );

    let mut snapshot = manager.get(&created.group_id).await.unwrap();
    snapshot
        .participants
        .get_mut("member")
        .unwrap()
        .last_seen_at = Some(Utc::now() - Duration::seconds(50));
    snapshot.updated_at = Utc::now() + Duration::milliseconds(1);
    manager
        .apply_snapshot(snapshot, "host", "192.168.100.1")
        .await
        .unwrap();
    let changed = manager.expire_stale_for_host("host").await;
    assert_eq!(
        changed[0].participants["member"].state,
        GroupMemberState::Disconnected
    );
}

#[tokio::test]
async fn snapshots_invites_wire_messages_and_persistence_are_safe() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("persist.log");
    let host = GroupSessionManager::new(&log);
    let created = host
        .create(
            "Persistent".into(),
            participant("host", "192.168.100.1"),
            vec![participant("member", "192.168.100.2")],
            vec![MediaType::Video],
        )
        .await
        .unwrap();
    let wire = GroupWireMessage::Invite {
        session: created.clone(),
    };
    let round_trip: GroupWireMessage =
        serde_json::from_str(&serde_json::to_string(&wire).unwrap()).unwrap();
    assert!(matches!(round_trip, GroupWireMessage::Invite { .. }));

    let receiver = GroupSessionManager::new(dir.path().join("receiver.log"));
    receiver
        .register_invite(created.clone(), "member", "192.168.100.2")
        .await
        .unwrap();
    let mut stale = created.clone();
    stale.updated_at -= Duration::seconds(1);
    assert!(receiver
        .apply_snapshot(stale, "member", "192.168.100.2")
        .await
        .is_err());
    assert!(receiver
        .apply_snapshot(created.clone(), "outsider", "192.168.100.9")
        .await
        .is_err());

    drop(host);
    let restored = GroupSessionManager::new(&log);
    assert_eq!(
        restored.get(&created.group_id).await.unwrap().title,
        "Persistent"
    );
    restored.record_log(
        "manual",
        &created.group_id,
        "host",
        Some("member"),
        "covered",
    );
    assert!(std::fs::read_to_string(restored.log_path())
        .unwrap()
        .contains("manual"));
}
