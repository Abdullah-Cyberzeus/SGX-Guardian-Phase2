use chrono::{Duration, Utc};
use serde_json::json;
use sgx_guardian_client::call::media_state::{MediaStats, MediaStreamState};
use sgx_guardian_client::call::protocol::{ReplayProtector, SignalKind, SignalingEnvelope};
use sgx_guardian_client::call::signal_hub::{CallSignalHub, QualityReport};
use sgx_guardian_client::call::{
    AudioStream, CallAnswer, CallMediaState, CallOffer, MediaGate, MediaType, ScreenShareStream,
    VerificationRequirements, VerificationState, VideoStream,
};
use sgx_guardian_client::key_manager::KeyManager;
use tempfile::tempdir;

fn signer(name: &str) -> (tempfile::TempDir, KeyManager) {
    let dir = tempdir().unwrap();
    let key = KeyManager::load_or_generate(dir.path().join(name).to_str().unwrap()).unwrap();
    (dir, key)
}

#[tokio::test]
async fn offers_and_answers_validate_sign_serialize_and_reject_tampering() {
    let (_dir, key) = signer("caller.pk8");
    let offer = CallOffer::new(
        "node-a".into(),
        "vid-a".into(),
        "session-a".into(),
        "nonce-a".into(),
        vec![MediaType::Audio, MediaType::Video],
        &key,
    )
    .await
    .unwrap();
    offer.verify_signature(&key.pubkey_der().unwrap()).unwrap();
    let parsed = CallOffer::from_json(&offer.to_json().unwrap()).unwrap();
    assert_eq!(parsed.requested_media.len(), 2);
    assert!(CallOffer::from_json("not-json").is_err());

    let mut tampered = parsed;
    tampered.session_id = "other-session".into();
    assert!(tampered
        .verify_signature(&key.pubkey_der().unwrap())
        .is_err());
    for (device, virtual_id, session, nonce, media) in [
        ("", "vid", "session", "nonce", vec![MediaType::Audio]),
        ("node", "", "session", "nonce", vec![MediaType::Audio]),
        ("node", "vid", "", "nonce", vec![MediaType::Audio]),
        ("node", "vid", "session", "", vec![MediaType::Audio]),
        ("node", "vid", "session", "nonce", vec![]),
    ] {
        assert!(CallOffer::new(
            device.into(),
            virtual_id.into(),
            session.into(),
            nonce.into(),
            media,
            &key,
        )
        .await
        .is_err());
    }

    let accepted = CallAnswer::accept(
        "node-b".into(),
        "vid-b".into(),
        "session-a".into(),
        "answer-1".into(),
        vec![MediaType::Audio],
        &key,
    )
    .await
    .unwrap();
    assert!(accepted.accepted);
    accepted
        .verify_signature(&key.pubkey_der().unwrap())
        .unwrap();
    assert!(CallAnswer::accept(
        "node-b".into(),
        "vid-b".into(),
        "session-a".into(),
        "answer-2".into(),
        vec![],
        &key,
    )
    .await
    .is_err());
    let rejected = CallAnswer::reject(
        "node-b".into(),
        "vid-b".into(),
        "session-a".into(),
        "answer-3".into(),
        "busy".into(),
        &key,
    )
    .await
    .unwrap();
    assert!(!rejected.accepted);
    assert_eq!(rejected.rejection_reason.as_deref(), Some("busy"));
    assert!(!rejected.to_json().unwrap().is_empty());
    assert!(CallAnswer::from_json("{").is_err());
}

#[test]
fn signaling_envelopes_are_canonical_signed_fresh_and_shape_checked() {
    let (_dir, key) = signer("signal.pk8");
    let first = SignalingEnvelope::new(
        SignalKind::SdpOffer,
        "session",
        "node-a",
        "vid-a",
        1,
        "nonce-1",
        json!({"z": 2, "a": {"y": 1, "b": 0}}),
    );
    let reordered = SignalingEnvelope {
        payload: serde_json::from_str(r#"{"a":{"b":0,"y":1},"z":2}"#).unwrap(),
        timestamp: first.timestamp,
        ..first.clone()
    };
    assert_eq!(
        first.canonical_bytes().unwrap(),
        reordered.canonical_bytes().unwrap()
    );
    let signed = first.sign(&key).unwrap();
    signed.verify(&key.pubkey_der().unwrap()).unwrap();
    signed.validate_freshness(Utc::now()).unwrap();

    let mut stale = signed.clone();
    stale.timestamp = Utc::now() - Duration::minutes(10);
    assert!(stale.validate_freshness(Utc::now()).is_err());
    let mut invalid = signed.clone();
    invalid.version += 1;
    assert!(invalid.verify(&key.pubkey_der().unwrap()).is_err());
    invalid = signed.clone();
    invalid.sequence = 0;
    assert!(invalid.canonical_bytes().is_ok());
    assert!(invalid.sign(&key).is_err());
    invalid = signed;
    invalid.payload = json!("x".repeat(49 * 1024));
    assert!(invalid.sign(&key).is_err());
}

#[test]
fn every_signal_kind_has_the_expected_browser_classification() {
    let browser = [
        SignalKind::SdpOffer,
        SignalKind::SdpAnswer,
        SignalKind::IceCandidate,
        SignalKind::IceComplete,
        SignalKind::MediaReady,
        SignalKind::Hangup,
        SignalKind::Error,
    ];
    let guardian = [
        SignalKind::Offer,
        SignalKind::Answer,
        SignalKind::Heartbeat,
        SignalKind::GroupControl,
    ];
    assert!(browser.into_iter().all(SignalKind::is_browser_signal));
    assert!(guardian.into_iter().all(|kind| !kind.is_browser_signal()));
}

#[tokio::test]
async fn replay_protection_is_scoped_by_sender_and_session_and_can_be_forgotten() {
    let protector = ReplayProtector::default();
    let envelope = |sender: &str, session: &str, sequence: u64, nonce: &str| {
        SignalingEnvelope::new(
            SignalKind::Heartbeat,
            session,
            sender,
            "vid",
            sequence,
            nonce,
            json!({}),
        )
    };
    let first = envelope("node-a", "call-a", 2, "nonce-2");
    protector.check_and_record(&first).await.unwrap();
    assert!(protector.check_and_record(&first).await.is_err());
    assert!(protector
        .check_and_record(&envelope("node-a", "call-a", 1, "nonce-1"))
        .await
        .is_err());
    protector
        .check_and_record(&envelope("node-b", "call-a", 1, "nonce-1"))
        .await
        .unwrap();
    protector
        .check_and_record(&envelope("node-a", "call-b", 1, "nonce-1"))
        .await
        .unwrap();
    protector.forget_session("call-a").await;
    protector
        .check_and_record(&envelope("node-a", "call-a", 1, "nonce-1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn signal_hub_queues_broadcasts_clears_and_rejects_invalid_data() {
    let hub = CallSignalHub::default();
    let mut live = hub.subscribe();
    let signal = SignalingEnvelope::new(
        SignalKind::IceCandidate,
        "call",
        "node-a",
        "vid-a",
        1,
        "nonce",
        json!({"candidate": "candidate:1"}),
    );
    let stored = hub.push_remote(&signal).await.unwrap();
    assert_eq!(live.recv().await.unwrap(), stored);
    assert_eq!(hub.list_after("call", 0).await, vec![stored.clone()]);
    assert!(hub.list_after("call", stored.id).await.is_empty());
    let non_browser = SignalingEnvelope::new(
        SignalKind::Offer,
        "call",
        "node-a",
        "vid-a",
        2,
        "nonce-2",
        json!({}),
    );
    assert!(hub.push_remote(&non_browser).await.is_err());

    let valid = QualityReport {
        rtt_ms: Some(120_000),
        jitter_ms: Some(60_000),
        packet_loss_percent: Some(100.0),
        codec: Some("audio/opus".into()),
        observed_at: Utc::now() - Duration::days(1),
    };
    hub.record_quality("call", valid).await.unwrap();
    for invalid in [
        QualityReport {
            rtt_ms: Some(120_001),
            jitter_ms: None,
            packet_loss_percent: None,
            codec: None,
            observed_at: Utc::now(),
        },
        QualityReport {
            rtt_ms: None,
            jitter_ms: Some(60_001),
            packet_loss_percent: None,
            codec: None,
            observed_at: Utc::now(),
        },
        QualityReport {
            rtt_ms: None,
            jitter_ms: None,
            packet_loss_percent: Some(-0.1),
            codec: None,
            observed_at: Utc::now(),
        },
        QualityReport {
            rtt_ms: None,
            jitter_ms: None,
            packet_loss_percent: Some(f32::NAN),
            codec: None,
            observed_at: Utc::now(),
        },
        QualityReport {
            rtt_ms: None,
            jitter_ms: None,
            packet_loss_percent: None,
            codec: Some("x".repeat(65)),
            observed_at: Utc::now(),
        },
    ] {
        assert!(hub.record_quality("call", invalid).await.is_err());
    }
    hub.clear("call").await;
    assert!(hub.list_after("call", 0).await.is_empty());
}

#[test]
fn media_streams_stats_and_gate_cover_audio_video_and_screen_share() {
    assert_eq!(MediaStreamState::Inactive.as_str(), "inactive");
    assert_eq!(MediaStreamState::Active.as_str(), "active");
    assert_eq!(MediaStreamState::Paused.as_str(), "paused");
    assert_eq!(MediaStreamState::Error.as_str(), "error");
    assert_eq!(MediaStats::default().bytes_sent, 0);

    let mut audio = AudioStream::new("opus".into(), 48_000, 2, 128);
    let mut video = VideoStream::new("vp9".into(), 1280, 720, 30, 2500);
    let mut screen = ScreenShareStream::new("vp9".into(), 1920, 1080, 15, 3000);
    audio.activate();
    video.pause();
    screen.activate();
    assert_eq!(video.resolution(), "1280x720");

    let mut media = CallMediaState::new("call".into());
    media.add_audio(audio);
    media.add_video(video);
    media.add_screen_share(screen);
    assert!(media.is_audio_active());
    assert!(!media.is_video_active());
    assert!(media.is_screen_share_active());
    assert!(media.is_any_stream_active());

    let mut gate = MediaGate::new("call".into());
    assert!(gate.check_media_stream(&media).is_err());
    assert!(gate.verify_policy().is_err());
    gate.verify_attestation().unwrap();
    gate.verify_authorization().unwrap();
    gate.verify_policy().unwrap();
    assert_eq!(gate.state(), VerificationState::Verified);
    gate.check_media_stream(&media).unwrap();

    let mut denied = MediaGate::with_requirements(
        "denied".into(),
        VerificationRequirements {
            require_attestation: true,
            require_authorization: true,
            require_policy_check: true,
        },
    );
    assert!(denied.deny("policy").is_err());
    assert_eq!(denied.state(), VerificationState::Failed);
}
