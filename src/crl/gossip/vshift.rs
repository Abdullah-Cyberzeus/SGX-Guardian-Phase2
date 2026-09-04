//! Task2 VS15 VSHIFT_ALERT routing over the EXISTING Guardian gossip channel.
//!
//! No dedicated listener or port is created here. Outbound messages use the
//! same active gossip peer directory, Nebula overlay addresses, TCP port and
//! newline-delimited JSON framing as CRL gossip.
//!
//! Transport membership is the Guardian Mesh Circle. The embedded
//! `VShiftAlert.circle_id` remains part of the Task2 policy contract and is
//! trust-authorized separately by VS16 before any enforcement.

use super::{
    engine::{active_gossip_peers, did_record_path, GossipPeer},
    protocol::{self, VShiftGossipAck, VShiftGossipMessage, KIND_VSHIFT_ACK, KIND_VSHIFT_ALERT},
    GossipConfig,
};
use crate::did::DidRecord;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sgx_anomaly_engine::virtual_shift::{
    AttestationConnector, AttestationConnectorResponse, AttestationRequest, IdentityRotationResult,
    IdentityRotationStatus, MemberAlertVerifier, MemberIdentityRotator, MemberPolicyApplier,
    MemberPolicyApplyResult, ReAttestationResult, ReAttestationService, VShiftAlert,
    VerificationStatus, VS15_GOSSIP, VS16_MEMBER_VERIFICATION, VS17_MEMBER_POLICY_STATE,
    VS18_MEMBER_IDENTITY_STATE,
};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::BufReader,
    net::{tcp::OwnedWriteHalf, TcpStream},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VShiftNetworkDelivery {
    pub node_id: String,
    pub peer_did: String,
    pub relay_hops: u32,
    pub received_at_ms: u64,
    pub delivery_time_ms: u64,
    pub duplicate_suppressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VShiftBroadcastReceipt {
    pub schema_version: u32,
    pub message_type: String,
    pub transport: String,
    pub gossip_port: u16,
    pub alert_id: String,
    pub origin_node: String,
    pub mesh_circle_id: String,
    pub policy_circle_id: String,
    pub broadcast_started_at_ms: u64,
    pub broadcast_completed_at_ms: u64,
    pub delivered: Vec<VShiftNetworkDelivery>,
    pub pending_offline_nodes: Vec<String>,
    pub duplicate_suppressed: bool,
    pub status: String,
    pub receipt_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VShiftRetryTarget {
    pub node_id: String,
    pub peer_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VShiftRetryOutbox {
    pub schema_version: u32,
    pub alert_id: String,
    pub origin_node: String,
    pub mesh_circle_id: String,
    pub policy_circle_id: String,
    pub alert_pb: Vec<u8>,
    pub pending_peers: Vec<VShiftRetryTarget>,
    pub discover_peers: bool,
    pub attempts: u64,
    pub last_attempt_at_ms: Option<u64>,
    pub status: String,
}

pub async fn broadcast_vshift_alert(
    origin_node: &str,
    alert: &VShiftAlert,
) -> Result<VShiftBroadcastReceipt> {
    let config = GossipConfig::from_env();

    if !config.enabled {
        anyhow::bail!("existing Guardian gossip transport is disabled");
    }

    alert.validate()?;

    let local = DidRecord::load(&did_record_path()).context("load local DID for VSHIFT gossip")?;

    let mesh_circle_id = current_mesh_circle_id()?;

    let started_at_ms = now_ms()?;
    let peers = active_gossip_peers(&local.did);

    let mut delivered = Vec::new();
    let mut pending = BTreeSet::new();
    let mut duplicate_suppressed = false;

    for peer in &peers {
        match send_to_peer(origin_node, &local, &mesh_circle_id, &config, &peer, alert).await {
            Ok(receipt) => {
                duplicate_suppressed |= receipt.duplicate_suppressed;
                delivered.push(receipt);
            }
            Err(error) => {
                let label = peer_label(peer);

                tracing::warn!(
                    "VSHIFT gossip delivery failed alert_id={} peer={} did={} error={}",
                    alert.alert_id,
                    label,
                    peer.did,
                    error
                );

                pending.insert(label);
            }
        }
    }

    delivered.sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let pending_peers: Vec<VShiftRetryTarget> = peers
        .iter()
        .filter_map(|peer| {
            let label = peer_label(peer);

            if pending.contains(&label) {
                Some(VShiftRetryTarget {
                    node_id: label,
                    peer_did: peer.did.clone(),
                })
            } else {
                None
            }
        })
        .collect();

    let completed_at_ms = now_ms()?;

    let status = if delivered.is_empty() && pending.is_empty() {
        "queued_no_active_gossip_peers"
    } else if pending.is_empty() {
        "broadcast_network_not_applied"
    } else {
        "broadcast_partial_pending_retry"
    };

    let root = virtual_shift_root();
    let receipt_dir = root.join(VS15_GOSSIP).join(&alert.alert_id);
    std::fs::create_dir_all(&receipt_dir)?;

    let receipt_path = receipt_dir.join("broadcast_receipt.json");

    let receipt = VShiftBroadcastReceipt {
        schema_version: 1,
        message_type: "VSHIFT_ALERT".into(),
        transport: "existing_guardian_gossip".into(),
        gossip_port: config.port,
        alert_id: alert.alert_id.clone(),
        origin_node: origin_node.to_owned(),
        mesh_circle_id,
        policy_circle_id: alert.circle_id.clone(),
        broadcast_started_at_ms: started_at_ms,
        broadcast_completed_at_ms: completed_at_ms,
        delivered,
        pending_offline_nodes: pending.into_iter().collect(),
        duplicate_suppressed,
        status: status.into(),
        receipt_path: receipt_path.display().to_string(),
    };

    let attempts_path = receipt_dir.join("broadcast_attempts.jsonl");

    // The first production retry may already have an older partial
    // broadcast_receipt.json from the initial approval attempt. Preserve it
    // once before replacing the latest-state receipt.
    if receipt_path.is_file() && !attempts_path.is_file() {
        if let Ok(previous_bytes) = std::fs::read(&receipt_path) {
            if let Ok(previous) = serde_json::from_slice::<VShiftBroadcastReceipt>(&previous_bytes)
            {
                append_json_line(&attempts_path, &previous)?;
            }
        }
    }

    append_json_line(&attempts_path, &receipt)?;
    write_json_atomic(&receipt_path, &receipt)?;

    write_retry_outbox(
        &receipt_dir,
        origin_node,
        &receipt.mesh_circle_id,
        alert,
        &pending_peers,
        peers.is_empty(),
        receipt.broadcast_completed_at_ms,
    )?;

    println!(
        "VSHIFT-GOSSIP existing-transport alert_id={} origin={} port={} delivered={} pending={} duplicate_suppressed={}",
        receipt.alert_id,
        receipt.origin_node,
        receipt.gossip_port,
        receipt.delivered.len(),
        receipt.pending_offline_nodes.len(),
        receipt.duplicate_suppressed
    );

    Ok(receipt)
}

fn write_retry_outbox(
    receipt_dir: &Path,
    origin_node: &str,
    mesh_circle_id: &str,
    alert: &VShiftAlert,
    pending_peers: &[VShiftRetryTarget],
    peer_directory_empty: bool,
    completed_at_ms: u64,
) -> Result<()> {
    let outbox_path = receipt_dir.join("retry_outbox.json");

    let previous_attempts = std::fs::read(&outbox_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<VShiftRetryOutbox>(&bytes).ok())
        .map(|state| state.attempts)
        .unwrap_or(0);

    let discover_peers = peer_directory_empty && pending_peers.is_empty();

    let status = if discover_peers {
        "pending_peer_discovery"
    } else if pending_peers.is_empty() {
        "converged"
    } else {
        "pending_retry"
    };

    let outbox = VShiftRetryOutbox {
        schema_version: 1,
        alert_id: alert.alert_id.clone(),
        origin_node: origin_node.to_owned(),
        mesh_circle_id: mesh_circle_id.to_owned(),
        policy_circle_id: alert.circle_id.clone(),
        alert_pb: alert.encode()?,
        pending_peers: pending_peers.to_vec(),
        discover_peers,
        attempts: previous_attempts.saturating_add(1),
        last_attempt_at_ms: Some(completed_at_ms),
        status: status.into(),
    };

    write_json_atomic(&outbox_path, &outbox)
}

/// Automatic VS15 convergence worker.
///
/// This is NOT a transport. It binds no socket and opens no new port.
/// It only reuses the existing Guardian gossip peer directory, Nebula
/// addresses, framing and GossipConfig.port (50063 by default).
pub async fn retry_task(node_id: String, config: GossipConfig) {
    let interval_secs = config.interval_secs.max(1);

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        match retry_pending_once(&node_id, &config).await {
            Ok(converged) if converged > 0 => {
                println!(
                    "VSHIFT-GOSSIP auto-retry cycle node={} converged_alerts={}",
                    node_id, converged
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    "VSHIFT-GOSSIP auto-retry cycle failed node={} error={}",
                    node_id,
                    error
                );
            }
        }
    }
}

async fn retry_pending_once(node_id: &str, config: &GossipConfig) -> Result<usize> {
    if !config.enabled {
        return Ok(0);
    }

    let local =
        DidRecord::load(&did_record_path()).context("load local DID for VSHIFT automatic retry")?;

    let mesh_circle_id = current_mesh_circle_id()?;
    let active_peers = active_gossip_peers(&local.did);

    let root = virtual_shift_root().join(VS15_GOSSIP);

    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(0);
        }
        Err(error) => return Err(error.into()),
    };

    let mut converged = 0usize;

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!("VSHIFT-GOSSIP retry directory read failed: {}", error);
                continue;
            }
        };

        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);

        if !is_dir {
            continue;
        }

        let outbox_path = entry.path().join("retry_outbox.json");

        if !outbox_path.is_file() {
            continue;
        }

        match retry_one_outbox(
            node_id,
            config,
            &local,
            &mesh_circle_id,
            &active_peers,
            &outbox_path,
        )
        .await
        {
            Ok(true) => {
                converged = converged.saturating_add(1);
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    "VSHIFT-GOSSIP retry outbox failed path={} error={}",
                    outbox_path.display(),
                    error
                );
            }
        }
    }

    Ok(converged)
}

async fn retry_one_outbox(
    node_id: &str,
    config: &GossipConfig,
    local: &DidRecord,
    mesh_circle_id: &str,
    active_peers: &[GossipPeer],
    outbox_path: &Path,
) -> Result<bool> {
    let mut outbox: VShiftRetryOutbox = serde_json::from_slice(&std::fs::read(outbox_path)?)
        .context("decode VSHIFT retry outbox")?;

    if outbox.schema_version != 1 {
        anyhow::bail!("unsupported VSHIFT retry outbox schema");
    }

    // Only the originating Guardian owns this durable retry record.
    if outbox.origin_node != node_id {
        return Ok(false);
    }

    if !outbox.discover_peers && outbox.pending_peers.is_empty() && outbox.status == "converged" {
        return Ok(false);
    }

    if outbox.mesh_circle_id != mesh_circle_id {
        anyhow::bail!(
            "VSHIFT retry Mesh Circle changed outbox={} local={}",
            outbox.mesh_circle_id,
            mesh_circle_id
        );
    }

    let alert =
        VShiftAlert::decode(&outbox.alert_pb).context("decode persisted VSHIFT retry alert")?;

    if alert.alert_id != outbox.alert_id {
        anyhow::bail!("VSHIFT retry outbox alert_id binding mismatch");
    }

    if alert.circle_id != outbox.policy_circle_id {
        anyhow::bail!("VSHIFT retry outbox policy Circle binding mismatch");
    }

    // If the original attempt happened before the peer directory was ready,
    // discover eligible peers now. This still uses active_gossip_peers().
    if outbox.discover_peers {
        if active_peers.is_empty() {
            outbox.attempts = outbox.attempts.saturating_add(1);
            outbox.last_attempt_at_ms = Some(now_ms()?);
            outbox.status = "pending_peer_discovery".into();
            write_json_atomic(outbox_path, &outbox)?;
            return Ok(false);
        }

        outbox.pending_peers = active_peers
            .iter()
            .map(|peer| VShiftRetryTarget {
                node_id: peer_label(peer),
                peer_did: peer.did.clone(),
            })
            .collect();

        outbox.discover_peers = false;
    }

    let targets = std::mem::take(&mut outbox.pending_peers);

    let mut still_pending = Vec::new();
    let mut recovered = Vec::new();

    for target in targets {
        let Some(peer) = active_peers.iter().find(|peer| peer.did == target.peer_did) else {
            still_pending.push(target);
            continue;
        };

        match send_to_peer(
            &outbox.origin_node,
            local,
            mesh_circle_id,
            config,
            peer,
            &alert,
        )
        .await
        {
            Ok(delivery) => {
                recovered.push(delivery);
            }

            Err(error) => {
                tracing::warn!(
                    "VSHIFT-GOSSIP auto-retry failed alert_id={} peer={} did={} error={}",
                    outbox.alert_id,
                    target.node_id,
                    target.peer_did,
                    error
                );

                still_pending.push(target);
            }
        }
    }

    outbox.pending_peers = still_pending;
    outbox.attempts = outbox.attempts.saturating_add(1);
    outbox.last_attempt_at_ms = Some(now_ms()?);

    outbox.status = if outbox.pending_peers.is_empty() {
        "converged".into()
    } else {
        "pending_retry".into()
    };

    write_json_atomic(outbox_path, &outbox)?;

    let receipt_dir = outbox_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("VSHIFT retry outbox has no parent directory"))?;

    update_receipt_after_auto_retry(receipt_dir, &outbox, &recovered)?;

    let event = serde_json::json!({
        "schema_version": 1,
        "alert_id": outbox.alert_id,
        "origin_node": outbox.origin_node,
        "transport": "existing_guardian_gossip",
        "gossip_port": config.port,
        "automatic": true,
        "attempt": outbox.attempts,
        "recovered_nodes": recovered
            .iter()
            .map(|delivery| delivery.node_id.clone())
            .collect::<Vec<_>>(),
        "pending_nodes": outbox
            .pending_peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<Vec<_>>(),
        "duplicate_suppressed": recovered
            .iter()
            .any(|delivery| delivery.duplicate_suppressed),
        "status": outbox.status,
        "at_ms": outbox.last_attempt_at_ms
    });

    append_json_line(&receipt_dir.join("retry_events.jsonl"), &event)?;

    println!(
        "VSHIFT-GOSSIP auto-retry alert_id={} delivered={} pending={} status={}",
        outbox.alert_id,
        recovered.len(),
        outbox.pending_peers.len(),
        outbox.status
    );

    Ok(outbox.pending_peers.is_empty())
}

fn update_receipt_after_auto_retry(
    receipt_dir: &Path,
    outbox: &VShiftRetryOutbox,
    recovered: &[VShiftNetworkDelivery],
) -> Result<()> {
    let receipt_path = receipt_dir.join("broadcast_receipt.json");

    if !receipt_path.is_file() {
        return Ok(());
    }

    let mut receipt: VShiftBroadcastReceipt =
        serde_json::from_slice(&std::fs::read(&receipt_path)?)
            .context("decode VSHIFT broadcast receipt during retry")?;

    for delivery in recovered {
        if let Some(existing) = receipt
            .delivered
            .iter_mut()
            .find(|existing| existing.peer_did == delivery.peer_did)
        {
            *existing = delivery.clone();
        } else {
            receipt.delivered.push(delivery.clone());
        }
    }

    receipt
        .delivered
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let mut pending_nodes = BTreeSet::new();

    for peer in &outbox.pending_peers {
        pending_nodes.insert(peer.node_id.clone());
    }

    receipt.pending_offline_nodes = pending_nodes.into_iter().collect();

    receipt.duplicate_suppressed |= recovered
        .iter()
        .any(|delivery| delivery.duplicate_suppressed);

    receipt.broadcast_completed_at_ms = now_ms()?;

    receipt.status = if outbox.discover_peers {
        "queued_no_active_gossip_peers".into()
    } else if outbox.pending_peers.is_empty() {
        "broadcast_network_not_applied".into()
    } else {
        "broadcast_partial_pending_retry".into()
    };

    append_json_line(&receipt_dir.join("broadcast_attempts.jsonl"), &receipt)?;

    write_json_atomic(&receipt_path, &receipt)
}

async fn send_to_peer(
    origin_node: &str,
    local: &DidRecord,
    mesh_circle_id: &str,
    config: &GossipConfig,
    peer: &GossipPeer,
    alert: &VShiftAlert,
) -> Result<VShiftNetworkDelivery> {
    let addr = format!("{}:{}", peer.overlay_ip, config.port);

    let stream = tokio::time::timeout(
        Duration::from_secs(protocol::IO_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .with_context(|| format!("timeout connecting VSHIFT peer {addr}"))?
    .with_context(|| format!("connect VSHIFT peer {addr}"))?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let message = VShiftGossipMessage {
        kind: KIND_VSHIFT_ALERT.into(),
        schema_version: 1,
        mesh_circle_id: mesh_circle_id.to_owned(),
        sender_did: local.did.clone(),
        sender_node: origin_node.to_owned(),
        origin_node: origin_node.to_owned(),
        alert_id: alert.alert_id.clone(),
        sent_at_ms: now_ms()?,
        alert_pb: alert.encode()?,
    };

    protocol::write_json_line(&mut write_half, &message)
        .await
        .context("write VSHIFT gossip message")?;

    let line = protocol::read_json_line(&mut reader)
        .await
        .context("read VSHIFT gossip acknowledgement")?;

    let ack: VShiftGossipAck =
        serde_json::from_str(line.trim()).context("decode VSHIFT gossip acknowledgement")?;

    if ack.kind != KIND_VSHIFT_ACK {
        anyhow::bail!("unexpected VSHIFT acknowledgement kind '{}'", ack.kind);
    }

    if ack.alert_id != alert.alert_id {
        anyhow::bail!("VSHIFT acknowledgement alert_id mismatch");
    }

    if let Some(error) = ack.error {
        anyhow::bail!("VSHIFT peer rejected alert: {error}");
    }

    Ok(VShiftNetworkDelivery {
        node_id: ack.receiver_node,
        peer_did: peer.did.clone(),
        relay_hops: 1,
        received_at_ms: ack.received_at_ms,
        delivery_time_ms: ack.received_at_ms.saturating_sub(alert.issued_at_ms),
        duplicate_suppressed: ack.duplicate_suppressed,
    })
}

pub async fn handle_inbound_line(
    line: &str,
    writer: &mut OwnedWriteHalf,
    node_id: &str,
    _config: &GossipConfig,
) -> Result<(), String> {
    let message: VShiftGossipMessage = serde_json::from_str(line.trim())
        .map_err(|error| format!("bad VSHIFT gossip message: {error}"))?;

    let processed = process_inbound(&message, node_id);

    match processed {
        Ok((alert, duplicate_suppressed, received_at_ms, verification_status)) => {
            let ack = VShiftGossipAck {
                kind: KIND_VSHIFT_ACK.into(),
                schema_version: 1,
                alert_id: alert.alert_id.clone(),
                receiver_node: node_id.to_owned(),
                received_at_ms,
                duplicate_suppressed,
                error: None,
            };

            protocol::write_json_line(writer, &ack)
                .await
                .map_err(|error| error.to_string())?;

            if duplicate_suppressed {
                println!(
                    "VSHIFT-GOSSIP duplicate_suppressed alert_id={} node={} transport=existing_guardian_gossip",
                    alert.alert_id,
                    node_id
                );
            } else {
                println!(
                    "VSHIFT-GOSSIP received alert_id={} node={} transport=existing_guardian_gossip port=50063 status={}",
                    alert.alert_id,
                    node_id,
                    verification_status
                );
            }

            Ok(())
        }

        Err(reason) => {
            tracing::warn!(
                "VSHIFT-GOSSIP rejected alert_id={} node={} reason={}",
                message.alert_id,
                node_id,
                reason
            );

            let ack = VShiftGossipAck {
                kind: KIND_VSHIFT_ACK.into(),
                schema_version: 1,
                alert_id: message.alert_id.clone(),
                receiver_node: node_id.to_owned(),
                received_at_ms: now_ms().unwrap_or_default(),
                duplicate_suppressed: false,
                error: Some(reason.clone()),
            };

            let _ = protocol::write_json_line(writer, &ack).await;

            Err(reason)
        }
    }
}

fn process_inbound(
    message: &VShiftGossipMessage,
    node_id: &str,
) -> Result<(VShiftAlert, bool, u64, String), String> {
    if message.kind != KIND_VSHIFT_ALERT || message.schema_version != 1 {
        return Err("unsupported VSHIFT gossip message".into());
    }

    if message.alert_id.trim().is_empty()
        || message.sender_did.trim().is_empty()
        || message.sender_node.trim().is_empty()
        || message.origin_node.trim().is_empty()
    {
        return Err("VSHIFT gossip message contains empty identity fields".into());
    }

    let local =
        DidRecord::load(&did_record_path()).map_err(|error| format!("load local DID: {error}"))?;

    let mesh_circle_id =
        current_mesh_circle_id().map_err(|error| format!("resolve Mesh Circle: {error}"))?;

    if message.mesh_circle_id != mesh_circle_id {
        return Err(format!(
            "VSHIFT gossip Mesh Circle mismatch local={} sender={}",
            mesh_circle_id, message.mesh_circle_id
        ));
    }

    if message.sender_did == local.did {
        return Err("VSHIFT gossip sender DID equals local DID".into());
    }

    if crate::crl::is_revoked(&message.sender_did) {
        return Err(format!(
            "VSHIFT gossip sender is revoked: {}",
            message.sender_did
        ));
    }

    let peers = active_gossip_peers(&local.did);

    let sender = peers
        .iter()
        .find(|peer| peer.did == message.sender_did)
        .ok_or_else(|| {
            format!(
                "VSHIFT gossip sender not in local active peer directory: {}",
                message.sender_did
            )
        })?;

    if !sender.node_name.is_empty() && sender.node_name != message.sender_node {
        return Err(format!(
            "VSHIFT gossip sender node mismatch directory={} announced={}",
            sender.node_name, message.sender_node
        ));
    }

    let alert = VShiftAlert::decode(&message.alert_pb)
        .map_err(|error| format!("invalid VSHIFT_ALERT wire payload: {error}"))?;

    if alert.alert_id != message.alert_id {
        return Err("VSHIFT gossip envelope alert_id does not match payload".into());
    }

    let received_at_ms = now_ms().map_err(|error| format!("receive timestamp failed: {error}"))?;

    // VS16: transport acceptance is not policy authorization. Every receiving
    // member independently verifies Circle scope, configured Guardian trust
    // anchor, Ed25519 signature, policy hash/version, freshness and replay
    // state before VS17 is allowed to see this alert.
    let verification_status = verify_member_alert(node_id, &alert, received_at_ms)?;

    let first_delivery =
        claim_alert(node_id, &alert).map_err(|error| format!("dedupe state failed: {error}"))?;

    if first_delivery {
        if let Err(error) = persist_first_receive(
            node_id,
            message,
            &alert,
            received_at_ms,
            &verification_status,
        ) {
            release_alert_claim(node_id, &alert.alert_id);
            return Err(format!("persist VSHIFT receive evidence failed: {error}"));
        }
    }

    // VS17 policy apply -> VS18 identity rotation -> forced re-attestation.
    if first_delivery && verification_status == "verified_not_applied" {
        let _ = apply_verified_member_alert(node_id, &alert, received_at_ms)?;
        let rotation = rotate_member_identity_after_apply(node_id, &alert, received_at_ms)?;

        if rotation.status == IdentityRotationStatus::RotatedReAttestationRequired {
            let _ = complete_member_reattestation(node_id, &alert, received_at_ms)?;
        }
    }

    append_receive_event(node_id, message, &alert, received_at_ms, !first_delivery)
        .map_err(|error| format!("persist VSHIFT receive event failed: {error}"))?;

    Ok((alert, !first_delivery, received_at_ms, verification_status))
}

pub fn verify_and_apply_local_vshift_alert(
    node_id: &str,
    alert: &VShiftAlert,
) -> Result<serde_json::Value, String> {
    let processed_at_ms =
        now_ms().map_err(|error| format!("local VSHIFT timestamp failed: {error}"))?;

    let verification_status = verify_member_alert(node_id, alert, processed_at_ms)?;

    let (policy_apply, identity_rotation, re_attestation) = if verification_status
        == "verified_not_applied"
    {
        let policy_apply = apply_verified_member_alert(node_id, alert, processed_at_ms)?;
        let identity_rotation =
            rotate_member_identity_after_apply(node_id, alert, processed_at_ms)?;

        let re_attestation =
            if identity_rotation.status == IdentityRotationStatus::RotatedReAttestationRequired {
                Some(complete_member_reattestation(
                    node_id,
                    alert,
                    processed_at_ms,
                )?)
            } else {
                None
            };

        (Some(policy_apply), Some(identity_rotation), re_attestation)
    } else {
        (None, None, None)
    };

    let replay_apply_suppressed = policy_apply.is_none();

    Ok(serde_json::json!({
        "schema_version": 1,
        "member_id": node_id,
        "alert_id": &alert.alert_id,
        "verification_status": verification_status,
        "policy_apply": policy_apply,
        "identity_rotation": identity_rotation,
        "re_attestation": re_attestation,
        "replay_apply_suppressed": replay_apply_suppressed
    }))
}

fn apply_verified_member_alert(
    node_id: &str,
    alert: &VShiftAlert,
    applied_at_ms: u64,
) -> Result<MemberPolicyApplyResult, String> {
    let root = virtual_shift_root();

    let applier = MemberPolicyApplier::new(
        root.join("config").join("active_virtual_shift_policy.json"),
        root.join(VS16_MEMBER_VERIFICATION),
        root.join(VS17_MEMBER_POLICY_STATE),
    );

    applier
        .apply_verified_alert(node_id, alert, applied_at_ms)
        .map_err(|error| format!("VS17 member policy apply failed: {error}"))
}

fn rotate_member_identity_after_apply(
    node_id: &str,
    alert: &VShiftAlert,
    rotated_at_ms: u64,
) -> Result<IdentityRotationResult, String> {
    let root = virtual_shift_root();

    let rotator = MemberIdentityRotator::new(
        root.join(VS17_MEMBER_POLICY_STATE),
        root.join(VS18_MEMBER_IDENTITY_STATE),
    );

    rotator
        .rotate_after_applied_policy(node_id, alert, rotated_at_ms)
        .map_err(|error| format!("VS18 member identity rotation failed: {error}"))
}

#[derive(Debug, Clone)]
struct GuardianLocalAttestationConnector {
    node_id: String,
}

impl AttestationConnector for GuardianLocalAttestationConnector {
    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<AttestationConnectorResponse> {
        if request.member_id != self.node_id {
            return Ok(AttestationConnectorResponse {
                accepted: false,
                reason: format!(
                    "Task2 attestation member mismatch: request={} local={}",
                    request.member_id, self.node_id
                ),
            });
        }

        let key_path = format!(
            "/var/lib/sgx-guardian/sgx-agent/device_{}.key",
            self.node_id
        );
        let km = crate::key_manager::KeyManager::load_or_generate(&key_path)?;

        // Bind the exact Task2 rotated identity and policy lifecycle into the
        // material whose SHA-256 digest is signed by real Guardian attestation.
        let binding = format!(
            "SGX-TASK2-VS18-REATTEST-v1\nmember_id={}\nvirtual_id={}\nalert_id={}\npolicy_version={}\n",
            request.member_id,
            request.virtual_id,
            request.alert_id,
            request.policy_version
        );

        let evidence =
            crate::attestation_service::AttestationService::create_signed_evidence(&km, &binding)?;

        let verified = crate::attestation_service::AttestationService::verify_signed_evidence(
            &evidence, &binding,
        )?;

        let identity_matches = evidence.node_id == request.member_id;
        let accepted = verified && identity_matches;

        Ok(AttestationConnectorResponse {
            accepted,
            reason: if accepted {
                format!(
                    "Guardian attestation verified fresh signed DKP/PCR evidence bound to Task2 VirtualID {} for alert {} policy v{}.",
                    request.virtual_id,
                    request.alert_id,
                    request.policy_version
                )
            } else {
                format!(
                    "Guardian attestation rejected Task2 binding: cryptographic_verified={} evidence_node={} requested_member={}.",
                    verified,
                    evidence.node_id,
                    request.member_id
                )
            },
        })
    }
}

fn complete_member_reattestation(
    node_id: &str,
    alert: &VShiftAlert,
    completed_at_ms: u64,
) -> Result<ReAttestationResult, String> {
    let root = virtual_shift_root();

    let service = ReAttestationService::new(root.join(VS18_MEMBER_IDENTITY_STATE));
    let connector = GuardianLocalAttestationConnector {
        node_id: node_id.to_string(),
    };

    service
        .complete_after_rotation(
            node_id,
            alert,
            "guardian-local-cryptographic-attestation",
            &connector,
            completed_at_ms,
        )
        .map_err(|error| format!("VS18 forced re-attestation failed: {error}"))
}

fn verify_member_alert(
    node_id: &str,
    alert: &VShiftAlert,
    received_at_ms: u64,
) -> Result<String, String> {
    let root = virtual_shift_root();
    let authorization_path = root
        .join("config")
        .join("circle_guardian_authorization.json");

    if !authorization_path.is_file() {
        return Err(format!(
            "VS16 authorization config missing: {}",
            authorization_path.display()
        ));
    }

    let verifier = MemberAlertVerifier::from_config(
        &authorization_path,
        root.join("08_MEMBER_POLICY_VERIFICATION"),
    )
    .map_err(|error| format!("VS16 verifier initialization failed: {error}"))?;

    let verification = verifier
        .verify_and_record(node_id, alert, received_at_ms)
        .map_err(|error| format!("VS16 member verification failed: {error}"))?;

    match &verification.status {
        VerificationStatus::VerifiedNotApplied => Ok("verified_not_applied".into()),
        VerificationStatus::AlreadyVerified => Ok("already_verified".into()),
        VerificationStatus::Rejected => Err(format!(
            "VS16 member verification rejected: {}",
            verification.reason
        )),
    }
}

fn current_mesh_circle_id() -> Result<String> {
    crate::crl::issue::current_circle_id()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .or_else(|_| Ok(crate::crl::issue::DEFAULT_CIRCLE_ID.to_owned()))
}

fn virtual_shift_root() -> PathBuf {
    std::env::var("SGX_THREAT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/threat"))
        .join("virtual_shift")
}

fn claim_alert(node_id: &str, alert: &VShiftAlert) -> Result<bool> {
    safe_component(node_id)?;
    safe_component(&alert.alert_id)?;

    let dir = virtual_shift_root().join(VS15_GOSSIP).join(&alert.alert_id);

    std::fs::create_dir_all(&dir)?;

    let marker = dir.join(format!("seen-{node_id}.marker"));

    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker)
    {
        Ok(mut file) => {
            writeln!(file, "{}", now_ms()?)?;
            file.sync_all()?;
            Ok(true)
        }

        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),

        Err(error) => Err(error.into()),
    }
}

fn release_alert_claim(node_id: &str, alert_id: &str) {
    let marker = virtual_shift_root()
        .join(VS15_GOSSIP)
        .join(alert_id)
        .join(format!("seen-{node_id}.marker"));

    let _ = std::fs::remove_file(marker);
}

fn persist_first_receive(
    node_id: &str,
    message: &VShiftGossipMessage,
    alert: &VShiftAlert,
    received_at_ms: u64,
    verification_status: &str,
) -> Result<()> {
    let dir = virtual_shift_root().join(VS15_GOSSIP).join(&alert.alert_id);

    std::fs::create_dir_all(&dir)?;

    write_atomic(&dir.join("received_vshift_alert.pb"), &message.alert_pb)?;

    let receipt = serde_json::json!({
        "schema_version": 1,
        "message_type": "VSHIFT_ALERT",
        "transport": "existing_guardian_gossip",
        "gossip_port": GossipConfig::from_env().port,
        "member_id": node_id,
        "alert_id": alert.alert_id,
        "origin_node": message.origin_node,
        "sender_node": message.sender_node,
        "sender_did": message.sender_did,
        "mesh_circle_id": message.mesh_circle_id,
        "policy_circle_id": alert.circle_id,
        "received_at_ms": received_at_ms,
        "duplicate_suppressed": false,
        "status": verification_status,
        "next_stage": "VS17 policy apply/rollback; not triggered by VS16 verification"
    });

    write_json_atomic(&dir.join("receive_receipt.json"), &receipt)
}

fn append_receive_event(
    node_id: &str,
    message: &VShiftGossipMessage,
    alert: &VShiftAlert,
    received_at_ms: u64,
    duplicate: bool,
) -> Result<()> {
    let dir = virtual_shift_root().join(VS15_GOSSIP).join(&alert.alert_id);

    std::fs::create_dir_all(&dir)?;

    let event = serde_json::json!({
        "schema_version": 1,
        "member_id": node_id,
        "alert_id": alert.alert_id,
        "sender_node": message.sender_node,
        "sender_did": message.sender_did,
        "mesh_circle_id": message.mesh_circle_id,
        "policy_circle_id": alert.circle_id,
        "received_at_ms": received_at_ms,
        "duplicate_suppressed": duplicate
    });

    let mut line = serde_json::to_vec(&event)?;
    line.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("receive_events.jsonl"))?;

    file.write_all(&line)?;
    file.sync_data()?;

    Ok(())
}

fn peer_label(peer: &GossipPeer) -> String {
    if peer.node_name.trim().is_empty() {
        peer.did.clone()
    } else {
        peer.node_name.clone()
    }
}

fn safe_component(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        anyhow::bail!("unsafe VSHIFT path component");
    }

    Ok(())
}

fn append_json_line(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    file.write_all(&line)?;
    file.sync_data()?;

    Ok(())
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(value)?)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), now_ms()?));

    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;

    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
