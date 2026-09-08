//! CA Broker Worker — runs on Node A (Home CA) only.
//!
//! Maintains a persistent outbound WebSocket connection to the VPS broker.
//! Receives forwarded enrollment requests from remote nodes, signs
//! certificates using the existing NebulaCA, and sends responses back.
//!
//! This module does NOT handle PIN validation (removed per design decision).
//! All enrollment requests forwarded by the broker are processed.

use crate::logging::log_event;
use crate::nebula::ca::NebulaCA;
use crate::nebula::models::CircleMembership;
use crate::nebula::overlay_registry::OverlayRegistry;
use crate::nebula::registry_sync::REGISTRY_PATH;
use base64::{engine::general_purpose, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const NEBULA_BASE_DIR: &str = "/var/lib/sgx-guardian/nebula";
const RECONNECT_INTERVAL_SECS: u64 = 5;
const PA_PUB_PATH: &str = "/etc/sgx-guardian/policies/pa_admin_pub.der";
const SIGNED_POLICY_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";

// ────────────────────────────────────────────────────────────────────
// Message types (mirrors sgx-broker/src/models.rs)
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrollmentRequest {
    circle_id: String,
    node_id: String,
    public_key_pem: String,
    #[serde(default)]
    did_doc_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrollmentResponse {
    status: String,
    overlay_ip: String,
    cert: String,
    #[serde(default)]
    key: String,
    ca_cert: String,
    config: String,
    #[serde(default)]
    member_vc_json: String,
    #[serde(default)]
    status_list_json: String,
    #[serde(default)]
    did_doc_aggregate_json: String,
    #[serde(default)]
    signing_pubkey_der_b64: String,
    #[serde(default)]
    signed_policy_b64: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsEnvelope {
    event: String,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<EnrollmentRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<EnrollmentResponse>,
}

#[derive(Default)]
struct EnrollmentTrustMaterial {
    member_vc_json: String,
    status_list_json: String,
    did_doc_aggregate_json: String,
    signing_pubkey_der_b64: String,
    signed_policy_b64: String,
}

fn validate_enrollment_did(
    request: &EnrollmentRequest,
) -> Result<crate::did::document::DidDocument, String> {
    if request.did_doc_json.trim().is_empty() {
        return Err("signed DID document is missing from enrollment request".into());
    }
    let doc: crate::did::document::DidDocument = serde_json::from_str(&request.did_doc_json)
        .map_err(|error| format!("invalid DID document JSON: {}", error))?;
    if doc.sgx_node_name.as_deref() != Some(request.node_id.as_str()) {
        return Err(format!(
            "DID node name mismatch: request={} document={}",
            request.node_id,
            doc.sgx_node_name.as_deref().unwrap_or("<missing>")
        ));
    }
    if doc.controller != doc.id {
        return Err("DID document controller does not match its id".into());
    }
    if doc.sgx_status.as_deref() != Some("active") {
        return Err("DID document is not active".into());
    }
    crate::did::Did::parse(&doc.id).map_err(|error| format!("invalid DID: {}", error))?;
    crate::did::doc_sign::verify(&doc)
        .map_err(|error| format!("DID document signature invalid: {}", error))?;

    // The key already displayed in the approval YAML must be the same key
    // that signed the DID document. This binds the administrator's approval
    // to the identity that will receive the membership VC.
    let supplied_key = general_purpose::STANDARD
        .decode(request.public_key_pem.trim())
        .map_err(|error| format!("enrollment public key is not Base64 DER: {}", error))?;
    let raw_key = if supplied_key.len() == 65 && supplied_key.first() == Some(&0x04) {
        supplied_key
    } else if supplied_key.len() >= 65 && supplied_key.get(supplied_key.len() - 65) == Some(&0x04) {
        supplied_key[supplied_key.len() - 65..].to_vec()
    } else {
        return Err(format!(
            "unsupported enrollment P-256 public key length {}",
            supplied_key.len()
        ));
    };
    let vm = doc
        .verification_method
        .first()
        .ok_or_else(|| "DID document has no verification method".to_string())?;
    let expected_x = general_purpose::URL_SAFE_NO_PAD.encode(&raw_key[1..33]);
    let expected_y = general_purpose::URL_SAFE_NO_PAD.encode(&raw_key[33..65]);
    if vm.public_key_jwk.x != expected_x || vm.public_key_jwk.y != expected_y {
        return Err("enrollment public key does not match DID document key".into());
    }
    Ok(doc)
}

async fn ingest_enrollment_did(request: &EnrollmentRequest) -> Result<String, String> {
    let doc = validate_enrollment_did(request)?;
    crate::did::doc_distribution::ca_ingest_published(&request.did_doc_json)
        .await
        .map_err(|error| format!("DID document ingest failed: {}", error))?;
    Ok(doc.id)
}

fn issue_member_vc_for_subject(
    node_id: &str,
    subject_did: &str,
) -> Result<crate::vc::credential::VerifiableCredential, String> {
    let issuer = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
        .map_err(|error| format!("CA DID load failed: {}", error))?;
    let km = crate::vc::issue::load_runtime_key_manager("nodeA")
        .map_err(|error| format!("VC key manager failed: {}", error))?;
    crate::vc::issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        crate::vc::issue::IssueRequest {
            subject_did,
            role: crate::vc::credential::CredentialRole::Member,
            permissions: crate::vc::issue::default_permissions_for_role(
                crate::vc::credential::CredentialRole::Member,
            ),
            circle_id: crate::vc::issue::DEFAULT_CIRCLE_ID,
            node_hint: Some(node_id.to_string()),
            duration_days: None,
        },
    )
    .map(crate::vc::issue::IssueMembershipOutcome::into_vc)
    .map_err(|error| format!("membership VC issue failed: {}", error))
}

async fn build_trust_material(
    request: &EnrollmentRequest,
    subject_did: &str,
) -> Result<EnrollmentTrustMaterial, String> {
    let vc = issue_member_vc_for_subject(&request.node_id, subject_did)?;
    let status_list_json = std::fs::read_to_string(crate::vc::persistence::status_list_path())
        .map_err(|error| format!("status-list read failed: {}", error))?;
    let did_doc_aggregate_json = crate::did::doc_distribution::ca_export_aggregate()
        .await
        .map_err(|error| format!("DID aggregate export failed: {}", error))?;
    Ok(EnrollmentTrustMaterial {
        member_vc_json: serde_json::to_string(&vc)
            .map_err(|error| format!("membership VC serialization failed: {}", error))?,
        status_list_json,
        did_doc_aggregate_json,
        signing_pubkey_der_b64: std::fs::read(PA_PUB_PATH)
            .ok()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| general_purpose::STANDARD.encode(bytes))
            .unwrap_or_default(),
        signed_policy_b64: std::fs::read(SIGNED_POLICY_PATH)
            .ok()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| general_purpose::STANDARD.encode(bytes))
            .unwrap_or_default(),
    })
}

// ────────────────────────────────────────────────────────────────────
// Public entry point
// ────────────────────────────────────────────────────────────────────

/// Start the CA broker worker. This function never returns — it
/// reconnects automatically on disconnect with a 5-second backoff.
///
/// Called from main.rs on Node A only when `SGX_BROKER_URL` is set.
pub async fn start_ca_broker_worker(vps_url: String, circle_id: String, auth_token: String) {
    println!("☁️  CA broker worker starting (VPS: {})", vps_url);
    log_event(
        "nodeA",
        &format!("CA broker worker connecting to {}", vps_url),
    );

    loop {
        match connect_and_serve(&vps_url, &circle_id, &auth_token).await {
            Ok(_) => {
                println!(
                    "☁️  CA broker session ended cleanly, reconnecting in {}s...",
                    RECONNECT_INTERVAL_SECS
                );
            }
            Err(e) => {
                eprintln!(
                    "⚠️  CA broker connection failed: {} — retrying in {}s...",
                    e, RECONNECT_INTERVAL_SECS
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
    }
}

/// Single connection attempt: connect, serve requests, return on disconnect.
async fn connect_and_serve(vps_url: &str, circle_id: &str, auth_token: &str) -> Result<(), String> {
    // Build the WebSocket URL
    let ws_base = vps_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws_url = format!(
        "{}/ws/ca-bridge?circle_id={}&node_id=nodeA",
        ws_base.trim_end_matches('/'),
        circle_id
    );
    if !auth_token.is_empty() {
        ws_url.push_str(&format!("&token={}", auth_token));
    }

    println!("🔌 Connecting to broker: {}", ws_url);

    let (ws_stream, _response) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    println!("✅ CA broker WebSocket connected");
    log_event("nodeA", "CA broker WebSocket connected to VPS");

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // Process inbound messages from the broker (forwarded enrollment requests)
    while let Some(msg_result) = ws_stream_rx.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                let envelope: WsEnvelope = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("⚠️  Failed to parse broker message: {}", e);
                        continue;
                    }
                };

                if envelope.event != "ENROLLMENT_REQUEST" {
                    continue;
                }

                let request = match envelope.payload {
                    Some(req) => req,
                    None => {
                        eprintln!("⚠️  ENROLLMENT_REQUEST missing payload");
                        continue;
                    }
                };

                println!(
                    "📥 [Broker] Enrollment request: node={} circle={}",
                    request.node_id, request.circle_id
                );

                // Process the enrollment (sign cert)
                let response = process_enrollment(&request).await;

                // Send response back to broker
                let response_envelope = WsEnvelope {
                    event: "ENROLLMENT_RESPONSE".to_string(),
                    request_id: envelope.request_id.clone(),
                    payload: None,
                    response: Some(response),
                };

                let json = match serde_json::to_string(&response_envelope) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("⚠️  Failed to serialize response: {}", e);
                        continue;
                    }
                };

                if let Err(e) = ws_sink.send(Message::Text(json.into())).await {
                    eprintln!("❌ Failed to send response to broker: {}", e);
                    return Err(format!("WS send failed: {}", e));
                }

                println!(
                    "✅ [Broker] Signed cert sent back for node={}",
                    request.node_id
                );
            }
            Ok(Message::Ping(data)) => {
                let _ = ws_sink.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                println!("🔌 Broker closed the WebSocket connection");
                return Ok(());
            }
            Err(e) => {
                return Err(format!("WS read error: {}", e));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Process an enrollment request with manual admin review (matching LAN workflow).
///
/// Workflow:
/// 1. Idempotency: If cert + key already exist on disk, return APPROVED immediately.
/// 2. If requests/<node_id>.yaml does NOT exist:
///    - Allocate/retrieve overlay IP.
///    - Write `/var/lib/sgx-guardian/nebula/requests/<node_id>.yaml` with `approve: false`.
///    - Print admin approval banner to console.
///    - Return `status: "PENDING"`.
/// 3. If requests/<node_id>.yaml exists:
///    - Check `approve` decision.
///    - If still `false`: return `status: "PENDING"`.
///    - If `member` / `lighthouse` / `relay` / `lh_relay`:
///      - Sign certificate via NebulaCA.
///      - Read cert, key, CA cert.
///      - Generate remote nebula.yaml config.
///      - Delete the request YAML.
///      - Return `status: "APPROVED"`.
async fn process_enrollment(request: &EnrollmentRequest) -> EnrollmentResponse {
    if request.node_id.is_empty()
        || !request
            .node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return EnrollmentResponse {
            status: "REJECTED".to_string(),
            overlay_ip: String::new(),
            cert: String::new(),
            key: String::new(),
            ca_cert: String::new(),
            config: String::new(),
            member_vc_json: String::new(),
            status_list_json: String::new(),
            did_doc_aggregate_json: String::new(),
            signing_pubkey_der_b64: String::new(),
            signed_policy_b64: String::new(),
            message: "invalid node_id".to_string(),
        };
    }
    let requests_dir = format!("{}/requests", NEBULA_BASE_DIR);
    let _ = std::fs::create_dir_all(&requests_dir);

    let cert_path = format!("{}/nodes/{}.crt", NEBULA_BASE_DIR, request.node_id);
    let key_path = format!("{}/nodes/{}.key", NEBULA_BASE_DIR, request.node_id);
    let ca_path = format!("{}/ca/ca.crt", NEBULA_BASE_DIR);
    let yaml_path = format!("{}/{}.yaml", requests_dir, request.node_id);
    if request.circle_id != crate::vc::issue::DEFAULT_CIRCLE_ID {
        return EnrollmentResponse {
            status: "REJECTED".to_string(),
            overlay_ip: String::new(),
            cert: String::new(),
            key: String::new(),
            ca_cert: String::new(),
            config: String::new(),
            member_vc_json: String::new(),
            status_list_json: String::new(),
            did_doc_aggregate_json: String::new(),
            signing_pubkey_der_b64: String::new(),
            signed_policy_b64: String::new(),
            message: format!("unsupported circle_id {}", request.circle_id),
        };
    }
    let subject_did = match validate_enrollment_did(request) {
        Ok(doc) => doc.id,
        Err(message) => {
            return EnrollmentResponse {
                status: "REJECTED".to_string(),
                overlay_ip: String::new(),
                cert: String::new(),
                key: String::new(),
                ca_cert: String::new(),
                config: String::new(),
                member_vc_json: String::new(),
                status_list_json: String::new(),
                did_doc_aggregate_json: String::new(),
                signing_pubkey_der_b64: String::new(),
                signed_policy_b64: String::new(),
                message,
            };
        }
    };

    // ── 1. Fast-path: Already approved and issued on disk ────────────────
    if std::path::Path::new(&cert_path).exists()
        && std::path::Path::new(&key_path).exists()
        && std::path::Path::new(&ca_path).exists()
    {
        if let (Ok(cert), Ok(key), Ok(ca_cert)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
            std::fs::read_to_string(&ca_path),
        ) {
            if let Err(message) = ingest_enrollment_did(request).await {
                return EnrollmentResponse {
                    status: "REJECTED".to_string(),
                    overlay_ip: String::new(),
                    cert: String::new(),
                    key: String::new(),
                    ca_cert: String::new(),
                    config: String::new(),
                    member_vc_json: String::new(),
                    status_list_json: String::new(),
                    did_doc_aggregate_json: String::new(),
                    signing_pubkey_der_b64: String::new(),
                    signed_policy_b64: String::new(),
                    message,
                };
            }
            let trust = match build_trust_material(request, &subject_did).await {
                Ok(trust) => trust,
                Err(message) => {
                    return EnrollmentResponse {
                        status: "ERROR".to_string(),
                        overlay_ip: String::new(),
                        cert: String::new(),
                        key: String::new(),
                        ca_cert: String::new(),
                        config: String::new(),
                        member_vc_json: String::new(),
                        status_list_json: String::new(),
                        did_doc_aggregate_json: String::new(),
                        signing_pubkey_der_b64: String::new(),
                        signed_policy_b64: String::new(),
                        message,
                    };
                }
            };
            let reg = OverlayRegistry::load_or_create(
                REGISTRY_PATH,
                "guardian-circle-alpha",
                "192.168.100",
                "nodeA",
            );
            let overlay_ip = reg
                .get_ip_cidr(&request.node_id)
                .unwrap_or("192.168.100.2/24")
                .to_string();
            let config = generate_remote_node_config(&request.node_id, &overlay_ip);

            return EnrollmentResponse {
                status: "APPROVED".to_string(),
                overlay_ip,
                cert,
                key,
                ca_cert,
                config,
                member_vc_json: trust.member_vc_json,
                status_list_json: trust.status_list_json,
                did_doc_aggregate_json: trust.did_doc_aggregate_json,
                signing_pubkey_der_b64: trust.signing_pubkey_der_b64,
                signed_policy_b64: trust.signed_policy_b64,
                message: format!("Certificate already active for {}", request.node_id),
            };
        }
    }

    // ── 2. Allocate or retrieve assigned overlay IP ──────────────────────
    let mut reg = OverlayRegistry::load_or_create(
        REGISTRY_PATH,
        "guardian-circle-alpha",
        "192.168.100",
        "nodeA",
    );

    let overlay_ip = match reg.get_ip_cidr(&request.node_id) {
        Some(existing) => existing.to_string(),
        None => match reg.assign_ip(&request.node_id) {
            Ok(ip) => {
                let _ = reg.save(REGISTRY_PATH);
                ip
            }
            Err(e) => {
                return EnrollmentResponse {
                    status: "REJECTED".to_string(),
                    overlay_ip: String::new(),
                    cert: String::new(),
                    key: String::new(),
                    ca_cert: String::new(),
                    config: String::new(),
                    member_vc_json: String::new(),
                    status_list_json: String::new(),
                    did_doc_aggregate_json: String::new(),
                    signing_pubkey_der_b64: String::new(),
                    signed_policy_b64: String::new(),
                    message: format!("IP allocation failed: {}", e),
                };
            }
        },
    };

    // ── 3. Check if approval file exists; create it if missing ──────────
    if !std::path::Path::new(&yaml_path).exists() {
        let fingerprint = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(request.public_key_pem.as_bytes());
            hex::encode(&hash[..8])
        };

        let yaml_data = crate::cert_service::CertRequestYaml {
            node_id: request.node_id.clone(),
            requested_at: chrono::Utc::now().to_rfc3339(),
            overlay_ip: overlay_ip.clone(),
            public_key_fingerprint: fingerprint,
            requested_role: "member".to_string(),
            approve: crate::cert_service::ApprovalDecision::False,
        };

        if let Ok(yaml_string) = serde_yaml::to_string(&yaml_data) {
            let _ = std::fs::write(&yaml_path, &yaml_string);
        }

        println!();
        println!(
            "📥 [Broker] Remote enrollment request from: {}",
            request.node_id
        );
        println!("Approval file created: {}", yaml_path);
        println!();
        println!("Edit the file and set 'approve' to ONE of:");
        println!("  approve: false        (reject or keep pending)");
        println!("  approve: member       (accept as standard member)");
        println!("  approve: lighthouse   (accept as lighthouse only)");
        println!("  approve: relay        (accept as relay only)");
        println!("  approve: lh_relay     (accept as lighthouse + relay)");
        println!();
        println!("Save the file to trigger approval.");

        log_event(
            "nodeA",
            &format!(
                "Broker enrollment request created for {} — awaiting admin approval",
                request.node_id
            ),
        );

        return EnrollmentResponse {
            status: "PENDING".to_string(),
            overlay_ip: overlay_ip.clone(),
            cert: String::new(),
            key: String::new(),
            ca_cert: String::new(),
            config: String::new(),
            member_vc_json: String::new(),
            status_list_json: String::new(),
            did_doc_aggregate_json: String::new(),
            signing_pubkey_der_b64: String::new(),
            signed_policy_b64: String::new(),
            message: format!(
                "Enrollment request pending administrator approval on Node A (file: {})",
                yaml_path
            ),
        };
    }

    // ── 4. Approval file exists: check decision ─────────────────────────
    let yaml_content = match std::fs::read_to_string(&yaml_path) {
        Ok(c) => c,
        Err(e) => {
            return EnrollmentResponse {
                status: "PENDING".to_string(),
                overlay_ip: overlay_ip.clone(),
                cert: String::new(),
                key: String::new(),
                ca_cert: String::new(),
                config: String::new(),
                member_vc_json: String::new(),
                status_list_json: String::new(),
                did_doc_aggregate_json: String::new(),
                signing_pubkey_der_b64: String::new(),
                signed_policy_b64: String::new(),
                message: format!("Reading approval YAML failed: {}", e),
            };
        }
    };

    let parsed_yaml: crate::cert_service::CertRequestYaml =
        match serde_yaml::from_str(&yaml_content) {
            Ok(p) => p,
            Err(e) => {
                return EnrollmentResponse {
                    status: "PENDING".to_string(),
                    overlay_ip: overlay_ip.clone(),
                    cert: String::new(),
                    key: String::new(),
                    ca_cert: String::new(),
                    config: String::new(),
                    member_vc_json: String::new(),
                    status_list_json: String::new(),
                    did_doc_aggregate_json: String::new(),
                    signing_pubkey_der_b64: String::new(),
                    signed_policy_b64: String::new(),
                    message: format!("Parsing approval YAML failed: {}", e),
                };
            }
        };

    let current_fingerprint = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(request.public_key_pem.as_bytes());
        hex::encode(&hash[..8])
    };
    if parsed_yaml.public_key_fingerprint != current_fingerprint {
        return EnrollmentResponse {
            status: "REJECTED".to_string(),
            overlay_ip: String::new(),
            cert: String::new(),
            key: String::new(),
            ca_cert: String::new(),
            config: String::new(),
            member_vc_json: String::new(),
            status_list_json: String::new(),
            did_doc_aggregate_json: String::new(),
            signing_pubkey_der_b64: String::new(),
            signed_policy_b64: String::new(),
            message: "enrollment identity key changed after administrator review began".to_string(),
        };
    }

    match parsed_yaml.approve {
        crate::cert_service::ApprovalDecision::False => {
            // Still pending approval
            EnrollmentResponse {
                status: "PENDING".to_string(),
                overlay_ip: overlay_ip.clone(),
                cert: String::new(),
                key: String::new(),
                ca_cert: String::new(),
                config: String::new(),
                member_vc_json: String::new(),
                status_list_json: String::new(),
                did_doc_aggregate_json: String::new(),
                signing_pubkey_der_b64: String::new(),
                signed_policy_b64: String::new(),
                message: format!(
                    "Enrollment request for {} is pending administrator review in {}",
                    request.node_id, yaml_path
                ),
            }
        }
        crate::cert_service::ApprovalDecision::Member
        | crate::cert_service::ApprovalDecision::Lighthouse
        | crate::cert_service::ApprovalDecision::Relay
        | crate::cert_service::ApprovalDecision::LhRelay => {
            // ── Approved! Issue certificate ─────────────────────────────
            println!(
                "✅ [Broker] Certificate approval detected for node={} (role: {:?})",
                request.node_id, parsed_yaml.approve
            );

            if let Err(message) = ingest_enrollment_did(request).await {
                return EnrollmentResponse {
                    status: "REJECTED".to_string(),
                    overlay_ip: String::new(),
                    cert: String::new(),
                    key: String::new(),
                    ca_cert: String::new(),
                    config: String::new(),
                    member_vc_json: String::new(),
                    status_list_json: String::new(),
                    did_doc_aggregate_json: String::new(),
                    signing_pubkey_der_b64: String::new(),
                    signed_policy_b64: String::new(),
                    message,
                };
            }

            let membership = CircleMembership {
                node_name: request.node_id.clone(),
                circle_id: request.circle_id.clone(),
                vc_hash: format!("broker-enrollment-{}", request.node_id),
                is_valid: true,
            };

            if let Err(e) = NebulaCA::issue_node_cert(NEBULA_BASE_DIR, &membership, &overlay_ip) {
                return EnrollmentResponse {
                    status: "REJECTED".to_string(),
                    overlay_ip: String::new(),
                    cert: String::new(),
                    key: String::new(),
                    ca_cert: String::new(),
                    config: String::new(),
                    member_vc_json: String::new(),
                    status_list_json: String::new(),
                    did_doc_aggregate_json: String::new(),
                    signing_pubkey_der_b64: String::new(),
                    signed_policy_b64: String::new(),
                    message: format!("Certificate signing failed: {}", e),
                };
            }

            let cert = match std::fs::read_to_string(&cert_path) {
                Ok(c) => c,
                Err(e) => {
                    return EnrollmentResponse {
                        status: "REJECTED".to_string(),
                        overlay_ip: String::new(),
                        cert: String::new(),
                        key: String::new(),
                        ca_cert: String::new(),
                        config: String::new(),
                        member_vc_json: String::new(),
                        status_list_json: String::new(),
                        did_doc_aggregate_json: String::new(),
                        signing_pubkey_der_b64: String::new(),
                        signed_policy_b64: String::new(),
                        message: format!("Failed to read signed cert: {}", e),
                    };
                }
            };

            let node_key = match std::fs::read_to_string(&key_path) {
                Ok(k) => k,
                Err(e) => {
                    return EnrollmentResponse {
                        status: "REJECTED".to_string(),
                        overlay_ip: String::new(),
                        cert: String::new(),
                        key: String::new(),
                        ca_cert: String::new(),
                        config: String::new(),
                        member_vc_json: String::new(),
                        status_list_json: String::new(),
                        did_doc_aggregate_json: String::new(),
                        signing_pubkey_der_b64: String::new(),
                        signed_policy_b64: String::new(),
                        message: format!("Failed to read node key: {}", e),
                    };
                }
            };

            let ca_cert = match std::fs::read_to_string(&ca_path) {
                Ok(c) => c,
                Err(e) => {
                    return EnrollmentResponse {
                        status: "REJECTED".to_string(),
                        overlay_ip: String::new(),
                        cert: String::new(),
                        key: String::new(),
                        ca_cert: String::new(),
                        config: String::new(),
                        member_vc_json: String::new(),
                        status_list_json: String::new(),
                        did_doc_aggregate_json: String::new(),
                        signing_pubkey_der_b64: String::new(),
                        signed_policy_b64: String::new(),
                        message: format!("Failed to read CA cert: {}", e),
                    };
                }
            };

            // Clean up the approval request YAML file upon successful issuance
            let _ = std::fs::remove_file(&yaml_path);

            let config = generate_remote_node_config(&request.node_id, &overlay_ip);
            let trust = match build_trust_material(request, &subject_did).await {
                Ok(trust) => trust,
                Err(message) => {
                    return EnrollmentResponse {
                        status: "ERROR".to_string(),
                        overlay_ip: overlay_ip.clone(),
                        cert: String::new(),
                        key: String::new(),
                        ca_cert: String::new(),
                        config: String::new(),
                        member_vc_json: String::new(),
                        status_list_json: String::new(),
                        did_doc_aggregate_json: String::new(),
                        signing_pubkey_der_b64: String::new(),
                        signed_policy_b64: String::new(),
                        message,
                    };
                }
            };

            log_event(
                "nodeA",
                &format!(
                    "Remote enrollment approved and issued via broker: node={} ip={}",
                    request.node_id, overlay_ip
                ),
            );

            EnrollmentResponse {
                status: "APPROVED".to_string(),
                overlay_ip: overlay_ip.clone(),
                cert,
                key: node_key,
                ca_cert,
                config,
                member_vc_json: trust.member_vc_json,
                status_list_json: trust.status_list_json,
                did_doc_aggregate_json: trust.did_doc_aggregate_json,
                signing_pubkey_der_b64: trust.signing_pubkey_der_b64,
                signed_policy_b64: trust.signed_policy_b64,
                message: format!(
                    "Certificate signed for {} at {}",
                    request.node_id, overlay_ip
                ),
            }
        }
    }
}

/// Generate a nebula.yaml config for a remote node.
///
/// The config points to the VPS as the lighthouse and relay,
/// using env vars SGX_VPS_PUBLIC_IP and SGX_VPS_OVERLAY_IP.
fn generate_remote_node_config(node_id: &str, overlay_ip: &str) -> String {
    let vps_cfg = crate::config_loader::resolve_vps_config("nodeA");
    let vps_public_ip = vps_cfg
        .vps_public_ip
        .unwrap_or_else(|| "159.203.186.55".to_string());
    let vps_overlay_ip = vps_cfg
        .vps_overlay_ip
        .unwrap_or_else(|| "192.168.100.10".to_string());

    format!(
        r#"# Auto-generated by SGX Guardian CA Broker
# Node: {node_id} | Overlay IP: {overlay_ip}
# VPS Lighthouse: {vps_overlay_ip} ({vps_public_ip}:4242)

pki:
  ca: "/var/lib/sgx-guardian/nebula/ca/ca.crt"
  cert: "/var/lib/sgx-guardian/nebula/nodes/{node_id}.crt"
  key: "/var/lib/sgx-guardian/nebula/nodes/{node_id}.key"

static_host_map:
  "{vps_overlay_ip}": ["{vps_public_ip}:4242"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "{vps_overlay_ip}"

listen:
  host: 0.0.0.0
  port: 4242

relay:
  am_relay: false
  use_relays: true
  relays:
    - "{vps_overlay_ip}"

punchy:
  punch: true
  respond: true

tun:
  dev: nebula0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500

logging:
  level: info

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
"#,
        node_id = node_id,
        overlay_ip = overlay_ip,
        vps_public_ip = vps_public_ip,
        vps_overlay_ip = vps_overlay_ip,
    )
}
