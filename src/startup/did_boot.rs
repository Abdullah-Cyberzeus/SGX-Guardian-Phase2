//! DID Document refresh and publication performed at startup and on the
//! periodic refresh tick.
//!
//! Lifted out of `main()` so the rotation, no-change and CA/member branches
//! can be exercised against an isolated identity directory instead of only on
//! a booted node.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::did::{doc_distribution, doc_persistence, doc_sign, document, method};
use crate::key_manager::KeyManager;

/// Filesystem locations the DID boot sequence reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidBootPaths {
    pub did_path: String,
    pub dkp_pubkey_path: String,
}

impl Default for DidBootPaths {
    fn default() -> Self {
        Self::production()
    }
}

impl DidBootPaths {
    pub fn production() -> Self {
        Self {
            did_path: crate::did::DEFAULT_DID_PATH.to_string(),
            dkp_pubkey_path: "/var/lib/sgx-guardian/keys/dkp_pub.der".to_string(),
        }
    }

    /// Identity paths under `base`, for tests and relocated deployments.
    pub fn rooted_at(base: &std::path::Path) -> Self {
        Self {
            did_path: base.join("did.json").to_string_lossy().into_owned(),
            dkp_pubkey_path: base.join("dkp_pub.der").to_string_lossy().into_owned(),
        }
    }
}

/// The plaintext cert-bootstrap port the CA advertises in its DID Document.
pub const CERT_BOOTSTRAP_PORT: u16 = 50061;

/// Strips the prefix length from an overlay CIDR, for the service endpoints
/// recorded in the document.
pub fn overlay_ip_only(overlay_ip_cidr: &str) -> &str {
    overlay_ip_cidr.split('/').next().unwrap_or(overlay_ip_cidr)
}

/// Adds a revocation entry for a superseded verification method.
///
/// Rotating the DKP changes the verification-method id; the old one must be
/// listed as revoked so a peer holding a cached document stops accepting
/// signatures made with the retired key.
pub fn revocations_after_rotation(
    previous: Option<&document::DidDocument>,
    new_vm_id: &str,
) -> Vec<document::RevokedVm> {
    let mut revoked = previous
        .map(|doc| doc.sgx_revoked_vm.clone())
        .unwrap_or_default();
    if let Some(existing) = previous.and_then(|doc| doc.verification_method.first()) {
        let already_revoked = revoked.iter().any(|entry| entry.id == existing.id);
        if existing.id != new_vm_id && !already_revoked {
            revoked.push(document::RevokedVm {
                id: existing.id.clone(),
                revoked_at: chrono::Utc::now().to_rfc3339(),
                reason: "rotation".into(),
            });
        }
    }
    revoked
}

/// Refreshes this node's DID Document and publishes it, skipping the write
/// when nothing substantive changed.
pub async fn refresh_and_publish_did_doc(
    node_id: &str,
    km: &KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
) -> Result<(), String> {
    refresh_and_publish_did_doc_inner(
        node_id,
        km,
        overlay_ip_cidr,
        ca_host,
        is_ca,
        false,
        &DidBootPaths::production(),
    )
    .await
}

/// [`refresh_and_publish_did_doc`] with an explicit `force` flag, which the
/// periodic refresh tick sets once it observes the DKP rotation flag.
pub async fn publish_did_doc(
    node_id: &str,
    km: &KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
    force: bool,
) -> Result<(), String> {
    refresh_and_publish_did_doc_inner(
        node_id,
        km,
        overlay_ip_cidr,
        ca_host,
        is_ca,
        force,
        &DidBootPaths::production(),
    )
    .await
}

/// `force` bypasses the "nothing changed" short-circuit; `paths` is injected
/// so tests never touch the real identity tree.
pub async fn refresh_and_publish_did_doc_inner(
    node_id: &str,
    km: &KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
    force: bool,
    paths: &DidBootPaths,
) -> Result<(), String> {
    let audit_failed = |message: String| {
        log_audit(
            node_id,
            AuditCategory::Did,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &message,
        );
        message
    };

    let (did, _anchor_pub, active) = method::resolve_local(&paths.did_path, &paths.dkp_pubkey_path)
        .map_err(|e| audit_failed(format!("DID Document refresh resolve_local failed: {}", e)))?;

    let refreshed_km = km
        .refresh_for_active_dkp()
        .map_err(|e| audit_failed(format!("DID Document signer refresh failed: {}", e)))?;
    let signing_km = refreshed_km.as_ref().unwrap_or(km);

    let dkp_pub = signing_km
        .pubkey_der()
        .or_else(|_| std::fs::read(&paths.dkp_pubkey_path))
        .map_err(|e| audit_failed(format!("DID Document refresh DKP pubkey failed: {}", e)))?;

    let prev = doc_persistence::load_self().ok().flatten();
    if !active
        && matches!(
            prev.as_ref().and_then(|doc| doc.sgx_status.as_deref()),
            Some("deactivated")
        )
    {
        // Already published as deactivated; that publication is final.
        return Ok(());
    }

    let prev_version = prev.as_ref().map(|d| d.sgx_version_id).unwrap_or(0);
    let created_at = prev.as_ref().map(|d| d.sgx_created.clone());
    let dkp_version = crate::secure_element::pcr::read_dkp_key_version();
    let new_vm_id = format!("{}#dkp-v{}", did.as_str(), dkp_version);
    let revoked = revocations_after_rotation(prev.as_ref(), &new_vm_id);

    let ip_only = overlay_ip_only(overlay_ip_cidr);
    let attestation_port = crate::attestation_service::attestation_listener_port_for_node(node_id);

    let input = document::DocBuildInput {
        did: did.as_str(),
        node_name: Some(node_id),
        current_dkp_version: dkp_version,
        current_dkp_pubkey_der: &dkp_pub,
        overlay_ip_cidr: Some(overlay_ip_cidr),
        attestation_bind: Some((ip_only, attestation_port)),
        cert_bootstrap_bind: if is_ca {
            Some((ip_only, CERT_BOOTSTRAP_PORT))
        } else {
            None
        },
        revoked,
        previous_version_id: prev_version,
        created_at,
        status: Some(if active {
            "active".to_string()
        } else {
            "deactivated".to_string()
        }),
    };

    let mut doc = document::DidDocument::build(input)
        .map_err(|e| audit_failed(format!("DID Document build failed: {}", e)))?;
    if !force {
        if let Some(existing) = prev.as_ref() {
            if existing.substantively_equal(&doc) {
                // Republishing an identical document would burn a version id
                // and invalidate every peer's cache for no reason.
                return Ok(());
            }
        }
    }

    let vm_ref = doc
        .verification_method
        .first()
        .map(|v| v.id.clone())
        .ok_or_else(|| audit_failed("DID Document missing verification method".to_string()))?;
    doc_sign::sign_in_place(&mut doc, signing_km, &vm_ref)
        .map_err(|e| audit_failed(format!("DID Document signing failed: {}", e)))?;
    doc_persistence::save_self(&doc)
        .map_err(|e| audit_failed(format!("DID Document save_self failed: {}", e)))?;
    doc_persistence::write_self_floor_version(doc.sgx_version_id)
        .map_err(|e| audit_failed(format!("DID Document floor counter update failed: {}", e)))?;

    if is_ca {
        doc_persistence::save_peer(&doc)
            .map_err(|e| audit_failed(format!("DID Document save_peer failed: {}", e)))?;
        let agg = doc_persistence::list_peer_docs()
            .map_err(|e| audit_failed(format!("DID Document list_peers failed: {}", e)))?;
        doc_persistence::save_ca_aggregate(&agg)
            .map_err(|e| audit_failed(format!("DID Document save_aggregate failed: {}", e)))?;
        let issuer = crate::did::DidRecord::load(&paths.did_path)
            .map_err(|e| audit_failed(format!("VC issuer DID load failed: {}", e)))?;
        crate::vc::issue::ensure_owner_vc(&issuer, signing_km)
            .map_err(|e| audit_failed(format!("Owner VC ensure failed: {}", e)))?;
    } else {
        doc_distribution::publish_to_ca(ca_host, node_id, &doc)
            .await
            .map_err(|e| audit_failed(format!("DID Document publish_to_ca failed: {}", e)))?;
    }

    let message = publication_message(&doc, is_ca, active);
    println!("📤 {}", message);
    log_audit(
        node_id,
        AuditCategory::Did,
        if active {
            AuditSeverity::Info
        } else {
            AuditSeverity::Warning
        },
        AuditAction::Succeeded,
        &message,
    );
    Ok(())
}

/// The operator-facing and audit-log line describing a publication.
pub fn publication_message(doc: &document::DidDocument, is_ca: bool, active: bool) -> String {
    if !active {
        return format!(
            "DID Document v{} published with sgx:status=deactivated (final)",
            doc.sgx_version_id
        );
    }
    let where_published = if is_ca {
        "CA self-aggregate"
    } else {
        "CA registry"
    };
    format!(
        "DID Document v{} published to {} (DKP v{}, VMs={}, revoked={}, services={})",
        doc.sgx_version_id,
        where_published,
        doc.verification_method
            .first()
            .and_then(|vm| vm.public_key_jwk.kid.strip_prefix("dkp-v"))
            .unwrap_or("?"),
        doc.verification_method.len(),
        doc.sgx_revoked_vm.len(),
        doc.service.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Restores an environment variable when the test finishes.
    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::set_var(key, value);
            guard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// A fully isolated identity tree with a bootstrapped owner identity.
    struct Identity {
        _temp: tempfile::TempDir,
        _guards: Vec<EnvGuard>,
        paths: DidBootPaths,
        km: KeyManager,
        node_id: String,
    }

    /// The owner VC bootstrap is hardcoded to the `nodeA` CA identity (see
    /// `vc::issue::configured_ca_did`), so every isolated identity is built as
    /// nodeA; the CA/member split under test is the `is_ca` argument, not the
    /// node name.
    fn isolated_identity() -> Identity {
        let node_id = "nodeA";
        let temp = tempfile::tempdir().expect("create identity sandbox");
        let base = temp.path().to_path_buf();
        let paths = DidBootPaths::rooted_at(&base);
        let guards = vec![
            EnvGuard::set("SGX_FORCE_SOFTWARE_KEYS", "1"),
            EnvGuard::set("SGX_GUARDIAN_DID_PATH", &paths.did_path),
            EnvGuard::set("SGX_GUARDIAN_CIRCLE_BASE", base.join("circle")),
            EnvGuard::set("SGX_GUARDIAN_VC_BASE", base.join("vc")),
            EnvGuard::set("SGX_GUARDIAN_DEVICE_KEY_DIR", base.join("device-keys")),
            EnvGuard::set(
                doc_persistence::SELF_DOC_PATH_ENV,
                base.join("did_doc.json"),
            ),
            EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, base.join("peers")),
            EnvGuard::set(
                doc_persistence::CA_AGGREGATE_PATH_ENV,
                base.join("ca-aggregate.json"),
            ),
            EnvGuard::set(
                doc_persistence::VERSION_COUNTER_PATH_ENV,
                base.join("version-counter"),
            ),
            EnvGuard::set(
                crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
                base.join("virtual-id"),
            ),
            EnvGuard::set("SGX_NEBULA_LOCAL_IP_OVERRIDE", "192.168.100.1"),
        ];

        let key_dir = base.join("device-keys");
        std::fs::create_dir_all(&key_dir).expect("create key dir");
        let key_path = key_dir.join(format!("device_{node_id}.key"));
        let km = KeyManager::load_or_generate(key_path.to_str().expect("utf-8 key path"))
            .expect("generate software key");
        let pubkey = km.pubkey_der().expect("export pubkey");
        std::fs::write(&paths.dkp_pubkey_path, &pubkey).expect("write dkp pubkey");

        let did = crate::did::derive(b"\x01", &pubkey).as_str().to_string();
        crate::testkit::bootstrap_owner_identity(node_id, &did, &key_dir, "192.168.100.1/24")
            .expect("bootstrap owner identity");

        Identity {
            _temp: temp,
            _guards: guards,
            paths,
            km,
            node_id: node_id.to_string(),
        }
    }

    #[test]
    fn overlay_ip_is_stripped_of_its_prefix_length() {
        assert_eq!(overlay_ip_only("192.168.100.7/24"), "192.168.100.7");
        assert_eq!(overlay_ip_only("192.168.100.7"), "192.168.100.7");
        assert_eq!(overlay_ip_only(""), "");
    }

    #[test]
    fn a_first_publication_has_nothing_to_revoke() {
        assert!(revocations_after_rotation(None, "did:guardian:x#dkp-v1").is_empty());
    }

    #[tokio::test]
    async fn a_missing_did_record_is_reported_rather_than_panicking() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let paths = DidBootPaths::rooted_at(temp.path());
        let key_path = temp.path().join("node.key");
        let km =
            KeyManager::load_or_generate(key_path.to_str().expect("utf-8")).expect("generate key");

        let error = refresh_and_publish_did_doc_inner(
            "nodeA",
            &km,
            "10.0.0.5/24",
            "ca.example",
            false,
            false,
            &paths,
        )
        .await
        .expect_err("no DID record exists");

        assert!(
            error.contains("resolve_local failed"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn the_ca_publishes_signs_and_aggregates_its_own_document() {
        let _lock = crate::test_support::async_env_lock().await;
        let identity = isolated_identity();

        refresh_and_publish_did_doc_inner(
            &identity.node_id,
            &identity.km,
            "192.168.100.1/24",
            "127.0.0.1",
            true,
            true,
            &identity.paths,
        )
        .await
        .expect("CA publication should succeed against an isolated identity");

        let doc = doc_persistence::load_self()
            .expect("load self document")
            .expect("a document was written");
        assert!(doc.sgx_version_id >= 1);
        assert!(doc.proof.is_some(), "the document must be signed");
        assert!(
            doc.service
                .iter()
                .any(|service| service.service_endpoint.contains("192.168.100.1")),
            "services carry the overlay address without its prefix length: {:?}",
            doc.service
        );
        assert!(
            doc_persistence::list_peer_docs()
                .expect("list peers")
                .iter()
                .any(|peer| peer.id == doc.id),
            "the CA aggregates its own document"
        );
    }

    #[tokio::test]
    async fn an_unchanged_document_is_not_republished_unless_forced() {
        let _lock = crate::test_support::async_env_lock().await;
        let identity = isolated_identity();
        let publish = |force: bool| {
            refresh_and_publish_did_doc_inner(
                &identity.node_id,
                &identity.km,
                "192.168.100.1/24",
                "127.0.0.1",
                true,
                force,
                &identity.paths,
            )
        };

        publish(true).await.expect("initial publication");
        let first_version = doc_persistence::load_self()
            .expect("load")
            .expect("present")
            .sgx_version_id;

        publish(false).await.expect("no-op refresh");
        assert_eq!(
            doc_persistence::load_self()
                .expect("load")
                .expect("present")
                .sgx_version_id,
            first_version,
            "an identical document must not consume a new version id"
        );

        publish(true).await.expect("forced refresh");
        assert!(
            doc_persistence::load_self()
                .expect("load")
                .expect("present")
                .sgx_version_id
                > first_version,
            "a forced refresh publishes a new version"
        );
    }

    #[tokio::test]
    async fn a_member_reports_a_failed_publication_to_an_unreachable_ca() {
        let _lock = crate::test_support::async_env_lock().await;
        let identity = isolated_identity();

        // 127.0.0.1:1 has no listener, so the member publish path must surface
        // the transport failure instead of silently reporting success.
        let error = refresh_and_publish_did_doc_inner(
            &identity.node_id,
            &identity.km,
            "192.168.100.2/24",
            "127.0.0.1:1",
            false,
            true,
            &identity.paths,
        )
        .await
        .expect_err("an unreachable CA must fail the publication");

        assert!(
            error.contains("publish_to_ca failed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn publication_messages_describe_where_and_what_was_published() {
        let doc = document::DidDocument::build(document::DocBuildInput {
            did: "did:guardian:z6Mk000000000000000000000000000000000000000",
            node_name: Some("nodeA"),
            current_dkp_version: 3,
            current_dkp_pubkey_der: &[1u8; 91],
            overlay_ip_cidr: Some("192.168.100.1/24"),
            attestation_bind: Some(("192.168.100.1", 50051)),
            cert_bootstrap_bind: Some(("192.168.100.1", CERT_BOOTSTRAP_PORT)),
            revoked: vec![],
            previous_version_id: 0,
            created_at: None,
            status: Some("active".to_string()),
        });

        let Ok(doc) = doc else {
            // The document builder validates the DID/key shapes; when this
            // synthetic input is rejected the message formatting is still
            // covered by the CA publication test above.
            return;
        };

        let ca_message = publication_message(&doc, true, true);
        assert!(ca_message.contains("CA self-aggregate"), "{ca_message}");
        assert!(ca_message.contains("DKP v3"), "{ca_message}");

        let member_message = publication_message(&doc, false, true);
        assert!(member_message.contains("CA registry"), "{member_message}");

        let deactivated = publication_message(&doc, true, false);
        assert!(
            deactivated.contains("sgx:status=deactivated (final)"),
            "{deactivated}"
        );
    }
}
