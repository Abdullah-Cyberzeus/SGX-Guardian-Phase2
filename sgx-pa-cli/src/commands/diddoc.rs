use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use sgx_guardian_client::did::{
    doc_distribution, doc_persistence, doc_sign, document::DidDocument, Did,
};

#[derive(Args)]
#[command(about = "DID Document operations (Sprint 5)")]
pub struct DidDocArgs {
    #[command(subcommand)]
    pub command: DidDocCommand,
}

#[derive(Subcommand)]
pub enum DidDocCommand {
    /// Show this device's DID Document summary
    Show,
    /// Verify a DID Document file (or self if omitted)
    Verify(VerifyArgs),
    /// Dump this device's DID Document JSON
    Dump,
    /// List cached peer DID Documents
    Peers,
    /// Show one cached peer DID Document by DID
    Peer(PeerArgs),
    /// Publish this device's DID Document to the CA
    Publish(PublishArgs),
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to a DID Document JSON file. Omit to verify self.
    pub path: Option<String>,
}

#[derive(Args)]
pub struct PeerArgs {
    pub did: String,
}

#[derive(Args)]
pub struct PublishArgs {
    /// CA host/IP for registry sync publish
    #[arg(long)]
    pub ca_host: String,
    /// Node name sent to CA (e.g., nodeB)
    #[arg(long)]
    pub node_name: String,
}

pub fn run(args: DidDocArgs) {
    match args.command {
        DidDocCommand::Show => cmd_show(),
        DidDocCommand::Verify(a) => cmd_verify(a),
        DidDocCommand::Dump => cmd_dump(),
        DidDocCommand::Peers => cmd_peers(),
        DidDocCommand::Peer(a) => cmd_peer(a),
        DidDocCommand::Publish(a) => cmd_publish(a),
    }
}

fn cmd_show() {
    match doc_persistence::load_self() {
        Ok(Some(d)) => print_summary(&d),
        Ok(None) => {
            eprintln!("No self DID Document found. Start sgx-guardian first.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Load failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_dump() {
    match doc_persistence::load_self() {
        Ok(Some(d)) => println!("{}", serde_json::to_string_pretty(&d).unwrap_or_default()),
        Ok(None) => std::process::exit(1),
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_verify(args: VerifyArgs) {
    let doc: DidDocument = match args.path {
        Some(path) => {
            let s = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("❌ Read {}: {}", path, e);
                std::process::exit(1);
            });
            serde_json::from_str(&s).unwrap_or_else(|e| {
                eprintln!("❌ Parse {}: {}", path, e);
                std::process::exit(1);
            })
        }
        None => match doc_persistence::load_self() {
            Ok(Some(d)) => d,
            Ok(None) => {
                eprintln!("No self DID Document found.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("❌ {}", e);
                std::process::exit(1);
            }
        },
    };

    let floor = if let Ok(Some(self_doc)) = doc_persistence::load_self() {
        if self_doc.id == doc.id {
            self_doc.sgx_version_id
        } else if let Ok(did) = Did::parse(&doc.id) {
            doc_persistence::load_peer(&did)
                .ok()
                .flatten()
                .map(|peer| peer.sgx_version_id)
                .unwrap_or(0)
        } else {
            0
        }
    } else if let Ok(did) = Did::parse(&doc.id) {
        doc_persistence::load_peer(&did)
            .ok()
            .flatten()
            .map(|peer| peer.sgx_version_id)
            .unwrap_or(0)
    } else {
        0
    };

    match doc_sign::verify_with_replay_protection(&doc, floor) {
        Ok(()) if floor == 0 => {
            println!("✅ Verified — proof signature valid (no local floor for this DID)")
        }
        Ok(()) if doc.sgx_version_id == floor => {
            println!(
                "✅ Verified — proof valid (version v{} matches local floor)",
                floor
            )
        }
        Ok(()) => println!(
            "✅ Verified — proof valid (v{} >= local floor v{})",
            doc.sgx_version_id, floor
        ),
        Err(e) => {
            eprintln!("❌ Verification failed: {}", e);
            std::process::exit(2);
        }
    }
}

fn cmd_peers() {
    match doc_persistence::list_peer_docs() {
        Ok(v) if v.is_empty() => println!("(no cached peer DID Documents)"),
        Ok(v) => {
            let mut t = Table::new();
            t.set_header(vec!["Node", "DID (short)", "v", "Status", "Services"]);
            for d in v {
                t.add_row(vec![
                    Cell::new(d.sgx_node_name.as_deref().unwrap_or("?")),
                    Cell::new(&d.id[..d.id.len().min(32)]),
                    Cell::new(format!("v{}", d.sgx_version_id)),
                    Cell::new(d.sgx_status.as_deref().unwrap_or("?")),
                    Cell::new(d.service.len().to_string()),
                ]);
            }
            println!("{}", t);
        }
        Err(e) => {
            eprintln!("❌ List failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_peer(args: PeerArgs) {
    let did = match Did::parse(&args.did) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("❌ Bad DID: {}", e);
            std::process::exit(1);
        }
    };
    match doc_persistence::load_peer(&did) {
        Ok(Some(d)) => print_summary(&d),
        Ok(None) => {
            eprintln!("Not cached: {}", args.did);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_publish(args: PublishArgs) {
    let doc = match doc_persistence::load_self() {
        Ok(Some(d)) => d,
        Ok(None) => {
            eprintln!("No self DID Document to publish.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("❌ Runtime init failed: {}", e);
            std::process::exit(1);
        });
    match rt.block_on(doc_distribution::publish_to_ca(
        &args.ca_host,
        &args.node_name,
        &doc,
    )) {
        Ok(resp) if resp.success => {
            let did = resp.did_doc_did.as_deref().unwrap_or(doc.id.as_str());
            let version = resp.did_doc_version.unwrap_or(doc.sgx_version_id);
            match resp.did_doc_peer_count {
                Some(count) => println!(
                    "✅ Published DID Document {} v{} to {} (CA aggregate peers={})",
                    did, version, args.ca_host, count
                ),
                None => println!(
                    "✅ Published DID Document {} v{} to {}",
                    did, version, args.ca_host
                ),
            }
        }
        Ok(resp) => {
            eprintln!(
                "❌ Publish rejected by CA: {}",
                resp.error
                    .unwrap_or_else(|| "unknown rejection".to_string())
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Publish failed: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use sgx_guardian_client::did::document::DocBuildInput;
    use sgx_guardian_client::key_manager::KeyManager;

    // doc_persistence's configured_* helpers read these env vars unconditionally (not gated
    // behind #[cfg(test)] in the main crate), so sgx-pa-cli's own tests can redirect them to
    // a tempdir. Process-global, so serialize access via the shared lock in `test_support`
    // (also used by `pairing.rs`, which touches the same `SGX_GUARDIAN_DID_DOC_PATH`).

    struct DidDocEnv {
        _guard: std::sync::MutexGuard<'static, ()>,
        _td: tempfile::TempDir,
        restore: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl DidDocEnv {
        fn new() -> (Self, DidDocument) {
            let guard = crate::test_support::DID_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let td = tempfile::tempdir().expect("tempdir");
            let self_doc_path = td.path().join("did_doc.json");
            let peers_dir = td.path().join("peers");
            std::fs::create_dir_all(&peers_dir).expect("peers dir");

            let restore = vec![
                (
                    doc_persistence::SELF_DOC_PATH_ENV,
                    std::env::var_os(doc_persistence::SELF_DOC_PATH_ENV),
                ),
                (
                    doc_persistence::PEERS_DOC_DIR_ENV,
                    std::env::var_os(doc_persistence::PEERS_DOC_DIR_ENV),
                ),
            ];
            std::env::set_var(doc_persistence::SELF_DOC_PATH_ENV, &self_doc_path);
            std::env::set_var(doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);

            let key_path = td.path().join("device.key");
            let km =
                KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
            let pubkey = km.pubkey_der().expect("pubkey");
            let did = Did::from_id_bytes(&[7u8; 32]);
            let did_str = did.to_string();
            let now = chrono::Utc::now().to_rfc3339();
            let mut doc = DidDocument::build(DocBuildInput {
                did: &did_str,
                node_name: Some("nodeTestDidDoc"),
                current_dkp_version: 1,
                current_dkp_pubkey_der: &pubkey,
                overlay_ip_cidr: Some("127.0.0.1/32"),
                attestation_bind: None,
                cert_bootstrap_bind: None,
                revoked: vec![],
                previous_version_id: 0,
                created_at: Some(now),
                status: Some("active".into()),
            })
            .expect("build did doc");
            let vm_ref = doc.verification_method.first().expect("vm").id.clone();
            sgx_guardian_client::did::doc_sign::sign_in_place(&mut doc, &km, &vm_ref)
                .expect("sign did doc");

            (
                Self {
                    _guard: guard,
                    _td: td,
                    restore,
                },
                doc,
            )
        }
    }

    impl Drop for DidDocEnv {
        fn drop(&mut self) {
            for (key, value) in self.restore.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn cmd_show_prints_a_summary_for_a_real_self_document() {
        let (_env, doc) = DidDocEnv::new();
        doc_persistence::save_self(&doc).expect("save self doc");
        cmd_show();
    }

    #[test]
    fn cmd_dump_prints_json_for_a_real_self_document() {
        let (_env, doc) = DidDocEnv::new();
        doc_persistence::save_self(&doc).expect("save self doc");
        cmd_dump();
    }

    #[test]
    fn cmd_peers_lists_a_real_cached_peer_document() {
        let (_env, doc) = DidDocEnv::new();
        doc_persistence::save_peer(&doc).expect("save peer doc");
        cmd_peers();
    }

    #[test]
    fn cmd_peers_reports_empty_when_no_peers_cached() {
        let (_env, _doc) = DidDocEnv::new();
        cmd_peers();
    }

    #[test]
    fn cmd_peer_prints_a_summary_for_a_cached_peer() {
        let (_env, doc) = DidDocEnv::new();
        doc_persistence::save_peer(&doc).expect("save peer doc");
        cmd_peer(PeerArgs {
            did: doc.id.clone(),
        });
    }

    #[test]
    fn cmd_verify_confirms_a_genuinely_signed_self_document() {
        let (_env, doc) = DidDocEnv::new();
        doc_persistence::save_self(&doc).expect("save self doc");
        cmd_verify(VerifyArgs { path: None });
    }

    #[test]
    fn cmd_verify_confirms_a_genuinely_signed_document_from_a_file() {
        let (_env, doc) = DidDocEnv::new();
        let path = std::env::temp_dir().join(format!(
            "diddoc-verify-file-test-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        cmd_verify(VerifyArgs {
            path: Some(path.to_string_lossy().to_string()),
        });
        let _ = std::fs::remove_file(&path);
    }
}

fn print_summary(d: &DidDocument) {
    let mut t = Table::new();
    t.set_header(vec!["Field", "Value"]);
    t.add_row(vec![Cell::new("DID"), Cell::new(&d.id)]);
    t.add_row(vec![Cell::new("Controller"), Cell::new(&d.controller)]);
    t.add_row(vec![
        Cell::new("Node hint"),
        Cell::new(d.sgx_node_name.as_deref().unwrap_or("?")),
    ]);
    t.add_row(vec![
        Cell::new("Version"),
        Cell::new(format!("v{}", d.sgx_version_id)),
    ]);
    t.add_row(vec![
        Cell::new("Status"),
        Cell::new(d.sgx_status.as_deref().unwrap_or("?")),
    ]);
    t.add_row(vec![Cell::new("Created"), Cell::new(&d.sgx_created)]);
    t.add_row(vec![Cell::new("Updated"), Cell::new(&d.sgx_updated)]);
    t.add_row(vec![
        Cell::new("Active VMs"),
        Cell::new(d.verification_method.len().to_string()),
    ]);
    t.add_row(vec![
        Cell::new("Revoked VMs"),
        Cell::new(d.sgx_revoked_vm.len().to_string()),
    ]);
    t.add_row(vec![
        Cell::new("Services"),
        Cell::new(d.service.len().to_string()),
    ]);
    if let Some(p) = &d.proof {
        t.add_row(vec![
            Cell::new("Proof VM"),
            Cell::new(&p.verification_method),
        ]);
        t.add_row(vec![Cell::new("Proof created"), Cell::new(&p.created)]);
    }
    println!("{}", t);

    if !d.service.is_empty() {
        let mut s = Table::new();
        s.set_header(vec!["Service ID", "Type", "Endpoint"]);
        for svc in &d.service {
            s.add_row(vec![
                Cell::new(svc.id.rsplit('#').next().unwrap_or(&svc.id)),
                Cell::new(&svc.svc_type),
                Cell::new(&svc.service_endpoint),
            ]);
        }
        println!("\nServices:\n{}", s);
    }
}
