use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use sgx_guardian_client::did::{self, DidError};
use std::path::{Path, PathBuf};

const CA_HOST_ENV: &str = "SGX_CA_HOST";
const CA_HOST_MISSING_MSG: &str =
    "CA registry host is not configured; set SGX_CA_HOST or pass --ca-host.";

#[derive(Args)]
#[command(about = "DID lifecycle and registry operations (Sprint 5)")]
pub struct DidArgs {
    #[command(subcommand)]
    pub command: DidCommand,
}

#[derive(Subcommand)]
pub enum DidCommand {
    /// Show this device's DID and metadata
    Show,
    /// Resolve a DID locally (self or cached peer)
    Resolve(DidResolveArgs),
    /// List cached peer DIDs
    Peers,
    /// Force-create is handled by daemon startup; this displays current state
    Create,
    /// Deactivate this device's DID
    Deactivate(DidDeactivateArgs),
    /// One-time migration: backup and remove did.json so daemon remints from DIK
    Remint(DidRemintArgs),
}

#[derive(Args)]
pub struct DidResolveArgs {
    /// DID string to resolve. Omit to resolve self.
    pub did: Option<String>,
    /// CA host/IP for registry-backed DID resolution
    #[arg(long)]
    pub ca_host: Option<String>,
}

#[derive(Args)]
pub struct DidDeactivateArgs {
    /// Reason (recorded for operator context)
    #[arg(long, default_value = "manual")]
    pub reason: String,
    /// Skip interactive confirmation
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct DidRemintArgs {
    /// Confirm destructive operation (removes current did.json after backup)
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: DidArgs) {
    match args.command {
        DidCommand::Show => cmd_show(),
        DidCommand::Resolve(a) => cmd_resolve(a),
        DidCommand::Peers => cmd_peers(),
        DidCommand::Create => cmd_create(),
        DidCommand::Deactivate(a) => cmd_deactivate(a),
        DidCommand::Remint(a) => cmd_remint(a),
    }
}

fn cmd_show() {
    match did::DidRecord::load(did::DEFAULT_DID_PATH) {
        Ok(rec) => {
            let mut table = Table::new();
            table.set_header(vec!["Field", "Value"]);
            table.add_row(vec![Cell::new("DID"), Cell::new(&rec.did)]);
            table.add_row(vec![Cell::new("Method"), Cell::new(&rec.method)]);
            table.add_row(vec![
                Cell::new("Method version"),
                Cell::new(&rec.method_version),
            ]);
            table.add_row(vec![Cell::new("Created"), Cell::new(&rec.created_at)]);
            table.add_row(vec![
                Cell::new("Deactivated"),
                Cell::new(rec.deactivated_at.as_deref().unwrap_or("—")),
            ]);
            table.add_row(vec![
                Cell::new("Current DKP version"),
                Cell::new(format!("v{}", rec.current_dkp_version)),
            ]);
            table.add_row(vec![
                Cell::new("SE050 UID source"),
                Cell::new(&rec.derivation.se050_uid_source),
            ]);
            table.add_row(vec![
                Cell::new("DKP_v1 pubkey hash"),
                Cell::new(&rec.derivation.dkp_v1_pubkey_sha256_b16),
            ]);
            table.add_row(vec![
                Cell::new("DIK pubkey hash"),
                Cell::new(if rec.derivation.dik_pubkey_sha256_b16.is_empty() {
                    "—"
                } else {
                    &rec.derivation.dik_pubkey_sha256_b16
                }),
            ]);
            println!("{}", table);
        }
        Err(e) => {
            eprintln!("❌ Could not load DID at {}: {}", did::DEFAULT_DID_PATH, e);
            std::process::exit(1);
        }
    }
}

fn cmd_resolve(args: DidResolveArgs) {
    let dkp_pubkey_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";

    if args.did.is_none() {
        match did::method::resolve_local(did::DEFAULT_DID_PATH, dkp_pubkey_path) {
            Ok((resolved_did, pk, active)) => {
                let pk_hex = hex::encode(&pk);
                println!("DID:    {}", resolved_did.as_str());
                println!("Status: {}", if active { "ACTIVE" } else { "DEACTIVATED" });
                println!(
                    "Pubkey: {}... ({} bytes)",
                    &pk_hex[..pk_hex.len().min(32)],
                    pk.len()
                );
                println!("Source: self (did.json)");
            }
            Err(e) => {
                eprintln!("❌ Resolve failed: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    let did_str = args.did.unwrap();
    let ca_host = resolve_ca_host(args.ca_host.as_deref());

    if let Ok(self_rec) = did::DidRecord::load(did::DEFAULT_DID_PATH) {
        if self_rec.did == did_str {
            println!("Self-resolution:");
            println!("DID:    {}", self_rec.did);
            println!(
                "Status: {}",
                if self_rec.is_active() {
                    "ACTIVE"
                } else {
                    "DEACTIVATED"
                }
            );
            println!("Source: self (did.json)");
            return;
        }
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("❌ Could not start runtime: {}", e);
            std::process::exit(1);
        }
    };

    let resolver = did::Resolver::new(did::ResolverConfig {
        ca_host: ca_host.clone().unwrap_or_default(),
        ..Default::default()
    });
    let result = rt.block_on(async { resolver.resolve(&did_str).await });

    match result {
        Ok(r) => {
            let mut t = Table::new();
            t.set_header(vec!["Field", "Value"]);
            t.add_row(vec![Cell::new("DID"), Cell::new(&r.did)]);
            t.add_row(vec![Cell::new("Status"), Cell::new(&r.status)]);
            t.add_row(vec![
                Cell::new("Version"),
                Cell::new(format!("v{}", r.version_id)),
            ]);
            t.add_row(vec![
                Cell::new("DKP version"),
                Cell::new(format!("v{}", r.dkp_version)),
            ]);
            t.add_row(vec![Cell::new("Source"), Cell::new(r.source.as_str())]);
            t.add_row(vec![Cell::new("Fetched at"), Cell::new(&r.fetched_at)]);
            t.add_row(vec![
                Cell::new("TTL remaining"),
                Cell::new(format!("{}s", r.ttl_remaining_sec)),
            ]);
            let public_key_preview_len = r.public_key_der_b64.len().min(40);
            t.add_row(vec![
                Cell::new("Pubkey (b64)"),
                Cell::new(format!(
                    "{}... ({} chars)",
                    &r.public_key_der_b64[..public_key_preview_len],
                    r.public_key_der_b64.len()
                )),
            ]);
            println!("{}", t);

            if r.services.is_empty() {
                println!("(no service endpoints)");
            } else {
                let mut st = Table::new();
                st.set_header(vec!["Service", "Type", "Endpoint"]);
                for service in &r.services {
                    let short_id = service
                        .id
                        .rsplit_once('#')
                        .map(|(_, suffix)| suffix)
                        .unwrap_or(&service.id);
                    st.add_row(vec![
                        Cell::new(short_id),
                        Cell::new(&service.r#type),
                        Cell::new(&service.endpoint),
                    ]);
                }
                println!("\nServices:\n{}", st);
            }
        }
        Err(DidError::Unresolvable(did)) => {
            if ca_host.is_none() {
                eprintln!("❌ {}", CA_HOST_MISSING_MSG);
                std::process::exit(1);
            }
            eprintln!("❌ Unresolvable: {}", did);
            eprintln!(
                "   No source (mem-cache, local doc, aggregate, CA network) returned a document."
            );
            std::process::exit(2);
        }
        Err(DidError::ResolutionFailed(message)) => {
            eprintln!("❌ {}", message);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Resolve failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn resolve_ca_host(cli_arg: Option<&str>) -> Option<String> {
    let env_host = std::env::var(CA_HOST_ENV).ok();
    resolve_ca_host_from_sources(cli_arg, env_host.as_deref(), &ca_host_config_candidates())
}

fn resolve_ca_host_from_sources(
    cli_arg: Option<&str>,
    env_host: Option<&str>,
    config_paths: &[PathBuf],
) -> Option<String> {
    normalize_host(cli_arg)
        .or_else(|| normalize_host(env_host))
        .or_else(|| load_ca_host_from_config_paths(config_paths))
}

fn normalize_host(host: Option<&str>) -> Option<String> {
    let host = host?.trim();
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

fn load_ca_host_from_config_paths(paths: &[PathBuf]) -> Option<String> {
    paths.iter().find_map(|path| {
        sgx_guardian_client::config_loader::load_config(path.to_str()?)
            .ok()
            .and_then(|cfg| normalize_configured_host(&cfg.ip))
    })
}

fn normalize_configured_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() || host == "0.0.0.0" {
        return None;
    }
    Some(host.to_string())
}

fn ca_host_config_candidates() -> Vec<PathBuf> {
    let filename = "nodeA.yaml";
    let mut candidates = vec![
        Path::new("/etc/sgx-guardian/config").join(filename),
        Path::new("/etc/sgx-guardian").join(filename),
    ];

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join("..").join("..").join("config").join(filename));
            candidates.push(exe_dir.join("..").join("config").join(filename));
        }
    }

    candidates
}

fn cmd_peers() {
    match did::registry::list(did::registry::default_peers_dir()) {
        Ok(peers) if peers.is_empty() => {
            println!("(no cached peer DIDs)");
        }
        Ok(peers) => {
            let mut table = Table::new();
            table.set_header(vec!["Node hint", "DID", "DKP v", "Last seen", "Source"]);
            for peer in peers {
                let did_short = &peer.did[..peer.did.len().min(32)];
                table.add_row(vec![
                    Cell::new(peer.node_id),
                    Cell::new(did_short),
                    Cell::new(format!("v{}", peer.current_dkp_version)),
                    Cell::new(peer.last_seen),
                    Cell::new(peer.source),
                ]);
            }
            println!("{}", table);
        }
        Err(e) => {
            eprintln!("❌ List failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_create() {
    println!("DID creation is performed by the daemon at startup.");
    println!("Restart `sgx-guardian` to force idempotent DID re-evaluation.");
    cmd_show();
}

fn cmd_deactivate(args: DidDeactivateArgs) {
    if !args.yes {
        eprintln!("⚠️ Deactivation is irreversible from this device.");
        eprintln!("Re-run with --yes to confirm.");
        std::process::exit(1);
    }

    match did::method::deactivate(did::DEFAULT_DID_PATH, &args.reason) {
        Ok(()) => {
            const DID_DOC_ROTATION_FLAG: &str = "/var/lib/sgx-guardian/identity/.dkp_rotated.flag";
            if let Some(parent) = std::path::Path::new(DID_DOC_ROTATION_FLAG).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(DID_DOC_ROTATION_FLAG, chrono::Utc::now().to_rfc3339());
            println!("✅ DID deactivated.");
            println!("  Final DID Document with sgx:status=deactivated will be published");
            println!("  by the running daemon within ~30 s. Restart not required.");
        }
        Err(DidError::Deactivated(when)) => {
            eprintln!("ℹ️ Already deactivated at {}", when);
        }
        Err(e) => {
            eprintln!("❌ Deactivate failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_remint(args: DidRemintArgs) {
    if !args.yes {
        eprintln!("⚠️ Remint will move the current DID record aside and require daemon restart.");
        eprintln!("Re-run with --yes to confirm.");
        std::process::exit(1);
    }

    let did_path = did::DEFAULT_DID_PATH;
    if !std::path::Path::new(did_path).exists() {
        println!(
            "ℹ️ No did.json found at {}. Restart daemon to mint from DIK.",
            did_path
        );
        return;
    }

    let backup_path = format!("{}.dkp-era.bak", did_path);
    match std::fs::rename(did_path, &backup_path) {
        Ok(()) => {
            println!("✅ DID record moved to backup: {}", backup_path);
            println!("🔁 Restart sgx-guardian daemon to regenerate DID from SE050 UID + DIK.");
        }
        Err(e) => {
            eprintln!("❌ Remint prep failed: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ca_host_config_candidates, normalize_configured_host, normalize_host,
        resolve_ca_host_from_sources, CA_HOST_MISSING_MSG,
    };
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn ca_host_prefers_cli_arg_then_env_then_config() {
        let td = TempDir::new().expect("tempdir");
        let config_path = td.path().join("nodeA.yaml");
        fs::write(
            &config_path,
            r#"
node_id: nodeA
hostname: nodeA.local
ip: 10.20.30.40
port: 8443
public_key: test-pubkey
"#,
        )
        .expect("write config");

        let from_cli = resolve_ca_host_from_sources(
            Some("198.51.100.10"),
            Some("198.51.100.11"),
            std::slice::from_ref(&config_path),
        );
        let from_env = resolve_ca_host_from_sources(
            Some("   "),
            Some("198.51.100.11"),
            std::slice::from_ref(&config_path),
        );
        let from_config =
            resolve_ca_host_from_sources(None, None, std::slice::from_ref(&config_path));

        assert_eq!(from_cli.as_deref(), Some("198.51.100.10"));
        assert_eq!(from_env.as_deref(), Some("198.51.100.11"));
        assert_eq!(from_config.as_deref(), Some("10.20.30.40"));
    }

    #[test]
    fn ca_host_ignores_missing_or_placeholder_config_values() {
        let td = TempDir::new().expect("tempdir");
        let missing_path = td.path().join("missing.yaml");
        let placeholder_path = td.path().join("nodeA.yaml");
        fs::write(
            &placeholder_path,
            r#"
node_id: nodeA
hostname: nodeA.local
ip: 0.0.0.0
port: 8443
public_key: test-pubkey
"#,
        )
        .expect("write placeholder config");

        let host = resolve_ca_host_from_sources(
            None,
            None,
            &[
                PathBuf::from(&missing_path),
                PathBuf::from(&placeholder_path),
            ],
        );

        assert!(host.is_none());
        assert_eq!(
            CA_HOST_MISSING_MSG,
            "CA registry host is not configured; set SGX_CA_HOST or pass --ca-host."
        );
    }

    #[test]
    fn host_normalizers_distinguish_cli_values_from_config_placeholders() {
        assert_eq!(
            normalize_host(Some(" 0.0.0.0 ")).as_deref(),
            Some("0.0.0.0")
        );
        assert_eq!(
            normalize_host(Some(" 10.0.0.4 ")).as_deref(),
            Some("10.0.0.4")
        );
        assert!(normalize_host(Some("  ")).is_none());
        assert!(normalize_host(None).is_none());

        assert!(normalize_configured_host("0.0.0.0").is_none());
        assert!(normalize_configured_host("  ").is_none());
        assert_eq!(
            normalize_configured_host(" ca.local ").as_deref(),
            Some("ca.local")
        );
    }

    #[test]
    fn malformed_config_is_skipped_and_candidate_paths_are_node_specific() {
        let td = TempDir::new().expect("tempdir");
        let malformed = td.path().join("bad.yaml");
        fs::write(&malformed, "not: [valid").expect("malformed config");
        assert!(resolve_ca_host_from_sources(None, None, &[malformed]).is_none());

        let candidates = ca_host_config_candidates();
        assert!(candidates.len() >= 2);
        assert!(candidates.iter().all(|path| path.ends_with("nodeA.yaml")));
    }
}
