use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use sgx_guardian_client::did::{self, DidError};

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

    match args.did {
        None => match did::method::resolve_local(did::DEFAULT_DID_PATH, dkp_pubkey_path) {
            Ok((resolved_did, pk, active)) => {
                let pk_hex = hex::encode(&pk);
                println!("DID:    {}", resolved_did.as_str());
                println!("Status: {}", if active { "ACTIVE" } else { "DEACTIVATED" });
                println!(
                    "Pubkey: {}... ({} bytes)",
                    &pk_hex[..pk_hex.len().min(32)],
                    pk.len()
                );
            }
            Err(e) => {
                eprintln!("❌ Resolve failed: {}", e);
                std::process::exit(1);
            }
        },
        Some(did_str) => {
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
                    return;
                }
            }

            match did::Did::parse(&did_str) {
                Ok(parsed) => match did::registry::get(did::registry::default_peers_dir(), &parsed)
                {
                    Ok(Some(peer)) => {
                        println!("Peer DID:    {}", peer.did);
                        println!("Node hint:   {}", peer.node_id);
                        println!("DKP version: v{}", peer.current_dkp_version);
                        println!("Last seen:   {}", peer.last_seen);
                        println!("Source:      {}", peer.source);
                    }
                    Ok(None) => {
                        eprintln!("❌ DID {} not found in local cache", did_str);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("❌ Cache error: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("❌ Bad DID format: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
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
            println!("✅ DID deactivated. Restart daemon to enforce runtime refusal.");
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
