use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use sgx_guardian_client::did::ResolverConfig;
use sgx_guardian_client::vc::credential::{CredentialRole, VerifiableCredential};
use sgx_guardian_client::vc::issue::{
    self, default_permissions_for_role, load_runtime_key_manager, IssueMembershipOutcome,
    IssueRequest, RenewRequest,
};
use sgx_guardian_client::vc::{persistence, status_list, verify};
use std::path::PathBuf;

const CA_HOST_ENV: &str = "SGX_CA_HOST";

#[derive(Args)]
#[command(about = "Verifiable Credential operations")]
pub struct VcArgs {
    #[command(subcommand)]
    pub command: VcCommand,
}

#[derive(Subcommand)]
pub enum VcCommand {
    Issue {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "member")]
        role: String,
        #[arg(long)]
        permissions: Option<String>,
        #[arg(long)]
        days: Option<i64>,
    },
    Show,
    Verify {
        #[arg(long)]
        path: String,
    },
    Revoke {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "policy violation")]
        reason: String,
    },
    Renew {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        days: i64,
        #[arg(long, default_value_t = false)]
        allow_expired: bool,
    },
    Status {
        #[arg(long)]
        id: String,
    },
    PullStatusList,
}

pub fn run(args: VcArgs) {
    match args.command {
        VcCommand::Issue {
            to,
            role,
            permissions,
            days,
        } => cmd_issue(&to, &role, permissions.as_deref(), days),
        VcCommand::Show => cmd_show(),
        VcCommand::Verify { path } => cmd_verify(&path),
        VcCommand::Revoke { id, reason } => cmd_revoke(&id, &reason),
        VcCommand::Renew {
            id,
            to,
            days,
            allow_expired,
        } => cmd_renew(id.as_deref(), to.as_deref(), days, allow_expired),
        VcCommand::Status { id } => cmd_status(&id),
        VcCommand::PullStatusList => cmd_pull_status_list(),
    }
}

fn cmd_issue(to: &str, role: &str, permissions: Option<&str>, days: Option<i64>) {
    let role = match parse_role(role) {
        Ok(role) => role,
        Err(message) => {
            eprintln!("❌ {}", message);
            std::process::exit(1);
        }
    };
    let (issuer, km) = load_runtime_issuer_and_km();
    let perms = permissions
        .map(parse_permissions)
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        })
        .unwrap_or_else(|| default_permissions_for_role(role.clone()));

    match issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: to,
            role,
            permissions: perms,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: None,
            duration_days: days,
        },
    ) {
        Ok(IssueMembershipOutcome::ReusedExisting { vc }) => {
            print_vc_table("Existing active VC found — no changes made", &[vc])
        }
        Ok(IssueMembershipOutcome::IssuedNew {
            vc,
            replaced_expired: true,
        }) => print_vc_table("Existing VC expired — issued new VC", &[vc]),
        Ok(IssueMembershipOutcome::IssuedNew { vc, .. }) => print_vc_table("Issued new VC", &[vc]),
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_show() {
    match persistence::list_own() {
        Ok(vcs) if vcs.is_empty() => println!("No local VCs found."),
        Ok(vcs) => print_vc_table("Local VCs", &vcs),
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_verify(path: &str) {
    let vc = match std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<VerifiableCredential>(&bytes).ok())
    {
        Some(vc) => vc,
        None => {
            eprintln!("❌ Could not load VC from {}", path);
            std::process::exit(1);
        }
    };
    let resolver = sgx_guardian_client::did::Resolver::new(ResolverConfig {
        ca_host: resolve_ca_host().unwrap_or_default(),
        ..Default::default()
    });
    let expected_issuer = issue::known_ca_did().ok();
    let status_list = load_verified_status_list(&resolver, expected_issuer.as_deref());
    if status_list.is_none() {
        eprintln!("❌ VC status list is unavailable or unverifiable");
        eprintln!("   Cannot verify revocation status — failing closed");
        std::process::exit(1);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("vc verify runtime");

    let result = rt.block_on(async {
        verify::verify_vc(
            &vc,
            &resolver,
            verify::VerifyOptions {
                expected_subject_did: None,
                expected_circle_id: Some(issue::DEFAULT_CIRCLE_ID),
                expected_issuer_did: expected_issuer.as_deref(),
                check_status_list: status_list.is_some(),
                status_list: status_list.as_ref(),
            },
        )
        .await
    });

    match result {
        Ok(()) => println!("✅ VC verified: {}", vc.id),
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_revoke(id: &str, reason: &str) {
    let (issuer, km) = load_runtime_issuer_and_km();
    let node_id = issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
    match issue::revoke_vc(&issuer, &km, id, reason, &node_id) {
        Ok(()) => println!("✅ Revoked VC {}", id),
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_renew(id: Option<&str>, to: Option<&str>, days: i64, allow_expired: bool) {
    if days <= 0 {
        eprintln!("❌ renewal days must be greater than zero");
        std::process::exit(1);
    }
    if (id.is_some() && to.is_some()) || (id.is_none() && to.is_none()) {
        eprintln!("❌ specify exactly one of --id or --to");
        std::process::exit(1);
    }

    let (issuer, km) = load_runtime_issuer_and_km();
    let node_id = issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
    match issue::renew_membership_vc(
        &issuer,
        &km,
        RenewRequest {
            vc_id: id,
            subject_did: to,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            duration_days: days,
            allow_expired,
        },
        &node_id,
    ) {
        Ok(vc) => print_vc_table("Renewed VC", &[vc]),
        Err(sgx_guardian_client::vc::VcError::CannotRenewRevokedVc) => {
            eprintln!("❌ Cannot renew revoked VC");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_status(id: &str) {
    let vc = match persistence::find_vc_by_id(id) {
        Ok(Some(vc)) => vc,
        Ok(None) => {
            eprintln!("❌ VC not found: {}", id);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    };
    let resolver = sgx_guardian_client::did::Resolver::new(ResolverConfig {
        ca_host: resolve_ca_host().unwrap_or_default(),
        ..Default::default()
    });
    let expected_issuer = issue::known_ca_did().ok();
    let status_list = load_verified_status_list(&resolver, expected_issuer.as_deref());
    let revoked = status_list
        .as_ref()
        .and_then(|view| {
            vc.credential_status
                .status_list_index
                .parse::<u64>()
                .ok()
                .and_then(|idx| view.is_revoked(idx).ok())
        })
        .unwrap_or(false);

    let mut table = Table::new();
    table.set_header(vec!["Field", "Value"]);
    table.add_row(vec![Cell::new("VC ID"), Cell::new(&vc.id)]);
    table.add_row(vec![Cell::new("Subject"), Cell::new(vc.subject_did())]);
    table.add_row(vec![Cell::new("Issuer"), Cell::new(vc.issuer_did())]);
    table.add_row(vec![
        Cell::new("Revoked"),
        Cell::new(if revoked { "true" } else { "false" }),
    ]);
    println!("{}", table);
}

fn cmd_pull_status_list() {
    let ca_host = match resolve_ca_host() {
        Some(host) => host,
        None => {
            eprintln!("❌ CA host is not configured; set SGX_CA_HOST.");
            std::process::exit(1);
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("status-list runtime");
    match rt
        .block_on(async { sgx_guardian_client::vc::distribution::pull_status_list(&ca_host).await })
    {
        Ok(true) => println!("✅ Pulled VC status list from {}", ca_host),
        Ok(false) => println!("No VC status list update."),
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}

fn print_vc_table(title: &str, vcs: &[VerifiableCredential]) {
    let mut table = Table::new();
    table.set_header(vec!["VC ID", "Subject", "Role", "Expires"]);
    for vc in vcs {
        table.add_row(vec![
            Cell::new(&vc.id),
            Cell::new(vc.subject_did()),
            Cell::new(match vc.credential_subject.role {
                CredentialRole::Owner => "owner",
                CredentialRole::Member => "member",
            }),
            Cell::new(&vc.expiration_date),
        ]);
    }
    println!("{}\n{}", title, table);
}

fn parse_role(raw: &str) -> Result<CredentialRole, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "owner" => Ok(CredentialRole::Owner),
        "member" => Ok(CredentialRole::Member),
        other => Err(format!("unsupported role '{}'", other)),
    }
}

fn parse_permissions(raw: &str) -> Result<Vec<String>, String> {
    let permissions = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if permissions.is_empty() {
        return Err("permissions list must not be empty".to_string());
    }
    Ok(permissions)
}

fn load_runtime_issuer_and_km() -> (
    sgx_guardian_client::did::DidRecord,
    std::sync::Arc<sgx_guardian_client::key_manager::KeyManager>,
) {
    let node_id = issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
    let issuer =
        match sgx_guardian_client::did::DidRecord::load(sgx_guardian_client::did::DEFAULT_DID_PATH)
        {
            Ok(issuer) => issuer,
            Err(e) => {
                eprintln!("❌ Load issuer DID failed: {}", e);
                std::process::exit(1);
            }
        };
    let km = match load_runtime_key_manager(&node_id) {
        Ok(km) => km,
        Err(e) => {
            eprintln!("❌ Load key manager failed: {}", e);
            std::process::exit(1);
        }
    };
    (issuer, km)
}

fn resolve_ca_host() -> Option<String> {
    std::env::var(CA_HOST_ENV)
        .ok()
        .filter(|host| !host.trim().is_empty() && host != "0.0.0.0")
        .or_else(|| {
            for path in ca_host_config_candidates() {
                if let Ok(cfg) = sgx_guardian_client::config_loader::load_config(path.to_str()?) {
                    if !cfg.ip.trim().is_empty() && cfg.ip != "0.0.0.0" {
                        return Some(cfg.ip);
                    }
                }
            }
            None
        })
}

fn ca_host_config_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/sgx-guardian/config/nodeA.yaml"),
        PathBuf::from("/etc/sgx-guardian/nodeA.yaml"),
        PathBuf::from("config/nodeA.yaml"),
    ]
}

fn load_verified_status_list(
    resolver: &sgx_guardian_client::did::Resolver,
    expected_issuer: Option<&str>,
) -> Option<status_list::StatusListView> {
    let credential = persistence::load_status_list_credential().ok()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        status_list::verify_status_list_credential(&credential, resolver, expected_issuer)
            .await
            .ok()
    })
}
