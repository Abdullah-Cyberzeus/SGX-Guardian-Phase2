use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use serde_json::json;
use sgx_guardian_client::crl::entry::{RevocationEvidence, RevocationReason, Severity};
use sgx_guardian_client::crl::{
    self, issue, persistence, verify, CertificateRevocationList, CrlEntry,
};
use sgx_guardian_client::did::Resolver;
use sgx_guardian_client::did::ResolverConfig;

const CA_HOST_ENV: &str = "SGX_CA_HOST";
const SKIP_EMERGENCY_BROADCAST_ENV: &str = "SGX_CRL_SKIP_EMERGENCY_BROADCAST";

#[derive(Args)]
#[command(about = "Certificate Revocation List operations")]
pub struct CrlArgs {
    #[command(subcommand)]
    pub command: CrlCommand,
}

#[derive(Subcommand)]
pub enum CrlCommand {
    /// Revoke a peer DID. By default uses this node's current role.
    Revoke {
        #[arg(long)]
        did: String,
        #[arg(long, default_value = "compromised")]
        reason: String,
        #[arg(long, default_value = "critical")]
        severity: String,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Reverse a mistaken revocation (Circle Owner only).
    Unrevoke {
        #[arg(long)]
        did: String,
    },
    /// Show the CRL contents.
    List,
    /// Show one entry by id.
    Show {
        #[arg(long)]
        id: String,
    },
    /// Check if a DID is revoked.
    Check {
        #[arg(long)]
        did: String,
    },
    /// Verify the local CRL against the resolver and the entry signatures.
    Verify,
    /// Print the current Merkle root (for anti-entropy diagnostics).
    Root,
}

pub fn run(args: CrlArgs) {
    match args.command {
        CrlCommand::Revoke {
            did,
            reason,
            severity,
            device_id,
            user_id,
            note,
        } => cmd_revoke(&did, &reason, &severity, device_id, user_id, note),
        CrlCommand::Unrevoke { did } => cmd_unrevoke(&did),
        CrlCommand::List => cmd_list(),
        CrlCommand::Show { id } => cmd_show(&id),
        CrlCommand::Check { did } => cmd_check(&did),
        CrlCommand::Verify => cmd_verify(),
        CrlCommand::Root => cmd_root(),
    }
}

fn cmd_revoke(
    did: &str,
    reason: &str,
    severity: &str,
    device_id: Option<String>,
    user_id: Option<String>,
    note: Option<String>,
) {
    if did.trim().is_empty() {
        eprintln!("❌ did must not be empty");
        std::process::exit(1);
    }
    let reason = match parse_reason(reason) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("❌ {}", message);
            std::process::exit(1);
        }
    };
    let severity = match parse_severity(severity) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("❌ {}", message);
            std::process::exit(1);
        }
    };

    let (revoker, km) = match issue::load_runtime_signing_context() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    };
    let circle_id =
        issue::current_circle_id().unwrap_or_else(|_| issue::DEFAULT_CIRCLE_ID.to_string());
    let (_, revoker_role) = match issue::local_revocation_context(&revoker) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    };
    let evidence = note.map(|note| RevocationEvidence {
        note: Some(note),
        audit_ref: None,
        attestation_ref: None,
        evidence_digest: None,
    });

    match issue::issue_revocation(
        &revoker,
        revoker_role,
        &km,
        issue::IssueRequest {
            revoked_did: did,
            reason,
            severity,
            circle_id: &circle_id,
            device_id,
            user_id,
            evidence,
        },
    ) {
        Ok(entry) => {
            let crl = persistence::load_crl().ok().flatten();
            if let Some(crl) = crl {
                println!(
                    "✅ CRL entry issued: {} (sequence={}, root={})",
                    entry.id, crl.sequence, crl.merkle_root
                );
            } else {
                println!("✅ CRL entry issued: {}", entry.id);
            }
            // Emergency Revocation: critical entries fire the priority UDP
            // broadcast immediately (bypasses routine gossip intervals).
            if matches!(
                entry.severity,
                sgx_guardian_client::crl::entry::Severity::Critical
            ) && std::env::var(SKIP_EMERGENCY_BROADCAST_ENV).ok().as_deref() != Some("1")
            {
                let node_id = sgx_guardian_client::vc::issue::resolve_runtime_node_id()
                    .unwrap_or_else(|| "nodeA".to_string());
                // sgx-pa-cli is a short-lived process; run the fire-and-forget
                // broadcast to completion on a tiny current-thread runtime so the
                // datagrams actually leave before the CLI exits.
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        sgx_guardian_client::crl::gossip::emergency::broadcast_for_entry(
                            node_id,
                            entry.clone(),
                        );
                        // Give the spawned send task a moment to flush datagrams.
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    });
                }
            }
        }
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    }
}

fn cmd_unrevoke(did: &str) {
    if did.trim().is_empty() {
        eprintln!("❌ did must not be empty");
        std::process::exit(1);
    }

    let (revoker, km) = match issue::load_runtime_signing_context() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    };
    let (_, revoker_role) = match issue::local_revocation_context(&revoker) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    };

    match issue::unrevoke_revocation(&revoker, revoker_role, &km, did) {
        Ok(entry) => {
            let crl = persistence::load_crl().ok().flatten();
            if let Some(crl) = crl {
                println!(
                    "✅ CRL entry unrevoked: {} (sequence={}, root={})",
                    entry.id, crl.sequence, crl.merkle_root
                );
            } else {
                println!("✅ CRL entry unrevoked: {}", entry.id);
            }
        }
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    }
}

fn cmd_list() {
    match persistence::load_crl() {
        Ok(Some(crl)) if crl.entries.is_empty() => println!("No CRL entries found."),
        Ok(Some(crl)) => print_list(&crl),
        Ok(None) => println!("No CRL entries found."),
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    }
}

fn cmd_show(id: &str) {
    let Some(entry) = load_entry_by_id(id) else {
        eprintln!("❌ CRL entry not found: {}", id);
        std::process::exit(1);
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&entry).expect("serialize crl entry")
    );
}

fn cmd_check(did: &str) {
    let revoked = crl::is_revoked(did);
    let entry = if revoked {
        load_entry_by_did(did)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "did": did,
            "revoked": revoked,
            "entry": entry,
        }))
        .expect("serialize crl check")
    );
}

fn cmd_verify() {
    let resolver = Resolver::new(ResolverConfig {
        ca_host: resolve_ca_host().unwrap_or_default(),
        ..Default::default()
    });
    let circle_id =
        issue::current_circle_id().unwrap_or_else(|_| issue::DEFAULT_CIRCLE_ID.to_string());
    let crl = match persistence::load_crl() {
        Ok(Some(crl)) => crl,
        Ok(None) => {
            eprintln!("❌ CRL not found.");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("crl verify runtime");
    let result = runtime.block_on(async { verify::verify_list(&crl, &resolver, &circle_id).await });

    match result {
        Ok(()) => println!("✅ CRL verified"),
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    }
}

fn cmd_root() {
    match persistence::load_crl() {
        Ok(Some(crl)) => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "sequence": crl.sequence,
                "merkle_root": crl.merkle_root,
            }))
            .expect("serialize crl root")
        ),
        Ok(None) => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "sequence": 0u64,
                "merkle_root": "",
            }))
            .expect("serialize crl root")
        ),
        Err(error) => {
            eprintln!("❌ {}", error);
            std::process::exit(1);
        }
    }
}

fn print_list(crl: &CertificateRevocationList) {
    let mut table = Table::new();
    table.set_header(vec![
        "Entry ID",
        "Revoked DID",
        "Reason",
        "Severity",
        "Revoker",
        "Timestamp",
    ]);
    for entry in &crl.entries {
        table.add_row(vec![
            Cell::new(&entry.id),
            Cell::new(&entry.revoked_did),
            Cell::new(entry.reason.as_str()),
            Cell::new(entry.severity.as_str()),
            Cell::new(&entry.revoker_did),
            Cell::new(&entry.timestamp),
        ]);
    }
    println!("CRL Entries ({} total)\n{}", crl.entries.len(), table);
}

fn load_entry_by_id(id: &str) -> Option<CrlEntry> {
    persistence::load_crl()
        .ok()
        .flatten()
        .and_then(|crl| crl.entries.into_iter().find(|entry| entry.id == id))
}

fn load_entry_by_did(did: &str) -> Option<CrlEntry> {
    persistence::load_crl().ok().flatten().and_then(|crl| {
        crl.entries
            .into_iter()
            .find(|entry| entry.revoked_did == did)
    })
}

fn resolve_ca_host() -> Option<String> {
    std::env::var(CA_HOST_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_reason(raw: &str) -> Result<RevocationReason, String> {
    match normalize_token(raw).as_str() {
        "compromised" => Ok(RevocationReason::Compromised),
        "lost" => Ok(RevocationReason::Lost),
        "stolen" => Ok(RevocationReason::Stolen),
        "policy_violation" => Ok(RevocationReason::PolicyViolation),
        "administrative_removal" => Ok(RevocationReason::AdministrativeRemoval),
        "voluntary_departure" => Ok(RevocationReason::VoluntaryDeparture),
        other => Err(format!("unsupported revocation reason '{}'", other)),
    }
}

fn parse_severity(raw: &str) -> Result<Severity, String> {
    match normalize_token(raw).as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        other => Err(format!("unsupported severity '{}'", other)),
    }
}

fn normalize_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[cfg(test)]
mod tests {
    use super::{normalize_token, parse_reason, parse_severity};
    use sgx_guardian_client::crl::entry::{RevocationReason, Severity};

    #[test]
    fn normalize_token_converts_spaces_and_dashes() {
        assert_eq!(normalize_token("Policy Violation"), "policy_violation");
        assert_eq!(
            normalize_token("administrative-removal"),
            "administrative_removal"
        );
    }

    #[test]
    fn parse_reason_maps_known_values() {
        let cases = [
            ("compromised", RevocationReason::Compromised),
            ("lost", RevocationReason::Lost),
            ("stolen", RevocationReason::Stolen),
            ("Policy Violation", RevocationReason::PolicyViolation),
            (
                "administrative-removal",
                RevocationReason::AdministrativeRemoval,
            ),
            ("voluntary departure", RevocationReason::VoluntaryDeparture),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                parse_reason(raw).expect("known reason").as_str(),
                expected.as_str()
            );
        }
        assert_eq!(
            parse_reason("unknown-reason").unwrap_err(),
            "unsupported revocation reason 'unknown_reason'"
        );
    }

    #[test]
    fn parse_severity_maps_known_values() {
        for (raw, expected) in [
            ("critical", Severity::Critical),
            ("High", Severity::High),
            (" medium ", Severity::Medium),
            ("LOW", Severity::Low),
        ] {
            assert_eq!(
                parse_severity(raw).expect("known severity").as_str(),
                expected.as_str()
            );
        }
        assert_eq!(
            parse_severity("bogus").unwrap_err(),
            "unsupported severity 'bogus'"
        );
    }

    #[test]
    fn normalize_token_handles_whitespace_case_and_repeated_separators() {
        assert_eq!(
            normalize_token("  VOLUNTARY  Departure "),
            "voluntary__departure"
        );
        assert_eq!(normalize_token("HIGH"), "high");
        assert_eq!(normalize_token(""), "");
    }

    #[test]
    fn parse_reason_rejects_empty_string() {
        assert_eq!(
            parse_reason("").unwrap_err(),
            "unsupported revocation reason ''"
        );
    }

    #[test]
    fn parse_severity_rejects_empty_string() {
        assert_eq!(parse_severity("").unwrap_err(), "unsupported severity ''");
    }
}
