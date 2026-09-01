use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use serde::Deserialize;

#[derive(Args)]
#[command(about = "VirtualID inspection and recomputation")]
pub struct VidArgs {
    #[command(subcommand)]
    pub command: VidCommand,
}

#[derive(Subcommand)]
pub enum VidCommand {
    /// Show the daemon-maintained current VirtualID session state.
    Show(VidShowArgs),
    /// Show cached VirtualIDs for known peers.
    Peers(VidPeersArgs),
    /// Manually recompute and display VID for given inputs.
    Recompute(VidRecomputeArgs),
}

#[derive(Args)]
pub struct VidShowArgs {
    #[arg(long, default_value = "nodeA")]
    pub node: String,
    #[arg(long, default_value = "http://127.0.0.1:8443")]
    pub api: String,
}

#[derive(Args)]
pub struct VidPeersArgs {
    #[arg(long, default_value = "http://127.0.0.1:8443")]
    pub api: String,
}

#[derive(Args)]
pub struct VidRecomputeArgs {
    #[arg(long)]
    pub did: String,
    #[arg(long)]
    pub dkp_pub_hex: String,
    #[arg(long)]
    pub pcr_digest_hex: String,
    #[arg(long)]
    pub policy_digest_hex: String,
    #[arg(long, default_value = "")]
    pub nonce_i_hex: String,
    #[arg(long, default_value = "")]
    pub nonce_r_hex: String,
}

#[derive(Debug, Deserialize)]
struct VidPeersResponse {
    peers: Vec<VidPeer>,
}

#[derive(Debug, Deserialize)]
struct VidShowResponse {
    node: String,
    did: String,
    #[serde(rename = "dkpBytes")]
    dkp_bytes: usize,
    #[serde(rename = "dkpVersion")]
    dkp_version: u32,
    #[serde(rename = "pcrDigest")]
    pcr_digest: String,
    #[serde(rename = "policyDigest")]
    policy_digest: String,
    #[serde(rename = "nonceI")]
    nonce_i: String,
    #[serde(rename = "nonceR")]
    nonce_r: String,
    #[serde(rename = "virtualId")]
    virtual_id: String,
    #[serde(rename = "changeReason")]
    change_reason: String,
    #[serde(rename = "sessionExpiresAt")]
    session_expires_at: String,
    #[serde(rename = "sessionTtl")]
    session_ttl: i64,
}

#[derive(Debug, Deserialize)]
struct VidPeer {
    did: String,
    #[serde(rename = "virtualId")]
    virtual_id: String,
    #[serde(rename = "observedAt")]
    observed_at: String,
    #[serde(rename = "lastRotationReason")]
    last_rotation_reason: Option<String>,
}

pub fn run(args: VidArgs) {
    let result = match args.command {
        VidCommand::Show(a) => cmd_show(a),
        VidCommand::Peers(a) => cmd_peers(a),
        VidCommand::Recompute(a) => cmd_recompute(a),
    };
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_show(args: VidShowArgs) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/vid/show?node={}",
        args.api.trim_end_matches('/'),
        args.node
    );
    let status: VidShowResponse = reqwest::blocking::get(url)?.error_for_status()?.json()?;

    let mut table = Table::new();
    table.set_header(vec!["Field", "Value"]);
    table.add_row(vec![Cell::new("Node"), Cell::new(status.node)]);
    table.add_row(vec![Cell::new("DID"), Cell::new(status.did)]);
    table.add_row(vec![Cell::new("DKP bytes"), Cell::new(status.dkp_bytes)]);
    table.add_row(vec![
        Cell::new("DKP version"),
        Cell::new(status.dkp_version),
    ]);
    table.add_row(vec![Cell::new("PCR digest"), Cell::new(status.pcr_digest)]);
    table.add_row(vec![
        Cell::new("Policy digest"),
        Cell::new(status.policy_digest),
    ]);
    table.add_row(vec![Cell::new("Nonce_I"), Cell::new(status.nonce_i)]);
    table.add_row(vec![Cell::new("Nonce_R"), Cell::new(status.nonce_r)]);
    table.add_row(vec![Cell::new("VirtualID"), Cell::new(status.virtual_id)]);
    table.add_row(vec![
        Cell::new("change_reason"),
        Cell::new(status.change_reason),
    ]);
    table.add_row(vec![
        Cell::new("session_expires_at"),
        Cell::new(status.session_expires_at),
    ]);
    table.add_row(vec![
        Cell::new("session_ttl"),
        Cell::new(status.session_ttl),
    ]);
    println!("{}", table);
    Ok(())
}

fn cmd_peers(args: VidPeersArgs) -> anyhow::Result<()> {
    let url = format!("{}/api/v1/vid/peers", args.api.trim_end_matches('/'));
    let resp: VidPeersResponse = reqwest::blocking::get(url)?.error_for_status()?.json()?;
    let mut table = Table::new();
    table.set_header(vec!["DID", "VirtualID", "Observed", "Rotation"]);
    for peer in resp.peers {
        table.add_row(vec![
            Cell::new(peer.did),
            Cell::new(peer.virtual_id),
            Cell::new(peer.observed_at),
            Cell::new(peer.last_rotation_reason.unwrap_or_else(|| "-".to_string())),
        ]);
    }
    println!("{}", table);
    Ok(())
}

fn cmd_recompute(args: VidRecomputeArgs) -> anyhow::Result<()> {
    let dkp_pub = sgx_guardian_client::virtual_id::canonical_dkp_pubkey_bytes(&hex::decode(
        args.dkp_pub_hex,
    )?);
    let pcr_digest = hex::decode(args.pcr_digest_hex)?;
    let policy_digest = hex::decode(args.policy_digest_hex)?;
    let nonce_i = hex::decode(args.nonce_i_hex)?;
    let nonce_r = hex::decode(args.nonce_r_hex)?;
    let vid = sgx_guardian_client::virtual_id::VirtualIdInputs {
        did: &args.did,
        dkp_pubkey_der: &dkp_pub,
        pcr_values: &pcr_digest,
        policy_digest: &policy_digest,
        nonce_i: &nonce_i,
        nonce_r: &nonce_r,
    }
    .compute();
    println!("{}", hex::encode(vid));
    Ok(())
}

#[cfg(test)]
fn read_policy_digest() -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(
        &sgx_guardian_client::policy::load_effective_policy_material().digest_hex,
    )?)
}

#[cfg(test)]
mod tests {
    use super::read_policy_digest;
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(v) = self.prev.take() {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn read_policy_digest_uses_effective_policy_material() {
        let td = tempdir().expect("create temp dir");
        let policies_dir = td.path().join("policies");
        fs::create_dir_all(&policies_dir).expect("create policies dir");
        let _policy_guard = EnvVarGuard::set("SGX_GUARDIAN_POLICY_DIR", &policies_dir);

        let active_yaml = r#"
policy_id: "active-policy"
version: "3.0.0"
rules:
  - id: "allow-dns"
    action: "ALLOW"
    src: "10.0.0.0/24"
    dst: "0.0.0.0/0"
    protocol: "UDP"
    port: 53
"#;
        fs::write(policies_dir.join("active_policy.yaml"), active_yaml)
            .expect("write active policy");

        let digest = read_policy_digest().expect("read policy digest");
        let parsed =
            sgx_guardian_client::policy::validate_policy(active_yaml).expect("parse active policy");

        assert_eq!(
            hex::encode(digest),
            sgx_guardian_client::policy::canonical_policy_digest(&parsed)
        );
    }

    // ── cmd_recompute: pure, no network ──────────────────────────────────

    #[test]
    fn cmd_recompute_computes_a_deterministic_vid_from_valid_hex_inputs() {
        super::cmd_recompute(super::VidRecomputeArgs {
            did: "did:guardian:test".to_string(),
            dkp_pub_hex: "04".to_string() + &"11".repeat(64),
            pcr_digest_hex: "22".repeat(32),
            policy_digest_hex: "33".repeat(32),
            nonce_i_hex: "44".repeat(16),
            nonce_r_hex: "55".repeat(16),
        })
        .expect("well-formed hex inputs must compute a VID");
    }

    #[test]
    fn cmd_recompute_rejects_invalid_hex() {
        super::cmd_recompute(super::VidRecomputeArgs {
            did: "did:guardian:test".to_string(),
            dkp_pub_hex: "not-hex".to_string(),
            pcr_digest_hex: "22".repeat(32),
            policy_digest_hex: "33".repeat(32),
            nonce_i_hex: String::new(),
            nonce_r_hex: String::new(),
        })
        .expect_err("invalid hex must fail");
    }

    // ── cmd_show / cmd_peers: real reqwest calls against a port nothing listens on, so
    // the connection is refused immediately — no real network dependency, no hang risk.

    #[test]
    fn cmd_show_fails_fast_when_the_api_is_unreachable() {
        let result = super::cmd_show(super::VidShowArgs {
            node: "nodeA".to_string(),
            api: "http://127.0.0.1:1".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn cmd_peers_fails_fast_when_the_api_is_unreachable() {
        let result = super::cmd_peers(super::VidPeersArgs {
            api: "http://127.0.0.1:1".to_string(),
        });
        assert!(result.is_err());
    }
}
