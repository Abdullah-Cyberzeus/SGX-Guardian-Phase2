use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use serde::Deserialize;
use std::fs;

#[derive(Args)]
#[command(about = "VirtualID inspection and recomputation")]
pub struct VidArgs {
    #[command(subcommand)]
    pub command: VidCommand,
}

#[derive(Subcommand)]
pub enum VidCommand {
    /// Show the VirtualID this node would currently produce.
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
    let did = sgx_guardian_client::did::DidRecord::load(sgx_guardian_client::did::DEFAULT_DID_PATH)
        .map(|r| r.did)
        .unwrap_or_default();
    let dkp_pub = fs::read("/var/lib/sgx-guardian/keys/dkp_pub.der")
        .or_else(|_| {
            fs::read(format!(
                "/var/lib/sgx-guardian/sgx-agent/device_{}.key",
                args.node
            ))
        })
        .unwrap_or_default();
    let pcr_digest = read_current_pcr_digest(&args.node).unwrap_or_default();
    let (policy_digest, policy_source) = read_policy_digest()?;
    let vid = sgx_guardian_client::virtual_id::VirtualIdInputs {
        did: &did,
        dkp_pubkey_der: &dkp_pub,
        pcr_composite_digest: &pcr_digest,
        policy_digest: &policy_digest,
        nonce_i: &[],
        nonce_r: &[],
    }
    .compute();

    let mut table = Table::new();
    table.set_header(vec!["Field", "Value"]);
    table.add_row(vec![Cell::new("DID"), Cell::new(did)]);
    table.add_row(vec![Cell::new("DKP bytes"), Cell::new(dkp_pub.len())]);
    table.add_row(vec![
        Cell::new("PCR digest"),
        Cell::new(hex::encode(&pcr_digest)),
    ]);
    table.add_row(vec![Cell::new("Policy source"), Cell::new(policy_source)]);
    table.add_row(vec![
        Cell::new("Policy digest"),
        Cell::new(hex::encode(&policy_digest)),
    ]);
    table.add_row(vec![Cell::new("VirtualID"), Cell::new(hex::encode(vid))]);
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
    let dkp_pub = hex::decode(args.dkp_pub_hex)?;
    let pcr_digest = hex::decode(args.pcr_digest_hex)?;
    let policy_digest = hex::decode(args.policy_digest_hex)?;
    let nonce_i = hex::decode(args.nonce_i_hex)?;
    let nonce_r = hex::decode(args.nonce_r_hex)?;
    let vid = sgx_guardian_client::virtual_id::VirtualIdInputs {
        did: &args.did,
        dkp_pubkey_der: &dkp_pub,
        pcr_composite_digest: &pcr_digest,
        policy_digest: &policy_digest,
        nonce_i: &nonce_i,
        nonce_r: &nonce_r,
    }
    .compute();
    println!("{}", hex::encode(vid));
    Ok(())
}

fn read_current_pcr_digest(node: &str) -> Option<Vec<u8>> {
    let path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node);
    let text = fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value
        .get("composite_digest")
        .and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s).ok())
}

fn read_policy_digest() -> anyhow::Result<(Vec<u8>, &'static str)> {
    let material = sgx_guardian_client::policy::load_effective_policy_material();
    let digest = hex::decode(&material.digest_hex)?;
    Ok((digest, material.source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
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
    fn read_policy_digest_prefers_active_policy_file() {
        let td = tempdir().expect("create temp dir");
        let policies_dir = td.path().join("policies");
        fs::create_dir_all(&policies_dir).expect("create policies dir");
        let _guard = EnvVarGuard::set("SGX_GUARDIAN_POLICY_DIR", &policies_dir);

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

        let (digest, source) = read_policy_digest().expect("read policy digest");
        let parsed =
            sgx_guardian_client::policy::validate_policy(active_yaml).expect("parse active policy");

        assert_eq!(source, "active-policy-file");
        assert_eq!(
            hex::encode(digest),
            sgx_guardian_client::policy::canonical_policy_digest(&parsed)
        );
    }
}
