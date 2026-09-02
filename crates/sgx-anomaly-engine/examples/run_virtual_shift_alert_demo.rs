//! VS14 demonstration: create, protobuf-encode, decode-verify and persist a
//! signed VSHIFT_ALERT. It intentionally does not broadcast anything.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    vshift_alert_from_signed_policy, write_vshift_alert, ReviewQueue, SignedVirtualShiftPolicy,
    VShiftAlert,
};

fn flag(args: &[String], name: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))?
        .trim();
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(Some(value.to_owned()))
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn find_signed(root: &Path, recommendation_id: &str) -> Result<PathBuf> {
    if !root.is_dir() {
        anyhow::bail!(
            "no VS13 signed-policy directory exists at {}",
            root.display()
        );
    }
    let mut matches = Vec::new();
    for directory in std::fs::read_dir(root)? {
        let path = directory?.path().join("signed_policy.json");
        if !path.is_file() {
            continue;
        }
        let signed: SignedVirtualShiftPolicy =
            serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        if signed.policy.source_recommendation_id == recommendation_id {
            matches.push((signed.policy.policy_version, path));
        }
    }
    matches.sort_by(|left, right| right.0.cmp(&left.0));
    match matches.len() {
        1.. => Ok(matches.remove(0).1),
        0 => anyhow::bail!("no VS13 signed policy found for '{recommendation_id}'; run VS13 first"),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let recommendation_id = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_alert_demo -- <approved-recommendation-id> [--owner nodeA] [--ttl-seconds 300]"
    ))?;
    let owner = flag(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let ttl_seconds: u64 = flag(&args, "--ttl-seconds")?
        .unwrap_or_else(|| "300".into())
        .parse()?;
    if !(1..=3600).contains(&ttl_seconds) {
        anyhow::bail!("--ttl-seconds must be from 1 to 3600");
    }
    let queue = ReviewQueue::from_role_config(
        "data/virtual_shift/VS10_VS11_REVIEWS",
        "config/node_roles.json",
    )?;
    let review = queue.show(&owner, recommendation_id)?;
    let signed_path = find_signed(
        Path::new("data/virtual_shift/VS13_SIGNED_POLICIES"),
        recommendation_id,
    )?;
    let signed: SignedVirtualShiftPolicy =
        serde_json::from_str(&std::fs::read_to_string(&signed_path)?)?;
    let issued_at_ms = now_ms()?;
    let expires_at_ms = issued_at_ms
        .checked_add(ttl_seconds * 1000)
        .ok_or_else(|| anyhow::anyhow!("expiry overflow"))?;
    let alert_id = format!("vsa-{}-{issued_at_ms}", signed.policy.policy_id);
    let alert =
        vshift_alert_from_signed_policy(&review, &signed, alert_id, issued_at_ms, expires_at_ms)?;
    let wire_bytes = alert.encode()?;
    let decoded = VShiftAlert::decode(&wire_bytes)?;
    let (json_path, protobuf_path) =
        write_vshift_alert("data/virtual_shift/VS14_ALERTS", &decoded)?;

    println!("==========================================================================");
    println!("TASK 2 - VS14 VSHIFT_ALERT MESSAGE");
    println!("==========================================================================");
    println!("Alert ID                : {}", decoded.alert_id);
    println!("Circle ID               : {}", decoded.circle_id);
    println!("Policy version          : {}", decoded.policy_version);
    println!("Source recommendation   : {}", decoded.recommendation_id);
    println!("Source anomaly          : {}", decoded.anomaly_id);
    println!(
        "Guardian signer         : {} ({})",
        decoded.signer_id, decoded.signature_algorithm
    );
    println!("Policy hash             : {}", decoded.policy_hash_hex);
    println!(
        "Issued / expires (ms)   : {} / {}",
        decoded.issued_at_ms, decoded.expires_at_ms
    );
    println!(
        "Wire encode/decode      : VERIFIED ({} bytes)",
        wire_bytes.len()
    );
    println!("Alert JSON              : {}", json_path.display());
    println!("Alert protobuf bytes    : {}", protobuf_path.display());
    println!("Status                  : created_not_broadcast");
    println!("STOP: VS14 only creates the signed message. VS15 will broadcast it.");
    Ok(())
}
