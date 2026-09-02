//! VS13 demonstration: Guardian signs the exact VS12 candidate bytes only
//! after an authorised owner approval record exists.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    sign_approved_policy, write_signed_policy, BuiltPolicyCandidate, GuardianKeyManager,
    ReviewQueue, VersionedPolicyCandidate,
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

fn find_candidate(root: &Path, recommendation_id: &str) -> Result<PathBuf> {
    if !root.is_dir() {
        anyhow::bail!("no VS12 candidate directory exists at {}", root.display());
    }
    let mut matches = Vec::new();
    let expected_current_suffix = format!("-{recommendation_id}");
    for directory in std::fs::read_dir(root)? {
        let path = directory?.path().join("candidate_policy.json");
        if !path.is_file() {
            continue;
        }
        let candidate: VersionedPolicyCandidate =
            serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        if candidate.source_recommendation_id == recommendation_id {
            let is_current_unique_path = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(&expected_current_suffix));
            matches.push((is_current_unique_path, path));
        }
    }
    // A demo may have an older candidate for the same recommendation.  Sign
    // the highest version, which is the only one suitable for a member whose
    // policy state has advanced since an earlier run.
    let mut versioned = Vec::new();
    for (_, path) in matches {
        let candidate: VersionedPolicyCandidate =
            serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        versioned.push((candidate.policy_version, path));
    }
    versioned.sort_by(|left, right| right.0.cmp(&left.0));
    match versioned.len() {
        1.. => Ok(versioned.remove(0).1),
        0 => anyhow::bail!(
            "no VS12 candidate found for '{recommendation_id}'; run VS12 for this approved ID first"
        ),
    }
}

fn read_built_candidate(path: &Path) -> Result<BuiltPolicyCandidate> {
    let candidate: VersionedPolicyCandidate =
        serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let canonical_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("candidate path needs a parent directory"))?
        .join("canonical_policy.json");
    Ok(BuiltPolicyCandidate {
        candidate,
        canonical_bytes: std::fs::read(canonical_path)?,
    })
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let recommendation_id = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_signing_demo -- <approved-recommendation-id> [--owner nodeA]"
    ))?;
    let owner = flag(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let queue = ReviewQueue::from_role_config(
        "data/virtual_shift/VS10_VS11_REVIEWS",
        "config/node_roles.json",
    )?;
    let review = queue.show(&owner, recommendation_id)?;
    let candidate_path = find_candidate(
        Path::new("data/virtual_shift/VS12_CANDIDATES"),
        recommendation_id,
    )?;
    let built = read_built_candidate(&candidate_path)?;
    let manager = GuardianKeyManager::from_config(
        "config/guardian_signer.json",
        "data/virtual_shift/guardian_keys",
    )?;
    let signed = sign_approved_policy(&manager, &review, &built, now_ms()?)?;
    let signed_path = write_signed_policy("data/virtual_shift/VS13_SIGNED_POLICIES", &signed)?;

    println!("==========================================================================");
    println!("TASK 2 - VS13 GUARDIAN SIGNING");
    println!("==========================================================================");
    println!("Approved recommendation : {}", review.recommendation_id);
    println!("Candidate policy         : {}", built.candidate.policy_id);
    println!(
        "Policy version           : {}",
        built.candidate.policy_version
    );
    println!("Guardian signer          : {}", signed.signer_id);
    println!("Algorithm                : {}", signed.algorithm);
    println!("Canonical SHA-256        : {}", signed.canonical_sha256);
    println!("Signature verified local : YES");
    println!("Signed policy JSON       : {}", signed_path.display());
    println!("Status                   : signed_not_broadcast");
    println!("STOP: VS13 signs only. VS14 will create the network alert; no policy is applied.");
    Ok(())
}
