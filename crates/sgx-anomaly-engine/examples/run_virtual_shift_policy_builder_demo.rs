//! VS12 demonstration: turn one VS11-approved review into a versioned policy
//! candidate. The active policy is read only; VS13 will sign this candidate.
//!
//! Run after `run_virtual_shift_owner_decision_demo ... approve`:
//! cargo run --example run_virtual_shift_policy_builder_demo -- <recommendation-id>

use std::path::Path;

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    build_candidate_from_approved_review, canonical_policy_bytes, sha256_hex,
    write_built_candidate, ActiveVirtualShiftPolicy, MemberVerificationState, ReviewQueue,
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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let recommendation_id = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_policy_builder_demo -- <recommendation-id> [--owner nodeA] [--member nodeA] [--active-policy config/active_virtual_shift_policy.json]"
    ))?;
    let owner = flag(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let member = flag(&args, "--member")?;
    let active_path = flag(&args, "--active-policy")?
        .unwrap_or_else(|| "config/active_virtual_shift_policy.json".into());

    let queue = ReviewQueue::from_role_config(
        "data/virtual_shift/VS10_VS11_REVIEWS",
        "config/node_roles.json",
    )?;
    let review = queue.show(&owner, recommendation_id)?;
    let active_before = std::fs::read(&active_path)?;
    let member_active = member.as_ref().map(|member_id| {
        let member_root = Path::new("data")
            .join("virtual_shift")
            .join("VS17_MEMBER_POLICY_STATE")
            .join(member_id);
        let canonical = member_root.join("policies").join("active_policy.json");
        if canonical.is_file() {
            canonical
        } else {
            member_root.join("active_policy.json")
        }
    });
    let active = match &member_active {
        Some(path) if path.is_file() => ActiveVirtualShiftPolicy::from_path(path)?,
        _ => ActiveVirtualShiftPolicy::from_path(&active_path)?,
    };
    let mut built = build_candidate_from_approved_review(&active, &review)?;

    // Individual demos can be rerun against a member that already accepted a
    // previous policy.  Its next candidate must be newer than both its local
    // active policy and any version already verified by VS16.
    if let Some(member_id) = &member {
        let verification_path = Path::new("data")
            .join("virtual_shift")
            .join("VS16_MEMBER_VERIFICATION")
            .join(member_id)
            .join("verification_state.json");
        let latest_verified = std::fs::read_to_string(verification_path)
            .ok()
            .and_then(|text| serde_json::from_str::<MemberVerificationState>(&text).ok())
            .map(|state| state.latest_verified_policy_version)
            .unwrap_or(0);
        if built.candidate.policy_version <= latest_verified {
            let next_version = latest_verified
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("policy version overflow"))?;
            // `parent_policy_version` means the member's actually ACTIVE
            // policy. A newer alert may have passed VS16 but not reached VS17
            // yet, so it must not become the parent of a later candidate.
            // Only the candidate version skips past verified-but-unapplied
            // versions to satisfy VS16's anti-stale check.
            built.candidate.policy_version = next_version;
            built.candidate.policy_id = format!(
                "vshift-{}-v{}-{}",
                built.candidate.circle_id, next_version, built.candidate.source_recommendation_id
            );
            built.candidate.canonical_sha256.clear();
            built.canonical_bytes = canonical_policy_bytes(&built.candidate)?;
            built.candidate.canonical_sha256 = sha256_hex(&built.canonical_bytes);
        }
    }
    let candidate_path = write_built_candidate("data/virtual_shift/VS12_CANDIDATES", &built)?;
    let active_unchanged = std::fs::read(&active_path)? == active_before;

    println!("==========================================================================");
    println!("TASK 2 - VS12 VERSIONED POLICY CANDIDATE");
    println!("==========================================================================");
    println!("Approved recommendation : {}", review.recommendation_id);
    println!("Source anomaly          : {}", review.anomaly_id);
    println!("Review owner            : {owner}");
    println!(
        "Receiving member        : {}",
        member.as_deref().unwrap_or("configured baseline only")
    );
    println!("Active Circle           : {}", active.circle_id);
    println!(
        "Active policy version   : {} (read only)",
        active.policy_version
    );
    println!("Candidate policy ID     : {}", built.candidate.policy_id);
    println!(
        "Candidate version       : {}",
        built.candidate.policy_version
    );
    println!(
        "Parent policy version   : {}",
        built.candidate.parent_policy_version
    );
    println!(
        "Final VS8 actions       : {}",
        built.candidate.actions.len()
    );
    println!(
        "Canonical SHA-256       : {}",
        built.candidate.canonical_sha256
    );
    println!("Candidate JSON          : {}", candidate_path.display());
    println!(
        "Canonical bytes         : {}",
        candidate_path
            .parent()
            .expect("candidate has parent")
            .join("canonical_policy.json")
            .display()
    );
    println!(
        "Active policy unchanged : {}",
        if active_unchanged {
            "YES"
        } else {
            "NO - ERROR"
        }
    );
    println!("Status                  : candidate_not_signed");
    println!("STOP: VS12 only builds and hashes a candidate. VS13 signing is next.");
    Ok(())
}
