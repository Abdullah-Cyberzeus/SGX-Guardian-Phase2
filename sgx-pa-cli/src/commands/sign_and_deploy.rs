//! `sgx-pa-cli policy-sign-and-deploy <yaml>`
//!
//! Runs ON nodeA. Signs the supplied policy YAML with the node-local PA key
//! and atomically writes /etc/sgx-guardian/policies/policy.sig +
//! /etc/sgx-guardian/policies/pa_admin_pub.der.
//!
//! No `scp` step needed — the daemon's cert_service automatically returns
//! the latest signed bytes + PA pubkey to every approved member node, so
//! the new policy propagates to nodeB/nodeC on their next bootstrap or
//! re-bootstrap (or, in steady state, after they restart and re-issue a
//! cert request).
use clap::Args;

#[derive(Args, Debug)]
#[command(about = "Sign a policy file with the local PA key and deploy on nodeA")]
pub struct SignAndDeployArgs {
    /// Path to the policy YAML file to sign
    pub file: String,
}

pub fn execute(args: SignAndDeployArgs) {
    // We delegate to the daemon's policy_authority module so the signing
    // logic and on-disk envelope format are guaranteed identical.
    match sgx_guardian_client::policy_authority::PaKey::load_or_generate() {
        Ok(pa) => match pa.sign_policy_to_disk(&args.file) {
            Ok(digest_hex) => {
                println!("✅ Policy signed and deployed.");
                println!("   YAML  : {}", args.file);
                println!("   Digest: {}", digest_hex);
                println!("   Output: /etc/sgx-guardian/policies/policy.sig");
                println!(
                    "   Pubkey: /etc/sgx-guardian/policies/pa_admin_pub.der \
                     (auto-distributed to members on next cert bootstrap)"
                );
            }
            Err(e) => eprintln!("❌ Policy signing failed: {}", e),
        },
        Err(e) => eprintln!("❌ PA key load/generate failed: {}", e),
    }
}
