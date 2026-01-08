//! Enforcement Engine
//!
//! Responsible for translating a verified UEP policy
//! into concrete OS-level enforcement (nftables).
//!
//! This module assumes the policy is already:
//! - Signed
//! - Verified
//! - Atomically activated

mod executor;
mod model;
mod translator;
mod validator;

use crate::policy::Policy;
use anyhow::Result;

/// Apply a verified policy to the system firewall.
///
/// This function is:
/// - Atomic
/// - Deterministic
/// - Fail-closed on error
pub fn enforce_policy(policy: &Policy) -> Result<()> {
    validator::validate_policy(policy)?;
    let rules = translator::translate(policy)?;
    executor::apply_rules(&rules)?;
    Ok(())
}
