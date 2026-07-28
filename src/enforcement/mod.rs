//! Enforcement Engine
//!
//! Responsible for orchestrating the translation of verified
//! security policies into concrete OS-level enforcement (nftables).
//!
//! Connects Validator -> Translator -> Executor into a single pipeline.

pub mod executor;
pub mod model;
pub mod translator;
pub mod validator;

use crate::policy::Policy;
use anyhow::{Context, Result};

/// Apply a verified policy to the system firewall.
///
/// Orchestrates the pipeline:
/// 1. Validate (safety checks)
/// 2. Translate (model conversion)
/// 3. Execute (nftables atomic commit)
pub fn apply_policy(policy: &Policy) -> Result<()> {
    // 1. Validate
    validator::validate_policy(policy).context("Enforcement Error [Validation]")?;

    // 2. Translate
    let translated_rules =
        translator::translate(policy).context("Enforcement Error [Translation]")?;

    // 3. Execute
    executor::apply_rules(&translated_rules).context("Enforcement Error [Execution]")?;

    Ok(())
}

/// Removes all active enforcement rules from the system safely.
/// Returns the system to an unprotected (or default) state.
pub fn remove_policy() -> Result<()> {
    executor::cleanup_rules().context("Enforcement Error [Removal]")?;
    Ok(())
}

/// Atomically reloads the firewall with a new policy.
/// Under the hood, apply_policy already performs an atomic replacement.
pub fn reload_policy(policy: &Policy) -> Result<()> {
    apply_policy(policy)
}
