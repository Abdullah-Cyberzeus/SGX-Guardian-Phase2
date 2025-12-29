//! Enforcement safety validation.
//!
//! Ensures policy is sane BEFORE translation or execution.
//! Day-1: only basic structural sanity checks (no semantic enforcement).

use crate::policy::Policy;
use anyhow::{anyhow, Result};

pub fn validate_policy(policy: &Policy) -> Result<()> {
    // Policy must contain at least one rule
    if policy.rules.is_empty() {
        return Err(anyhow!("policy contains no enforcement rules"));
    }

    for rule in &policy.rules {
        // Basic string presence checks
        if rule.action.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing action", rule.id));
        }

        if rule.protocol.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing protocol", rule.id));
        }

        if rule.src.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing source address", rule.id));
        }

        if rule.dst.trim().is_empty() {
            return Err(anyhow!("rule '{}' missing destination address", rule.id));
        }

        // Port sanity (if present)
        if let Some(port) = rule.port {
            if port == 0 {
                return Err(anyhow!("rule '{}' has invalid port 0", rule.id));
            }
        }
    }

    Ok(())
}
