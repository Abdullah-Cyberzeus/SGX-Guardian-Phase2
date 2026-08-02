//! Policy enforcement hooks for call sessions.
//!
//! Phase 2: Provide a runtime enforcer interface. Default implementation allows all.

use crate::call::error::{CallError, CallResult};
use crate::call::session::{CallParticipant, CallSession};
use async_trait::async_trait;
use std::sync::Arc;

/// Policy enforcer interface for call sessions.
#[async_trait]
pub trait PolicyEnforcer: Send + Sync {
    /// Check if the initiator -> receiver call is allowed by policy.
    async fn allow_call(&self, session: &CallSession) -> CallResult<bool>;
}

/// Default enforcer that allows all calls (safe default for Phase 2).
pub struct AllowAllEnforcer;

#[async_trait]
impl PolicyEnforcer for AllowAllEnforcer {
    async fn allow_call(&self, _session: &CallSession) -> CallResult<bool> {
        Ok(true)
    }
}

/// A concrete call policy enforcer that evaluates the currently active UEP policy.
pub struct CallPolicyEnforcer;

#[async_trait]
impl PolicyEnforcer for CallPolicyEnforcer {
    async fn allow_call(&self, session: &CallSession) -> CallResult<bool> {
        let material = crate::policy::load_effective_policy_material();
        let policy = crate::policy::validate_policy(&material.yaml).map_err(|e| {
            CallError::InternalError(format!("Failed to parse active policy: {}", e))
        })?;

        // Deny any call matching an explicit DENY rule for the dedicated call
        // signaling TCP port.
        for rule in policy.rules.iter() {
            if rule.action.eq_ignore_ascii_case("DENY") && rule_applies_to_session(rule, session) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn call_signaling_port() -> u16 {
    std::env::var("SGX_CALL_SIGNALING_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50065)
}

fn rule_applies_to_session(rule: &crate::policy::Rule, session: &CallSession) -> bool {
    if !rule.protocol.eq_ignore_ascii_case("TCP") {
        return false;
    }

    if let Some(port) = rule.port {
        if port != call_signaling_port() {
            return false;
        }
    }

    endpoint_matches(&rule.src, &session.initiator)
        && endpoint_matches(&rule.dst, &session.receiver)
}

fn endpoint_matches(pattern: &str, participant: &CallParticipant) -> bool {
    let normalized = pattern.trim().to_lowercase();

    if normalized.is_empty()
        || normalized == "*"
        || normalized == "any"
        || normalized == "0.0.0.0/0"
        || normalized == "0.0.0.0"
    {
        return true;
    }

    if normalized == participant.device_id.to_lowercase()
        || normalized == participant.virtual_id.to_lowercase()
    {
        return true;
    }

    if let Some(stripped) = normalized.strip_prefix("device:") {
        return stripped == participant.device_id.to_lowercase();
    }

    if let Some(stripped) = normalized.strip_prefix("virtual:") {
        return stripped == participant.virtual_id.to_lowercase();
    }

    false
}

pub type SharedEnforcer = Arc<dyn PolicyEnforcer>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::signaling::MediaType;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    const DENY_CALLS_POLICY: &str = r#"
policy_id: "call-deny"
version: "1.0.0"
rules:
  - id: "deny-call-signaling"
    action: "DENY"
    src: "0.0.0.0/0"
    dst: "0.0.0.0/0"
    protocol: "TCP"
    port: 50065
"#;

    #[tokio::test]
    async fn test_call_policy_enforcer_denies_wildcard_tcp_call() {
        let dir = tempdir().expect("create temp dir");
        env::set_var("SGX_GUARDIAN_POLICY_DIR", dir.path());
        fs::write(dir.path().join("active_policy.yaml"), DENY_CALLS_POLICY)
            .expect("write active policy");

        let session = CallSession::new(
            "initiator-device".to_string(),
            "initiator-virtual".to_string(),
            "receiver-device".to_string(),
            "receiver-virtual".to_string(),
            vec![MediaType::Audio],
            "nonce-123".to_string(),
        )
        .unwrap();

        let enforcer = CallPolicyEnforcer;
        assert!(!enforcer.allow_call(&session).await.unwrap());
    }
}
