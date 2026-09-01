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
        let _env_guard = crate::test_utils::TEST_ENV_LOCK.lock().await;
        let dir = tempdir().expect("create temp dir");
        let previous_policy_dir = env::var("SGX_GUARDIAN_POLICY_DIR").ok();
        let previous_signaling_port = env::var("SGX_CALL_SIGNALING_PORT").ok();
        env::set_var("SGX_GUARDIAN_POLICY_DIR", dir.path());
        env::set_var("SGX_CALL_SIGNALING_PORT", "50065");
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

        match previous_policy_dir {
            Some(value) => env::set_var("SGX_GUARDIAN_POLICY_DIR", value),
            None => env::remove_var("SGX_GUARDIAN_POLICY_DIR"),
        }
        match previous_signaling_port {
            Some(value) => env::set_var("SGX_CALL_SIGNALING_PORT", value),
            None => env::remove_var("SGX_CALL_SIGNALING_PORT"),
        }
    }

    fn participant() -> CallParticipant {
        CallParticipant {
            device_id: "device-A".into(),
            virtual_id: "virtual-A".into(),
            accepted: false,
            requested_media: vec![MediaType::Audio],
            dtls_fingerprint_signaled: None,
            dtls_fingerprint_confirmed: None,
        }
    }

    fn session() -> CallSession {
        CallSession::new(
            "device-A".into(),
            "virtual-A".into(),
            "device-B".into(),
            "virtual-B".into(),
            vec![MediaType::Audio],
            "nonce".into(),
        )
        .unwrap()
    }

    fn deny_rule(src: &str, dst: &str, protocol: &str, port: Option<u16>) -> crate::policy::Rule {
        crate::policy::Rule {
            id: "rule".into(),
            action: "DENY".into(),
            src: src.into(),
            dst: dst.into(),
            protocol: protocol.into(),
            port,
        }
    }

    #[test]
    fn call_signaling_port_defaults_when_env_missing_invalid_or_zero() {
        env::remove_var("SGX_CALL_SIGNALING_PORT");
        assert_eq!(call_signaling_port(), 50065);
        env::set_var("SGX_CALL_SIGNALING_PORT", "bad");
        assert_eq!(call_signaling_port(), 50065);
        env::set_var("SGX_CALL_SIGNALING_PORT", "0");
        assert_eq!(call_signaling_port(), 50065);
        env::remove_var("SGX_CALL_SIGNALING_PORT");
    }

    #[test]
    fn call_signaling_port_uses_positive_env_value() {
        env::set_var("SGX_CALL_SIGNALING_PORT", "4444");
        assert_eq!(call_signaling_port(), 4444);
        env::remove_var("SGX_CALL_SIGNALING_PORT");
    }

    #[test]
    fn endpoint_matches_wildcard_and_any_patterns() {
        let participant = participant();
        for pattern in ["", " ", "*", "any", "0.0.0.0/0", "0.0.0.0"] {
            assert!(endpoint_matches(pattern, &participant), "{pattern}");
        }
    }

    #[test]
    fn endpoint_matches_device_and_virtual_ids_case_insensitively() {
        let participant = participant();
        assert!(endpoint_matches("DEVICE-a", &participant));
        assert!(endpoint_matches("Virtual-A", &participant));
        assert!(endpoint_matches("device:DEVICE-a", &participant));
        assert!(endpoint_matches("virtual:Virtual-A", &participant));
    }

    #[test]
    fn endpoint_rejects_non_matching_patterns() {
        let participant = participant();
        assert!(!endpoint_matches("device:other", &participant));
        assert!(!endpoint_matches("virtual:other", &participant));
        assert!(!endpoint_matches("10.0.0.1", &participant));
    }

    #[test]
    fn rule_applies_to_session_rejects_non_tcp_protocol() {
        let rule = deny_rule("*", "*", "UDP", Some(50065));
        assert!(!rule_applies_to_session(&rule, &session()));
    }

    #[test]
    fn rule_applies_to_session_rejects_wrong_port() {
        env::set_var("SGX_CALL_SIGNALING_PORT", "50065");
        let rule = deny_rule("*", "*", "TCP", Some(1234));
        assert!(!rule_applies_to_session(&rule, &session()));
        env::remove_var("SGX_CALL_SIGNALING_PORT");
    }

    #[test]
    fn rule_applies_to_session_accepts_matching_custom_port() {
        env::set_var("SGX_CALL_SIGNALING_PORT", "4444");
        let rule = deny_rule("device:device-a", "virtual:virtual-b", "tcp", Some(4444));
        assert!(rule_applies_to_session(&rule, &session()));
        env::remove_var("SGX_CALL_SIGNALING_PORT");
    }

    #[test]
    fn rule_applies_to_session_accepts_missing_port_when_endpoints_match() {
        let rule = deny_rule("device-A", "device-B", "TCP", None);
        assert!(rule_applies_to_session(&rule, &session()));
    }

    #[test]
    fn rule_applies_to_session_rejects_source_or_destination_mismatch() {
        assert!(!rule_applies_to_session(
            &deny_rule("other", "device-B", "TCP", Some(50065)),
            &session()
        ));
        assert!(!rule_applies_to_session(
            &deny_rule("device-A", "other", "TCP", Some(50065)),
            &session()
        ));
    }
}
