//! UEP Gate - Call Initiation Policy Check
//!
//! This module integrates UEP (Unified Enforcement Point) checks into the call
//! initiation flow. Before a call offer is sent, this gate verifies that the
//! caller's role is authorized to call the target's role with the requested media type.
//!
//! If authorization is denied, the call is blocked locally **before** any signaling
//! is sent over Nebula.

use crate::enforcement::uep::{MediaType, Role, UepDecision, UepEngine};
use crate::policy_state;

/// UEP Gate error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UepGateError {
    /// Call authorization was denied by policy
    DeniedByPolicy(String),
    /// Failed to extract caller role from certificate
    MissingCallerRole,
    /// Failed to extract target role
    MissingTargetRole,
    /// Failed to load RBAC rules from policy
    RbacLoadFailed(String),
}

impl std::fmt::Display for UepGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UepGateError::DeniedByPolicy(reason) => {
                write!(f, "Call denied by policy: {}", reason)
            }
            UepGateError::MissingCallerRole => {
                write!(f, "Cannot determine caller role from certificate")
            }
            UepGateError::MissingTargetRole => {
                write!(f, "Cannot determine target role")
            }
            UepGateError::RbacLoadFailed(reason) => {
                write!(f, "Failed to load RBAC rules: {}", reason)
            }
        }
    }
}

impl std::error::Error for UepGateError {}

/// Result type for UEP gate operations
pub type UepGateResult<T> = Result<T, UepGateError>;

/// Check if a call from caller to target with media_type is authorized by policy
///
/// # Arguments
/// * `caller_role` - Role of the initiating party
/// * `target_role` - Role of the receiving party
/// * `media_type` - Type of media being requested
///
/// # Returns
/// * `Ok(decision)` - Contains the authorization decision and reason
/// * `Err(UepGateError)` - If authorization check fails (e.g., policy load error)
pub fn check_call_authorization(
    caller_role: Role,
    target_role: Role,
    media_type: MediaType,
) -> UepGateResult<UepDecision> {
    // Load RBAC rules from active policy
    let rules =
        policy_state::load_rbac_rules().map_err(|e| UepGateError::RbacLoadFailed(e.to_string()))?;

    // Create UEP engine and evaluate
    let engine = UepEngine::new(rules);
    let decision = engine.check_call(caller_role, target_role, media_type);

    // If denied, return error; if allowed, return decision
    if decision.allowed {
        Ok(decision)
    } else {
        Err(UepGateError::DeniedByPolicy(decision.reason))
    }
}

/// Extract the role from a certificate subject
///
/// Expects the subject to contain a role attribute like: "role=operator"
pub fn extract_role_from_subject(subject: &str) -> Option<Role> {
    for part in subject.split(',') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix("role=") {
            return Role::parse_str(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_role_from_subject() {
        let subject = "CN=node1,O=Guardian,role=admin,C=US";
        assert_eq!(extract_role_from_subject(subject), Some(Role::Admin));

        let subject = "CN=node2,role=operator,O=Guardian";
        assert_eq!(extract_role_from_subject(subject), Some(Role::Operator));

        let subject = "CN=node3,O=Guardian";
        assert_eq!(extract_role_from_subject(subject), None);
    }

    #[test]
    fn test_uep_gate_error_display() {
        let err = UepGateError::DeniedByPolicy("admin cannot call sensor".to_string());
        assert!(err.to_string().contains("Call denied by policy"));

        let err = UepGateError::MissingCallerRole;
        assert!(err.to_string().contains("caller role"));

        let err = UepGateError::RbacLoadFailed("file not found".to_string());
        assert!(err.to_string().contains("Failed to load RBAC rules"));
    }

    #[test]
    fn test_check_call_authorization_with_default_rules() {
        // This test uses the default RBAC rules loaded from policy_state
        // Admin should be allowed to call anyone
        let result = check_call_authorization(Role::Admin, Role::Operator, MediaType::Voice);
        assert!(result.is_ok());
        let decision = result.unwrap();
        assert!(decision.allowed);

        // Sensor should not be allowed to call Admin
        let result = check_call_authorization(Role::Sensor, Role::Admin, MediaType::Voice);
        assert!(result.is_err());
        match result {
            Err(UepGateError::DeniedByPolicy(reason)) => {
                assert!(reason.contains("cannot call"));
            }
            _ => panic!("expected DeniedByPolicy error"),
        }
    }
}
