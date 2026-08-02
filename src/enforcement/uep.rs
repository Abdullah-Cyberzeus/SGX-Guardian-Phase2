//! UEP (Unified Enforcement Point) - Local Policy-Based Call Authorization
//!
//! Evaluates RBAC (Role-Based Access Control) rules to determine if a call
//! initiation is permitted based on the caller's role, target's role, and media type.
//!
//! This is a **client-side gate** that blocks unauthorized call attempts *before*
//! any signaling is sent over Nebula.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Role identifier for RBAC rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Operator,
    Sensor,
    Camera,
    Robot,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Sensor => "sensor",
            Role::Camera => "camera",
            Role::Robot => "robot",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "sensor" => Some(Role::Sensor),
            "camera" => Some(Role::Camera),
            "robot" => Some(Role::Robot),
            _ => None,
        }
    }
}

/// Media type for call authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaType {
    Voice,
    Video,
    ScreenShare,
}

impl MediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaType::Voice => "voice",
            MediaType::Video => "video",
            MediaType::ScreenShare => "screen_share",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "voice" => Some(MediaType::Voice),
            "video" => Some(MediaType::Video),
            "screen_share" => Some(MediaType::ScreenShare),
            _ => None,
        }
    }
}

/// Result of a UEP authorization check
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UepDecision {
    pub allowed: bool,
    pub reason: String,
}

impl UepDecision {
    pub fn allow(reason: impl Into<String>) -> Self {
        UepDecision {
            allowed: true,
            reason: reason.into(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        UepDecision {
            allowed: false,
            reason: reason.into(),
        }
    }
}

/// RBAC rule definition: defines which roles can initiate calls to which roles
/// with which media types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacRule {
    /// The role initiating the call
    pub caller_role: Role,
    /// The role being called
    pub target_role: Role,
    /// Allowed media types (empty = all denied)
    pub allowed_media_types: HashSet<MediaType>,
}

/// UEP Engine - evaluates RBAC rules to authorize call attempts
pub struct UepEngine {
    rules: Vec<RbacRule>,
}

impl UepEngine {
    /// Create a new UEP engine with the given RBAC rules
    pub fn new(rules: Vec<RbacRule>) -> Self {
        UepEngine { rules }
    }

    /// Check if a call from caller_role to target_role with media_type is allowed
    pub fn check_call(
        &self,
        caller_role: Role,
        target_role: Role,
        media_type: MediaType,
    ) -> UepDecision {
        // Find matching rule
        for rule in &self.rules {
            if rule.caller_role == caller_role && rule.target_role == target_role {
                if rule.allowed_media_types.contains(&media_type) {
                    return UepDecision::allow(format!(
                        "{} calling {} via {} is allowed by policy",
                        caller_role.as_str(),
                        target_role.as_str(),
                        media_type.as_str()
                    ));
                } else {
                    return UepDecision::deny(format!(
                        "{} cannot call {} via {}: media type not authorized",
                        caller_role.as_str(),
                        target_role.as_str(),
                        media_type.as_str()
                    ));
                }
            }
        }

        // No matching rule = deny by default
        UepDecision::deny(format!(
            "{} cannot call {}: no policy rule found",
            caller_role.as_str(),
            target_role.as_str()
        ))
    }

    /// Default RBAC rules for a basic Circle of Trust
    /// - Admin can call anyone
    /// - Operator can call Operators and Cameras
    /// - Sensors, Cameras, Robots cannot initiate calls
    pub fn default_rules() -> Vec<RbacRule> {
        vec![
            // Admin can call everyone
            RbacRule {
                caller_role: Role::Admin,
                target_role: Role::Admin,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            RbacRule {
                caller_role: Role::Admin,
                target_role: Role::Operator,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            RbacRule {
                caller_role: Role::Admin,
                target_role: Role::Sensor,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            RbacRule {
                caller_role: Role::Admin,
                target_role: Role::Camera,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            RbacRule {
                caller_role: Role::Admin,
                target_role: Role::Robot,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            // Operator can call Operators and Cameras
            RbacRule {
                caller_role: Role::Operator,
                target_role: Role::Operator,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            RbacRule {
                caller_role: Role::Operator,
                target_role: Role::Camera,
                allowed_media_types: [MediaType::Voice, MediaType::Video]
                    .iter()
                    .cloned()
                    .collect(),
            },
            // Sensors, Cameras, Robots cannot initiate calls
            // (No rules for these roles as callers)
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_can_call_anyone() {
        let engine = UepEngine::new(UepEngine::default_rules());

        // Admin → Admin
        let decision = engine.check_call(Role::Admin, Role::Admin, MediaType::Voice);
        assert!(decision.allowed);

        // Admin → Operator
        let decision = engine.check_call(Role::Admin, Role::Operator, MediaType::Video);
        assert!(decision.allowed);

        // Admin → Sensor
        let decision = engine.check_call(Role::Admin, Role::Sensor, MediaType::Voice);
        assert!(decision.allowed);

        // Admin → Camera
        let decision = engine.check_call(Role::Admin, Role::Camera, MediaType::Video);
        assert!(decision.allowed);

        // Admin → Robot
        let decision = engine.check_call(Role::Admin, Role::Robot, MediaType::Voice);
        assert!(decision.allowed);
    }

    #[test]
    fn test_operator_can_call_operator_and_camera() {
        let engine = UepEngine::new(UepEngine::default_rules());

        // Operator → Operator
        let decision = engine.check_call(Role::Operator, Role::Operator, MediaType::Voice);
        assert!(decision.allowed);

        // Operator → Camera
        let decision = engine.check_call(Role::Operator, Role::Camera, MediaType::Video);
        assert!(decision.allowed);

        // Operator → Admin (denied)
        let decision = engine.check_call(Role::Operator, Role::Admin, MediaType::Voice);
        assert!(!decision.allowed);

        // Operator → Sensor (denied)
        let decision = engine.check_call(Role::Operator, Role::Sensor, MediaType::Voice);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_sensor_cannot_initiate_calls() {
        let engine = UepEngine::new(UepEngine::default_rules());

        let decision = engine.check_call(Role::Sensor, Role::Admin, MediaType::Voice);
        assert!(!decision.allowed);

        let decision = engine.check_call(Role::Sensor, Role::Operator, MediaType::Video);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_camera_cannot_initiate_calls() {
        let engine = UepEngine::new(UepEngine::default_rules());

        let decision = engine.check_call(Role::Camera, Role::Admin, MediaType::Voice);
        assert!(!decision.allowed);

        let decision = engine.check_call(Role::Camera, Role::Operator, MediaType::Voice);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_robot_cannot_initiate_calls() {
        let engine = UepEngine::new(UepEngine::default_rules());

        let decision = engine.check_call(Role::Robot, Role::Admin, MediaType::Voice);
        assert!(!decision.allowed);

        let decision = engine.check_call(Role::Robot, Role::Camera, MediaType::Video);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_decisions_have_descriptive_reasons() {
        let engine = UepEngine::new(UepEngine::default_rules());

        let allow_decision = engine.check_call(Role::Admin, Role::Operator, MediaType::Voice);
        assert!(allow_decision.allowed);
        assert!(allow_decision.reason.contains("allowed by policy"));

        let deny_decision = engine.check_call(Role::Sensor, Role::Admin, MediaType::Voice);
        assert!(!deny_decision.allowed);
        assert!(deny_decision.reason.contains("cannot call"));
    }

    #[test]
    fn test_custom_rules() {
        // Custom rule: only Sensors can call Admins via Voice
        let custom_rules = vec![RbacRule {
            caller_role: Role::Sensor,
            target_role: Role::Admin,
            allowed_media_types: [MediaType::Voice].iter().cloned().collect(),
        }];

        let engine = UepEngine::new(custom_rules);

        // Sensor → Admin via Voice (allowed)
        let decision = engine.check_call(Role::Sensor, Role::Admin, MediaType::Voice);
        assert!(decision.allowed);

        // Sensor → Admin via Video (denied)
        let decision = engine.check_call(Role::Sensor, Role::Admin, MediaType::Video);
        assert!(!decision.allowed);

        // Admin → Sensor (denied, not in custom rules)
        let decision = engine.check_call(Role::Admin, Role::Sensor, MediaType::Voice);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_role_string_conversion() {
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::from_str("admin"), Some(Role::Admin));
        assert_eq!(Role::from_str("operator"), Some(Role::Operator));
        assert_eq!(Role::from_str("invalid"), None);
    }

    #[test]
    fn test_media_type_string_conversion() {
        assert_eq!(MediaType::Voice.as_str(), "voice");
        assert_eq!(MediaType::from_str("voice"), Some(MediaType::Voice));
        assert_eq!(MediaType::from_str("video"), Some(MediaType::Video));
        assert_eq!(
            MediaType::from_str("screen_share"),
            Some(MediaType::ScreenShare)
        );
        assert_eq!(MediaType::from_str("invalid"), None);
    }
}
