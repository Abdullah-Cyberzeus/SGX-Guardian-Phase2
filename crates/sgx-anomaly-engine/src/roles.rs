//! Role metadata and shadow role baselines.
//!
//! Roles are context, not a 20th model feature.  They select/aggregate a
//! baseline without changing the locked 19-value feature vector.  The engine
//! currently uses this module in shadow mode: it learns role normal history
//! but keeps the existing per-node baseline as the alert decision source.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::{Score, ZScoreModel};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Admin,
    Member,
    Unknown,
}

/// Trusted audit context for an admin operation. This stays outside the
/// locked 19-value anomaly vector: it tells the baseline selector *which
/// expected admin activity is occurring*, rather than becoming a new model
/// feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAction {
    DeviceBlock,
    DeviceUnblock,
    CircleMemberAdd,
    CircleMemberRemove,
    PolicyChange,
    Unknown,
}

impl AdminAction {
    pub fn baseline_key(self) -> &'static str {
        match self {
            Self::DeviceBlock => "admin_action:device_block",
            Self::DeviceUnblock => "admin_action:device_unblock",
            Self::CircleMemberAdd => "admin_action:circle_member_add",
            Self::CircleMemberRemove => "admin_action:circle_member_remove",
            Self::PolicyChange => "admin_action:policy_change",
            Self::Unknown => "admin_action:unknown",
        }
    }
}

impl NodeRole {
    pub fn baseline_key(self) -> &'static str {
        match self {
            Self::Admin => "role:admin",
            Self::Member => "role:member",
            Self::Unknown => "role:unknown",
        }
    }
}

/// Trusted node-id to role mapping, supplied by deployment configuration or
/// the future board inventory service. It is not supplied by an untrusted
/// telemetry row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleRegistry {
    #[serde(flatten)]
    roles: HashMap<String, NodeRole>,
}

impl RoleRegistry {
    pub fn from_path(path: &str) -> anyhow::Result<Self> {
        Self::from_json_str(&std::fs::read_to_string(path)?)
    }

    pub fn from_json_str(json: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn role_for(&self, node: &str) -> NodeRole {
        self.roles.get(node).copied().unwrap_or(NodeRole::Unknown)
    }
}

/// A shareable role-level normal baseline. Pass the same instance to every
/// engine whose nodes should contribute to the same role baseline.
#[derive(Clone)]
pub struct RoleBaseline {
    registry: RoleRegistry,
    model: Arc<ZScoreModel>,
}

impl RoleBaseline {
    pub fn new(registry: RoleRegistry, z_alert_threshold: Option<f64>) -> Self {
        let model = match z_alert_threshold {
            Some(limit) => ZScoreModel::new(3.0).with_z_alert_threshold(limit),
            None => ZScoreModel::new(3.0),
        };
        Self {
            registry,
            model: Arc::new(model),
        }
    }

    pub fn role_for(&self, node: &str) -> NodeRole {
        self.registry.role_for(node)
    }

    /// Score against the shared role baseline. Shadow scores are intentionally
    /// not used to decide alerts until role-specific real normal data has been
    /// collected and calibrated.
    pub fn peek(&self, node: &str, vector: &[f64; 19]) -> Score {
        self.model.peek(self.role_for(node).baseline_key(), vector)
    }

    /// Add a row already judged normal by the existing production decision.
    pub fn fold_normal(&self, node: &str, vector: &[f64; 19]) {
        self.model.fold(self.role_for(node).baseline_key(), vector);
    }
}

/// Separate normal baselines for authorised admin action types. An action is
/// accepted only for a node mapped to the trusted `admin` role. A future board
/// audit collector supplies the action; today's 19-feature CSV has no such
/// action-type field, so this is intentionally not part of current scoring.
#[derive(Clone)]
pub struct AdminBaseline {
    registry: RoleRegistry,
    model: Arc<ZScoreModel>,
}

impl AdminBaseline {
    pub fn new(registry: RoleRegistry, z_alert_threshold: Option<f64>) -> Self {
        let model = match z_alert_threshold {
            Some(limit) => ZScoreModel::new(3.0).with_z_alert_threshold(limit),
            None => ZScoreModel::new(3.0),
        };
        Self {
            registry,
            model: Arc::new(model),
        }
    }

    /// `None` is returned for members/unknown nodes: an admin-only action by
    /// those roles must be handled by the authorisation layer as critical,
    /// not normalised into any baseline.
    pub fn peek(&self, node: &str, action: AdminAction, vector: &[f64; 19]) -> Option<Score> {
        (self.registry.role_for(node) == NodeRole::Admin)
            .then(|| self.model.peek(action.baseline_key(), vector))
    }

    /// Fold only an already-authorised, already-normal admin operation.
    pub fn fold_authorized_normal(&self, node: &str, action: AdminAction, vector: &[f64; 19]) {
        if self.registry.role_for(node) == NodeRole::Admin {
            self.model.fold(action.baseline_key(), vector);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_selects_role_and_unknown_fallback() {
        let registry =
            RoleRegistry::from_json_str(r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap();
        assert_eq!(registry.role_for("nodeA"), NodeRole::Admin);
        assert_eq!(registry.role_for("nodeB"), NodeRole::Member);
        assert_eq!(registry.role_for("missing"), NodeRole::Unknown);
    }

    #[test]
    fn same_role_nodes_share_one_shadow_baseline() {
        let registry =
            RoleRegistry::from_json_str(r#"{"nodeB":"member","nodeC":"member"}"#).unwrap();
        let baseline = RoleBaseline::new(registry, None);
        let mut vector = [0.0; 19];
        vector[15] = 20.0;
        for _ in 0..30 {
            baseline.fold_normal("nodeB", &vector);
        }
        assert!(baseline.peek("nodeC", &vector).confidence >= 1.0);
    }

    #[test]
    fn admin_baselines_are_action_specific_and_members_cannot_use_them() {
        let registry =
            RoleRegistry::from_json_str(r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap();
        let baseline = AdminBaseline::new(registry, None);
        let mut vector = [0.0; 19];
        vector[11] = 1.0;
        for _ in 0..30 {
            baseline.fold_authorized_normal("nodeA", AdminAction::DeviceBlock, &vector);
        }
        assert!(
            baseline
                .peek("nodeA", AdminAction::DeviceBlock, &vector)
                .unwrap()
                .confidence
                >= 1.0
        );
        assert!(
            baseline
                .peek("nodeA", AdminAction::PolicyChange, &vector)
                .unwrap()
                .confidence
                < 1.0
        );
        assert!(baseline
            .peek("nodeB", AdminAction::DeviceBlock, &vector)
            .is_none());
    }
}
