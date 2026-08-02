/// Threat Detection Rules Engine
/// Evaluates events against pre-configured threat rules
use crate::threat::errors::{ThreatError, ThreatResult};

/// Threat action to take
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatAction {
    /// Log the threat
    Log,
    /// Alert administrators
    Alert,
    /// Block the peer
    Block,
    /// Isolate the peer
    Isolate,
    /// Rate limit the peer
    RateLimit,
    /// Disconnect the peer
    Disconnect,
}

impl std::fmt::Display for ThreatAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatAction::Log => write!(f, "log"),
            ThreatAction::Alert => write!(f, "alert"),
            ThreatAction::Block => write!(f, "block"),
            ThreatAction::Isolate => write!(f, "isolate"),
            ThreatAction::RateLimit => write!(f, "rate_limit"),
            ThreatAction::Disconnect => write!(f, "disconnect"),
        }
    }
}

/// Threat detection rule
#[derive(Debug, Clone)]
pub struct ThreatRule {
    pub id: String,
    pub name: String,
    pub event_type: String,
    pub pattern: String,
    pub severity: String, // "low", "medium", "high", "critical"
    pub action: ThreatAction,
    pub enabled: bool,
}

impl ThreatRule {
    /// Create new threat rule
    pub fn new(
        id: String,
        name: String,
        event_type: String,
        pattern: String,
        severity: String,
        action: ThreatAction,
    ) -> Self {
        ThreatRule {
            id,
            name,
            event_type,
            pattern,
            severity,
            action,
            enabled: true,
        }
    }

    /// Check if event matches rule pattern
    pub fn matches(&self, event_type: &str, event_data: &str) -> bool {
        if !self.enabled {
            return false;
        }

        if event_type != self.event_type {
            return false;
        }

        // Simple pattern matching (contains)
        event_data.contains(&self.pattern)
    }

    /// Get severity level as numeric value
    pub fn severity_level(&self) -> u32 {
        match self.severity.as_str() {
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 0,
        }
    }
}

/// Threat rule engine
#[derive(Clone)]
pub struct ThreatRuleEngine {
    rules: Vec<ThreatRule>,
}

impl ThreatRuleEngine {
    /// Create new threat rule engine with default rules
    pub fn new() -> Self {
        let mut engine = ThreatRuleEngine { rules: Vec::new() };
        engine.load_default_rules();
        engine
    }

    /// Load default threat rules
    fn load_default_rules(&mut self) {
        let default_rules = vec![
            ThreatRule::new(
                "rule_001".to_string(),
                "Multiple Auth Failures".to_string(),
                "auth_failure".to_string(),
                "invalid".to_string(),
                "medium".to_string(),
                ThreatAction::Alert,
            ),
            ThreatRule::new(
                "rule_002".to_string(),
                "Policy Violation Attempt".to_string(),
                "policy_violation".to_string(),
                "denied".to_string(),
                "high".to_string(),
                ThreatAction::Block,
            ),
            ThreatRule::new(
                "rule_003".to_string(),
                "Unauthorized Media Access".to_string(),
                "media_access".to_string(),
                "unauthorized".to_string(),
                "critical".to_string(),
                ThreatAction::Disconnect,
            ),
            ThreatRule::new(
                "rule_004".to_string(),
                "Suspicious Call Pattern".to_string(),
                "call_pattern".to_string(),
                "suspicious".to_string(),
                "medium".to_string(),
                ThreatAction::Log,
            ),
            ThreatRule::new(
                "rule_005".to_string(),
                "Certificate Validation Failure".to_string(),
                "cert_validation".to_string(),
                "invalid".to_string(),
                "critical".to_string(),
                ThreatAction::Block,
            ),
        ];

        self.rules.extend(default_rules);
    }

    /// Evaluate event against all rules
    pub fn evaluate(
        &self,
        event_type: &str,
        event_data: &str,
    ) -> ThreatResult<Option<ThreatAction>> {
        // Find matching rules, prioritize by severity
        let mut matching_rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.matches(event_type, event_data))
            .collect();

        if matching_rules.is_empty() {
            return Ok(None);
        }

        // Sort by severity (highest first)
        matching_rules.sort_by_key(|b| std::cmp::Reverse(b.severity_level()));

        Ok(Some(matching_rules[0].action.clone()))
    }

    /// Get all rules
    pub fn rules(&self) -> &[ThreatRule] {
        &self.rules
    }

    /// Add custom rule
    pub fn add_rule(&mut self, rule: ThreatRule) -> ThreatResult<()> {
        if rule.id.is_empty() || rule.name.is_empty() {
            return Err(ThreatError::InvalidParameters(
                "Rule must have id and name".to_string(),
            ));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Disable rule by id
    pub fn disable_rule(&mut self, rule_id: &str) -> ThreatResult<()> {
        for rule in &mut self.rules {
            if rule.id == rule_id {
                rule.enabled = false;
                return Ok(());
            }
        }
        Err(ThreatError::InvalidParameters(format!(
            "Rule not found: {}",
            rule_id
        )))
    }

    /// Enable rule by id
    pub fn enable_rule(&mut self, rule_id: &str) -> ThreatResult<()> {
        for rule in &mut self.rules {
            if rule.id == rule_id {
                rule.enabled = true;
                return Ok(());
            }
        }
        Err(ThreatError::InvalidParameters(format!(
            "Rule not found: {}",
            rule_id
        )))
    }
}

impl Default for ThreatRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_rule_creation() {
        let rule = ThreatRule::new(
            "test_001".to_string(),
            "Test Rule".to_string(),
            "auth_failure".to_string(),
            "invalid".to_string(),
            "high".to_string(),
            ThreatAction::Alert,
        );
        assert_eq!(rule.id, "test_001");
        assert!(rule.enabled);
    }

    #[test]
    fn test_threat_rule_matching() {
        let rule = ThreatRule::new(
            "test_001".to_string(),
            "Test Rule".to_string(),
            "auth_failure".to_string(),
            "invalid".to_string(),
            "high".to_string(),
            ThreatAction::Alert,
        );
        assert!(rule.matches("auth_failure", "invalid_password"));
        assert!(!rule.matches("auth_success", "invalid_password"));
    }

    #[test]
    fn test_threat_rule_engine_creation() {
        let engine = ThreatRuleEngine::new();
        assert!(!engine.rules().is_empty()); // Default rules loaded
        assert_eq!(engine.rules().len(), 5); // 5 default rules
    }

    #[test]
    fn test_threat_rule_engine_evaluation() {
        let engine = ThreatRuleEngine::new();
        let action = engine.evaluate("auth_failure", "invalid_password");
        assert!(action.is_ok());
        assert!(action.unwrap().is_some()); // Should match default rule
    }

    #[test]
    fn test_threat_rule_engine_add_rule() {
        let mut engine = ThreatRuleEngine::new();
        let original_count = engine.rules().len();
        let rule = ThreatRule::new(
            "custom_001".to_string(),
            "Custom Rule".to_string(),
            "custom_event".to_string(),
            "pattern".to_string(),
            "low".to_string(),
            ThreatAction::Log,
        );
        assert!(engine.add_rule(rule).is_ok());
        assert_eq!(engine.rules().len(), original_count + 1);
    }

    #[test]
    fn test_threat_rule_engine_disable_rule() {
        let mut engine = ThreatRuleEngine::new();
        let rule_id = engine.rules()[0].id.clone();
        assert!(engine.disable_rule(&rule_id).is_ok());
        assert!(!engine.rules()[0].enabled);
    }

    #[test]
    fn test_threat_action_display() {
        assert_eq!(ThreatAction::Alert.to_string(), "alert");
        assert_eq!(ThreatAction::Block.to_string(), "block");
        assert_eq!(ThreatAction::Disconnect.to_string(), "disconnect");
    }

    #[test]
    fn test_threat_rule_severity_levels() {
        let rule_low = ThreatRule::new(
            "test_001".to_string(),
            "Test".to_string(),
            "test".to_string(),
            "test".to_string(),
            "low".to_string(),
            ThreatAction::Log,
        );
        let rule_critical = ThreatRule::new(
            "test_002".to_string(),
            "Test".to_string(),
            "test".to_string(),
            "test".to_string(),
            "critical".to_string(),
            ThreatAction::Block,
        );
        assert_eq!(rule_low.severity_level(), 1);
        assert_eq!(rule_critical.severity_level(), 4);
    }

    #[test]
    fn test_threat_rule_engine_no_match() {
        let engine = ThreatRuleEngine::new();
        let action = engine.evaluate("unknown_event", "unknown_pattern");
        assert!(action.is_ok());
        assert!(action.unwrap().is_none()); // No matching rule
    }
}
