//! Detection-engine boundary for port risk evaluation.

use crate::port_risk::{evaluate, PortRiskInput, PortRiskResult, ScoreRuleSet};
use crate::port_security::PortRuleSet;

pub struct PortDetectionEngine {
    pub knowledge_base: PortRuleSet,
    pub score_rules: ScoreRuleSet,
}
impl PortDetectionEngine {
    pub fn from_files(knowledge_path: &str, score_path: &str) -> Self {
        Self {
            knowledge_base: PortRuleSet::load_or_default(knowledge_path),
            score_rules: ScoreRuleSet::load_or_default(score_path),
        }
    }
    pub fn evaluate(&self, input: &PortRiskInput) -> PortRiskResult {
        evaluate(input, &self.knowledge_base, &self.score_rules)
    }
}
