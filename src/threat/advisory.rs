//! Security Advisory Service
//! Formats remediation plans into structured security advisories and manages
//! an in-memory advisory store for REST API and CLI access.

use crate::threat::remediation::RemediationPlan;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Life-cycle status of a Security Advisory.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryStatus {
    /// Awaiting administrator review and approval for pending actions.
    Pending,
    /// All actions were executed automatically; no admin approval required.
    AutoExecuted,
    /// Administrator approved pending actions.
    Approved,
    /// Administrator rejected the advisory recommendation.
    Rejected,
}

impl AdvisoryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AdvisoryStatus::Pending => "pending",
            AdvisoryStatus::AutoExecuted => "auto_executed",
            AdvisoryStatus::Approved => "approved",
            AdvisoryStatus::Rejected => "rejected",
        }
    }
}

/// Structured Security Advisory for presentation to admins and external APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityAdvisory {
    /// Unique identifier for this advisory (e.g. "adv-a1b2c3d4").
    pub advisory_id: String,
    /// Human-readable title summarizing threat and target.
    pub title: String,
    /// Severity label: "suspicious", "elevated", or "critical".
    pub severity_label: String,
    /// Associated remediation plan detailing actions and rationale.
    pub plan: RemediationPlan,
    /// Current life-cycle status of the advisory.
    pub status: AdvisoryStatus,
    /// Timestamp when the advisory was first created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when the advisory was last updated (score/title refresh).
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the advisory was approved/rejected/resolved (if applicable).
    pub resolved_at: Option<DateTime<Utc>>,
}

/// In-memory advisory repository. Retains recent advisories up to `max_entries`.
#[derive(Debug, Clone)]
pub struct AdvisoryStore {
    advisories: Vec<SecurityAdvisory>,
    max_entries: usize,
}

impl AdvisoryStore {
    /// Creates a new `AdvisoryStore` with the specified maximum capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            advisories: Vec::new(),
            max_entries,
        }
    }

    /// Default store capacity (500 entries).
    pub fn default_capacity() -> Self {
        Self::new(500)
    }

    /// Pushes a new advisory into the store, evicting the oldest entry if full.
    pub fn push(&mut self, advisory: SecurityAdvisory) {
        if self.advisories.len() >= self.max_entries {
            self.advisories.remove(0);
        }
        self.advisories.push(advisory);
    }

    /// Returns the numeric severity rank (higher = more severe).
    fn severity_rank(label: &str) -> u8 {
        match label {
            "critical" => 3,
            "elevated" => 2,
            _ => 1, // "suspicious"
        }
    }

    /// Upsert an advisory by `target_ip`:
    /// - If an active (non-resolved) advisory for the same IP exists **and** the new
    ///   severity is NOT higher, update its score/title/justification/updated_at in place.
    /// - If the new severity **escalates** the tier (e.g. suspicious → critical), or no
    ///   existing advisory is found, push a new entry.
    /// Returns `true` when a new advisory was inserted, `false` when updated in place.
    pub fn upsert_or_push(&mut self, new_adv: SecurityAdvisory) -> bool {
        let new_rank = Self::severity_rank(&new_adv.severity_label);

        // Find an active advisory for the same target IP that is still actionable
        // (pending or auto_executed — not yet approved/rejected by a human).
        if let Some(existing) = self.advisories.iter_mut().find(|a| {
            a.plan.target_ip == new_adv.plan.target_ip
                && matches!(a.status, AdvisoryStatus::Pending | AdvisoryStatus::AutoExecuted)
        }) {
            let existing_rank = Self::severity_rank(&existing.severity_label);

            if new_rank > existing_rank {
                // Severity escalated — push as a new, separate advisory so the
                // admin can see the escalation event clearly.
                // Fall through to insert below.
            } else {
                // Same or lower severity: update in place.
                existing.title = new_adv.title;
                existing.severity_label = new_adv.severity_label;
                existing.plan.score = new_adv.plan.score;
                existing.plan.justification = new_adv.plan.justification;
                existing.plan.auto_execute = new_adv.plan.auto_execute;
                existing.plan.requires_approval = new_adv.plan.requires_approval;
                existing.updated_at = Utc::now();
                return false; // updated, not inserted
            }
        }

        // No match or severity escalated — insert as new.
        if self.advisories.len() >= self.max_entries {
            self.advisories.remove(0);
        }
        self.advisories.push(new_adv);
        true
    }

    /// Lists all stored advisories, optionally filtered by `AdvisoryStatus`.
    pub fn list(&self, status_filter: Option<AdvisoryStatus>) -> Vec<SecurityAdvisory> {
        match status_filter {
            Some(status) => self
                .advisories
                .iter()
                .filter(|a| a.status == status)
                .cloned()
                .collect(),
            None => self.advisories.clone(),
        }
    }

    /// Retrieves an advisory by its `advisory_id`.
    pub fn get_by_id(&self, id: &str) -> Option<&SecurityAdvisory> {
        self.advisories.iter().find(|a| a.advisory_id == id)
    }

    /// Approves a pending advisory by ID.
    /// Updates status to `Approved` and sets `resolved_at`.
    pub fn approve(&mut self, id: &str) -> Option<SecurityAdvisory> {
        if let Some(advisory) = self.advisories.iter_mut().find(|a| a.advisory_id == id) {
            if advisory.status == AdvisoryStatus::Pending {
                advisory.status = AdvisoryStatus::Approved;
                advisory.resolved_at = Some(Utc::now());
                advisory.updated_at = Utc::now();
                return Some(advisory.clone());
            }
        }
        None
    }

    /// Rejects a pending advisory by ID.
    /// Updates status to `Rejected` and sets `resolved_at`.
    pub fn reject(&mut self, id: &str) -> Option<SecurityAdvisory> {
        if let Some(advisory) = self.advisories.iter_mut().find(|a| a.advisory_id == id) {
            if advisory.status == AdvisoryStatus::Pending {
                advisory.status = AdvisoryStatus::Rejected;
                advisory.resolved_at = Some(Utc::now());
                advisory.updated_at = Utc::now();
                return Some(advisory.clone());
            }
        }
        None
    }

    /// Returns the number of currently pending advisories.
    pub fn pending_count(&self) -> usize {
        self.advisories
            .iter()
            .filter(|a| a.status == AdvisoryStatus::Pending)
            .count()
    }

    /// Total count of advisories stored.
    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    /// Checks if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }
}

impl Default for AdvisoryStore {
    fn default() -> Self {
        Self::default_capacity()
    }
}

/// Formats a `RemediationPlan` into a complete `SecurityAdvisory`.
pub fn format_advisory(plan: RemediationPlan) -> SecurityAdvisory {
    let score_val = plan.score.score;

    let severity_label = if score_val >= 0.90 {
        "critical"
    } else if score_val >= 0.75 {
        "elevated"
    } else {
        "suspicious"
    };

    let title_prefix = match severity_label {
        "critical" => "[CRITICAL]",
        "elevated" => "[ELEVATED]",
        _ => "[SUSPICIOUS]",
    };

    let title = format!(
        "{} {} Threat from {} (Score: {:.2})",
        title_prefix,
        plan.score.category.as_str().to_uppercase(),
        plan.target_ip,
        score_val
    );

    let status = if plan.requires_approval.is_empty() {
        AdvisoryStatus::AutoExecuted
    } else {
        AdvisoryStatus::Pending
    };

    let short_uuid = &plan.plan_id[..8];
    let advisory_id = format!("adv-{}", short_uuid);

    let now = Utc::now();
    SecurityAdvisory {
        advisory_id,
        title,
        severity_label: severity_label.to_string(),
        plan,
        status,
        created_at: now,
        updated_at: now,
        resolved_at: if status == AdvisoryStatus::AutoExecuted {
            Some(now)
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{
        alert_scorer::AlertAnomalyScore, remediation::generate_plan, threat_alert::ThreatCategory,
    };

    fn make_score(val: f32, cat: ThreatCategory) -> AlertAnomalyScore {
        AlertAnomalyScore {
            score: val,
            contributing_ip: "192.168.1.105".to_string(),
            alert_count: 50,
            top_signature_id: 2009358,
            category: cat,
            computed_at: Utc::now(),
            window_secs: 300,
        }
    }

    #[test]
    fn test_advisory_title_critical() {
        let score = make_score(0.92, ThreatCategory::Reconnaissance);
        let plan = generate_plan(score).unwrap();
        let adv = format_advisory(plan);

        assert!(adv.title.starts_with("[CRITICAL]"));
        assert_eq!(adv.severity_label, "critical");
        assert_eq!(adv.status, AdvisoryStatus::Pending); // Has approval actions
    }

    #[test]
    fn test_advisory_title_elevated() {
        let score = make_score(0.80, ThreatCategory::PolicyViolation);
        let plan = generate_plan(score).unwrap();
        let adv = format_advisory(plan);

        assert!(adv.title.starts_with("[ELEVATED]"));
        assert_eq!(adv.severity_label, "elevated");
    }

    #[test]
    fn test_advisory_auto_executed_status() {
        let score = make_score(0.60, ThreatCategory::Other);
        let plan = generate_plan(score).unwrap();
        let adv = format_advisory(plan);

        assert_eq!(adv.status, AdvisoryStatus::AutoExecuted);
        assert!(adv.resolved_at.is_some());
    }

    #[test]
    fn test_advisory_store_push_and_list() {
        let mut store = AdvisoryStore::default();
        let score1 = make_score(0.80, ThreatCategory::Reconnaissance);
        let score2 = make_score(0.60, ThreatCategory::Other);

        store.push(format_advisory(generate_plan(score1).unwrap()));
        store.push(format_advisory(generate_plan(score2).unwrap()));

        assert_eq!(store.len(), 2);
        assert_eq!(store.list(None).len(), 2);
        assert_eq!(store.list(Some(AdvisoryStatus::Pending)).len(), 1);
        assert_eq!(store.list(Some(AdvisoryStatus::AutoExecuted)).len(), 1);
    }

    #[test]
    fn test_advisory_approve_changes_status() {
        let mut store = AdvisoryStore::default();
        let score = make_score(0.85, ThreatCategory::Exploit);
        let adv = format_advisory(generate_plan(score).unwrap());
        let adv_id = adv.advisory_id.clone();

        store.push(adv);
        assert_eq!(store.pending_count(), 1);

        let approved = store.approve(&adv_id);
        assert!(approved.is_some());
        let approved = approved.unwrap();
        assert_eq!(approved.status, AdvisoryStatus::Approved);
        assert!(approved.resolved_at.is_some());
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn test_advisory_reject_changes_status() {
        let mut store = AdvisoryStore::default();
        let score = make_score(0.85, ThreatCategory::Exploit);
        let adv = format_advisory(generate_plan(score).unwrap());
        let adv_id = adv.advisory_id.clone();

        store.push(adv);
        let rejected = store.reject(&adv_id);
        assert!(rejected.is_some());
        assert_eq!(rejected.unwrap().status, AdvisoryStatus::Rejected);
    }

    #[test]
    fn test_advisory_store_eviction() {
        let mut store = AdvisoryStore::new(2);
        let s1 = make_score(0.80, ThreatCategory::Reconnaissance);
        let s2 = make_score(0.85, ThreatCategory::Exploit);
        let s3 = make_score(0.90, ThreatCategory::Malware);

        let adv1 = format_advisory(generate_plan(s1).unwrap());
        let id1 = adv1.advisory_id.clone();
        store.push(adv1);
        store.push(format_advisory(generate_plan(s2).unwrap()));
        store.push(format_advisory(generate_plan(s3).unwrap()));

        assert_eq!(store.len(), 2);
        assert!(
            store.get_by_id(&id1).is_none(),
            "Oldest advisory should be evicted"
        );
    }
}
