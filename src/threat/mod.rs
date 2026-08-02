//! Suricata IDS/IPS integration.
//!
//! Responsibilities:
//!   - Tail `/var/log/suricata/eve.json` asynchronously without blocking.
//!   - Parse EVE JSONL into [`ThreatAlert`] entities.
//!   - Maintain a rolling alert ring buffer (10,000 alerts, in-memory + persisted).
//!   - Translate High/Critical alerts into ephemeral nftables drop rules
//!     in a dedicated `inet sgx_threat` table.
//!   - Forward alerts to the AI anomaly engine (stub for now; integration point reserved).
//!   - Schedule daily `suricata-update` runs for rule freshness.
//!
//! All subprocesses use `tokio::process::Command`, the tailer uses `tokio::fs`,
//! and writes are atomic (temp file + rename).

pub mod ai_bridge;
pub mod analytics;
pub mod anomaly;
pub mod blocker;
pub mod config;
pub mod error;
pub mod errors;
pub mod eve_parser;
pub mod eve_tailer;
pub mod incident;
pub mod inventory;
pub mod peer_scorer;
pub mod rule_manager;
pub mod service;
pub mod threat_alert;
pub mod threat_rules;

pub use analytics::{ThreatAnalytics, ThreatEvent};
pub use anomaly::{AnomalyDetector, AnomalyScore, AnomalyType};
pub use config::{BlockMode, SuricataConfig};
pub use error::{ThreatError, ThreatResult};
pub use incident::{Incident, IncidentManager, IncidentResponse, IncidentSeverity};
pub use inventory::AlertInventory;
pub use peer_scorer::{PeerScorer, PeerThreatScore};
pub use service::ThreatService;
pub use threat_alert::{Severity, ThreatAlert, ThreatCategory};
pub use threat_rules::{ThreatAction, ThreatRule, ThreatRuleEngine};
