//! sgx-anomaly-engine — standalone anomaly detection engine.
//!
//! Depends on NOTHING from SGX. Talks to the outside world only through
//! two traits: `telemetry::TelemetrySource` and `alert::AlertSink`.
//! See Part B of the plan for the architecture.

pub mod alert;
pub mod baseline;
pub mod engine;
pub mod features;
pub mod model;
pub mod policy;
pub mod policy_candidate;
pub mod port_detection;
pub mod port_knowledge;
pub mod port_recommendation;
pub mod port_risk;
pub mod port_security;
pub mod recorder;
pub mod roles;
pub mod rules;
pub mod security_context;
pub mod telemetry;
pub mod virtual_shift;

// Re-export the most commonly used items at the crate root.
pub use alert::{AlertSink, AnomalyAlert};
pub use engine::AnomalyEngine;
pub use telemetry::{RawSample, TelemetrySource};
