//! NMAP-driven network discovery and device profiling.
//!
//! This module is responsible for:
//!   - Periodically scanning the Guardian's primary LAN segment with `nmap`.
//!   - Parsing NMAP XML into the `ConnectedDevice` entity.
//!   - Persisting an inventory under `/var/lib/sgx-guardian/discovery/`.
//!   - Flagging devices not in the admin-curated whitelist.
//!   - Forwarding discovery deltas to the AI threat-prediction layer
//!     for vulnerability triage.
//!
//! Designed to be safe to spawn as a tokio task: every subprocess is async,
//! every file write is atomic, and every loop honours a shutdown channel.

pub mod config;
pub mod connected_device;
pub mod error;
pub mod inventory;
pub mod nmap_parser;
pub mod nmap_runner;
pub mod raw_store;
pub mod run_history;
pub mod scheduler;
pub mod vuln_trigger;
pub mod whitelist;

pub use config::{
    NmapConfig, ScanIntensity, ScanSchedule, ScheduleDay, ScheduleFrequency, ScheduleProfile,
    ScanScheduleProfile, ScheduledScanKind, ScheduledScans,
};
pub use connected_device::{ConnectedDevice, DeviceStatus, OpenPort, ScriptResult};
pub use error::{DiscoveryError, DiscoveryResult};
pub use inventory::Inventory;
pub use nmap_runner::NmapRunner;
pub use scheduler::DiscoveryScheduler;
