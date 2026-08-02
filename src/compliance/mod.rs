//! Compliance & Audit Automation (Phase 6)
//!
//! Provides tamper-evident audit chain verification, SIEM export helpers,
//! compliance report generation, and incident playbook execution.

pub mod audit_chain;
pub mod siem;
pub mod report;
pub mod playbook;

pub use audit_chain::{AuditChain, AuditRecord};
pub use siem::{SiemExporter, SiemEvent};
pub use report::{ComplianceReport, ReportSummary};
pub use playbook::{Playbook, PlaybookStep, PlaybookRunner};

use crate::compliance::audit_chain::AuditChain as _AuditChain;
use crate::compliance::siem::SiemExporter as _SiemExporter;
use crate::compliance::report::ComplianceReport as _ComplianceReport;
use crate::compliance::playbook::PlaybookRunner as _PlaybookRunner;

#[derive(Clone)]
pub struct ComplianceEngine {
    pub audit_chain: _AuditChain,
    pub siem: _SiemExporter,
    pub playbook_runner: _PlaybookRunner,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        ComplianceEngine {
            audit_chain: _AuditChain::new(),
            siem: _SiemExporter::new(),
            playbook_runner: _PlaybookRunner::new(),
        }
    }

    pub fn verify_audit_chain(&self, records: &[AuditRecord]) -> bool {
        self.audit_chain.verify_chain(records)
    }

    pub fn export_event_to_siem(&self, ev: SiemEvent) -> Result<(), String> {
        self.siem.export(ev)
    }

    pub fn generate_report(&self, peer_id: &str) -> ComplianceReport {
        self.siem.flush();
        _ComplianceReport::generate(peer_id)
    }

    pub fn run_playbook(&mut self, pb: Playbook) -> Result<(), String> {
        self.playbook_runner.run(pb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::audit_chain::AuditRecord;

    #[test]
    fn test_compliance_engine_creation() {
        let engine = ComplianceEngine::new();
        assert_eq!(engine.audit_chain.records().len(), 0);
    }

    #[test]
    fn test_verify_empty_chain() {
        let engine = ComplianceEngine::new();
        let records: Vec<AuditRecord> = Vec::new();
        assert!(engine.verify_audit_chain(&records));
    }
}
