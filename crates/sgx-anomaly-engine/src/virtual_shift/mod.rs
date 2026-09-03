//! Virtual Shift boundary.
//!
//! This module starts *after* Task 1 has detected an anomaly.  It never
//! changes the locked 19-feature schema, scoring models, thresholds, or alert
//! decision.  The first deliverable normalizes a Task 1 alert into a validated
//! event that later Virtual Shift phases can safely consume.

pub mod alert;
pub mod apply;
pub mod approval;
pub mod attestation;
pub mod audit;
pub mod errors;
pub mod evidence;
pub mod gossip;
pub mod hardening;
pub mod identity;
pub mod integration;
pub mod justification;
pub mod manual_override;
pub mod model;
pub mod policy_builder;
pub mod recommendation;
pub mod review;
pub mod routing_trust;
pub mod signing;
pub mod trigger;
pub mod verify;

pub use alert::{
    vshift_alert_from_signed_policy, write_vshift_alert, VShiftAlert, MAX_ALERT_TTL_MS,
    MAX_POLICY_BLOB_BYTES, MAX_VSHIFT_ALERT_BYTES, VSHIFT_ALERT_SCHEMA_VERSION,
};
pub use apply::{
    MemberPolicyApplier, MemberPolicyApplyResult, MemberPolicyStateSummary, PolicyApplyStatus,
    PolicyBackupSummary,
};
pub use approval::ApprovalService;
pub use attestation::{
    AttestationConnector, AttestationConnectorResponse, AttestationRequest,
    MockAttestationConnector, MockAttestationOutcome, ReAttestationResult, ReAttestationService,
    ReAttestationStatus,
};
pub use audit::{AuditService, AuditStep, PolicyAuditTrail};
pub use errors::VirtualShiftError;
pub use evidence::*;
pub use gossip::{
    write_gossip_receipt, GossipBroadcastReceipt, GossipDelivery, GossipDeliveryTiming,
    GossipMessageType, GossipTopology, GossipTransport, InMemoryGossipTransport,
};
pub use hardening::{FinalHardeningVerifier, FinalVerificationReport};
pub use identity::{
    AttestationState, IdentityRotationResult, IdentityRotationStatus, MemberIdentityRotator,
    VirtualIdentityState,
};
pub use integration::{
    anomaly_event_from_alert, anomaly_event_from_task1_record, task1_virtual_shift_handoff_record,
    Task1VirtualShiftHandoff, TriggerGateSnapshot,
};
pub use justification::{
    justification_from_aggregate, JustificationPackage, ProposalStageNote, SelectedActionReason,
    MAX_JUSTIFICATION_BYTES,
};
pub use manual_override::{ManualOverrideRecord, ManualOverrideService};
pub use model::{
    AnomalyEvent, AnomalyEventRegistration, AnomalyEventRegistry, AnomalyEvidence, AnomalyType,
};
pub use policy_builder::{
    add_owner_selected_rules, build_candidate_from_approved_review, canonical_policy_bytes,
    set_policy_targets, sha256_hex, write_built_candidate, ActiveVirtualShiftPolicy,
    AdminNetworkRuleTemplates, AdminRuleMatch, BuiltPolicyCandidate, NetworkPolicyRule,
    NetworkRuleAction, VersionedPolicyCandidate,
};
pub use recommendation::{
    aggregate_recommendations, attestation_recommendation_from_policy,
    firewall_recommendations_from_event, firewall_recommendations_with_context,
    logging_recommendation_from_policy, quarantine_recommendation_from_policy, read_recommendation,
    recommendation_from_event, write_recommendation, AggregatedAction, AggregatedRecommendation,
    AttestationProposalResult, AttestationRecommendation, FirewallProposalResult,
    FirewallRecommendation, LoggingProposalResult, LoggingRecommendation, LoggingScope,
    PolicyRecommendation, QuarantineProposalResult, QuarantineRecommendation, RecommendationStatus,
    RecommendedAction, RiskLevel, TrustedFirewallContext,
};
pub use review::{
    AiRemediationAction, AiRemediationHandoffResult, AiRemediationPlan, OwnerDecision, ReviewQueue,
    ReviewRecord, ReviewStatus,
};
pub use routing_trust::{
    RoutingTrustSources, RoutingTrustStatus, RoutingTrustSummary, RoutingTrustSummaryWriter,
};
pub use signing::{
    sign_approved_policy, verify_signed_policy, write_signed_policy, GuardianKeyManager,
    GuardianSignerConfig, SignedVirtualShiftPolicy,
};
pub use trigger::{TriggerDecision, VirtualShiftTriggerConfig, VirtualShiftTriggerManager};
pub use verify::{
    CircleGuardianAuthorization, GuardianTrustAnchor, MemberAlertVerifier,
    MemberVerificationResult, MemberVerificationState, VerificationStatus,
};
