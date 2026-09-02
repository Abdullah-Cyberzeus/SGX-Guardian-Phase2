//! Stable, human-readable evidence locations for the Virtual Shift phases.
//! Folder names describe what was saved, so an operator does not need to know
//! the internal VS stage numbers to understand the evidence.

// These are evidence stages, not internal VS numbers.  The numeric prefix
// makes their execution order obvious when viewing the data directory.
pub const VS01_TO_VS09_PROPOSALS: &str = "01_ANOMALY_POLICY_PROPOSALS";
pub const VS10_VS11_REVIEWS: &str = "02_OWNER_REVIEW_DECISIONS";
pub const VS12_CANDIDATES: &str = "04_POLICY_CANDIDATES";
pub const VS13_SIGNED_POLICIES: &str = "05_SIGNED_POLICY_PACKAGES";
pub const VS14_ALERTS: &str = "06_SIGNED_POLICY_ALERTS";
pub const VS15_GOSSIP: &str = "07_POLICY_DELIVERY_RECEIPTS";
pub const VS16_MEMBER_VERIFICATION: &str = "08_MEMBER_POLICY_VERIFICATION";
pub const VS17_MEMBER_POLICY_STATE: &str = "09_MEMBER_ACTIVE_POLICIES";
pub const VS18_MEMBER_IDENTITY_STATE: &str = "10_MEMBER_IDENTITY_AND_ATTESTATION";
pub const VS19_AUDIT: &str = "11_POLICY_AUDIT_TRAILS";
pub const VS19_OVERRIDES: &str = "14_FALSE_POSITIVE_POLICY_OVERRIDES";
pub const VS20_FINAL_VERIFICATION: &str = "13_FINAL_POLICY_LIFECYCLE_CHECKS";
