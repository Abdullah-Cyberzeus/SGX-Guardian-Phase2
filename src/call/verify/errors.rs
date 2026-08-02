//! Verification pipeline errors — one variant per stage plus pipeline-level errors.

use thiserror::Error;

/// Stage that produced the failure, used for audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStage {
    Cert,
    Crl,
    Attestation,
    PolicyDigest,
    VirtualId,
    Pipeline,
}

impl VerifyStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerifyStage::Cert => "cert",
            VerifyStage::Crl => "crl",
            VerifyStage::Attestation => "attestation",
            VerifyStage::PolicyDigest => "policy_digest",
            VerifyStage::VirtualId => "virtual_id",
            VerifyStage::Pipeline => "pipeline",
        }
    }
}

impl std::fmt::Display for VerifyStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum VerifyError {
    // ── Stage 1: Certificate ────────────────────────────────────────────────
    #[error("cert: expired (device_id={device_id})")]
    CertExpired { device_id: String },

    #[error("cert: not yet valid (device_id={device_id})")]
    CertNotYetValid { device_id: String },

    #[error("cert: invalid issuer signature (device_id={device_id})")]
    CertBadSignature { device_id: String },

    #[error("cert: malformed encoding (device_id={device_id}, reason={reason})")]
    CertMalformed { device_id: String, reason: String },

    #[error("cert: missing (device_id={device_id})")]
    CertMissing { device_id: String },

    // ── Stage 2: CRL ────────────────────────────────────────────────────────
    #[error("crl: device revoked (device_id={device_id}, serial={serial})")]
    CrlRevoked { device_id: String, serial: String },

    #[error("crl: cache unavailable and live fetch failed (device_id={device_id})")]
    CrlUnavailable { device_id: String },

    #[error("crl: refresh failed — using expired cache (device_id={device_id})")]
    CrlStale { device_id: String },

    // ── Stage 3: Attestation ────────────────────────────────────────────────
    #[error("attestation: PCR mismatch (device_id={device_id}, pcr_index={pcr_index})")]
    AttestationPcrMismatch { device_id: String, pcr_index: u32 },

    #[error("attestation: quote timestamp stale (device_id={device_id}, age_secs={age_secs})")]
    AttestationQuoteStale { device_id: String, age_secs: u64 },

    #[error("attestation: enclave measurement invalid (device_id={device_id})")]
    AttestationMeasurementInvalid { device_id: String },

    #[error("attestation: no trusted quote present (device_id={device_id})")]
    AttestationMissing { device_id: String },

    #[error("attestation: verification service error (device_id={device_id}, reason={reason})")]
    AttestationServiceError { device_id: String, reason: String },

    // ── Stage 4: Policy Digest ──────────────────────────────────────────────
    #[error("policy_digest: mismatch (device_id={device_id}, local={local}, remote={remote})")]
    PolicyDigestMismatch {
        device_id: String,
        local: String,
        remote: String,
    },

    #[error("policy_digest: missing from offer (device_id={device_id})")]
    PolicyDigestMissing { device_id: String },

    #[error("policy_digest: local policy unavailable (device_id={device_id})")]
    PolicyDigestLocalUnavailable { device_id: String },

    // ── Stage 5: VirtualID ──────────────────────────────────────────────────
    #[error("virtual_id: invalid encoding (device_id={device_id})")]
    VirtualIdMalformed { device_id: String },

    #[error("virtual_id: cannot resolve to device identity (virtual_id={virtual_id})")]
    VirtualIdUnresolvable { virtual_id: String },

    #[error("virtual_id: chain to device cert broken (virtual_id={virtual_id})")]
    VirtualIdChainBroken { virtual_id: String },

    #[error("virtual_id: expired (virtual_id={virtual_id})")]
    VirtualIdExpired { virtual_id: String },

    // ── Pipeline ─────────────────────────────────────────────────────────────
    #[error("pipeline: stage {stage} failed — call rejected")]
    PipelineStageFailed { stage: String },

    #[error("pipeline: internal error — {reason}")]
    PipelineInternal { reason: String },
}

impl VerifyError {
    /// Which stage produced this error (for audit logging).
    pub fn stage(&self) -> VerifyStage {
        match self {
            VerifyError::CertExpired { .. }
            | VerifyError::CertNotYetValid { .. }
            | VerifyError::CertBadSignature { .. }
            | VerifyError::CertMalformed { .. }
            | VerifyError::CertMissing { .. } => VerifyStage::Cert,

            VerifyError::CrlRevoked { .. }
            | VerifyError::CrlUnavailable { .. }
            | VerifyError::CrlStale { .. } => VerifyStage::Crl,

            VerifyError::AttestationPcrMismatch { .. }
            | VerifyError::AttestationQuoteStale { .. }
            | VerifyError::AttestationMeasurementInvalid { .. }
            | VerifyError::AttestationMissing { .. }
            | VerifyError::AttestationServiceError { .. } => VerifyStage::Attestation,

            VerifyError::PolicyDigestMismatch { .. }
            | VerifyError::PolicyDigestMissing { .. }
            | VerifyError::PolicyDigestLocalUnavailable { .. } => VerifyStage::PolicyDigest,

            VerifyError::VirtualIdMalformed { .. }
            | VerifyError::VirtualIdUnresolvable { .. }
            | VerifyError::VirtualIdChainBroken { .. }
            | VerifyError::VirtualIdExpired { .. } => VerifyStage::VirtualId,

            VerifyError::PipelineStageFailed { .. }
            | VerifyError::PipelineInternal { .. } => VerifyStage::Pipeline,
        }
    }
}

pub type VerifyResult<T> = Result<T, VerifyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_attribution_cert() {
        let e = VerifyError::CertExpired { device_id: "d1".into() };
        assert_eq!(e.stage(), VerifyStage::Cert);
    }

    #[test]
    fn stage_attribution_crl() {
        let e = VerifyError::CrlRevoked { device_id: "d1".into(), serial: "abc".into() };
        assert_eq!(e.stage(), VerifyStage::Crl);
    }

    #[test]
    fn stage_attribution_attestation() {
        let e = VerifyError::AttestationMissing { device_id: "d1".into() };
        assert_eq!(e.stage(), VerifyStage::Attestation);
    }

    #[test]
    fn stage_attribution_policy() {
        let e = VerifyError::PolicyDigestMismatch {
            device_id: "d1".into(),
            local: "aaa".into(),
            remote: "bbb".into(),
        };
        assert_eq!(e.stage(), VerifyStage::PolicyDigest);
    }

    #[test]
    fn stage_attribution_virtualid() {
        let e = VerifyError::VirtualIdExpired { virtual_id: "vid-xyz".into() };
        assert_eq!(e.stage(), VerifyStage::VirtualId);
    }
}
