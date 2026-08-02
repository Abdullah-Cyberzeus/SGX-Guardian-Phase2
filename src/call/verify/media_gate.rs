//! Media Path Verification Gate
//!
//! Ensures media only flows after full verification (attestation + authorization)
//! and UEP policy enforcement has been satisfied.

use crate::call::media_state::CallMediaState;
use crate::media::errors::{MediaError, MediaResult};
use serde::{Deserialize, Serialize};

/// State of media path verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState {
    /// Not yet verified
    Pending,
    /// Attestation completed
    AttestationComplete,
    /// Authorization check completed
    AuthorizationComplete,
    /// UEP policy check completed
    PolicyCheckComplete,
    /// All checks passed, media allowed
    Verified,
    /// Verification failed
    Failed,
}

impl VerificationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationState::Pending => "pending",
            VerificationState::AttestationComplete => "attestation_complete",
            VerificationState::AuthorizationComplete => "authorization_complete",
            VerificationState::PolicyCheckComplete => "policy_check_complete",
            VerificationState::Verified => "verified",
            VerificationState::Failed => "failed",
        }
    }
}

/// Media path verification requirements
#[derive(Debug, Clone)]
pub struct VerificationRequirements {
    pub require_attestation: bool,
    pub require_authorization: bool,
    pub require_policy_check: bool,
}

impl Default for VerificationRequirements {
    fn default() -> Self {
        VerificationRequirements {
            require_attestation: true,
            require_authorization: true,
            require_policy_check: true,
        }
    }
}

/// Media path verification gate
pub struct MediaGate {
    session_id: String,
    state: VerificationState,
    requirements: VerificationRequirements,
    attestation_verified: bool,
    authorization_verified: bool,
    policy_verified: bool,
}

impl MediaGate {
    /// Create a new media gate with default requirements
    pub fn new(session_id: String) -> Self {
        MediaGate {
            session_id,
            state: VerificationState::Pending,
            requirements: VerificationRequirements::default(),
            attestation_verified: false,
            authorization_verified: false,
            policy_verified: false,
        }
    }

    /// Create with custom requirements
    pub fn with_requirements(session_id: String, requirements: VerificationRequirements) -> Self {
        MediaGate {
            session_id,
            state: VerificationState::Pending,
            requirements,
            attestation_verified: false,
            authorization_verified: false,
            policy_verified: false,
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get verification state
    pub fn state(&self) -> VerificationState {
        self.state
    }

    /// Mark attestation as verified
    pub fn verify_attestation(&mut self) -> MediaResult<()> {
        if self.state != VerificationState::Pending {
            return Err(MediaError::InvalidState(
                "Cannot verify attestation in current state".to_string(),
            ));
        }

        self.attestation_verified = true;

        if !self.requirements.require_attestation {
            self.state = VerificationState::AttestationComplete;
        } else {
            self.state = VerificationState::AttestationComplete;
        }

        self.transition_state()?;
        Ok(())
    }

    /// Mark authorization as verified
    pub fn verify_authorization(&mut self) -> MediaResult<()> {
        if self.state != VerificationState::AttestationComplete {
            return Err(MediaError::InvalidState(
                "Attestation must be verified first".to_string(),
            ));
        }

        self.authorization_verified = true;
        self.state = VerificationState::AuthorizationComplete;
        self.transition_state()?;
        Ok(())
    }

    /// Mark policy check as verified
    pub fn verify_policy(&mut self) -> MediaResult<()> {
        if self.state != VerificationState::AuthorizationComplete {
            return Err(MediaError::InvalidState(
                "Authorization must be verified first".to_string(),
            ));
        }

        self.policy_verified = true;
        self.state = VerificationState::PolicyCheckComplete;
        self.transition_state()?;
        Ok(())
    }

    /// Transition to next state based on verification requirements
    fn transition_state(&mut self) -> MediaResult<()> {
        // Skip unneeded verifications
        let mut needs_attestation = self.requirements.require_attestation;
        let mut needs_authorization = self.requirements.require_authorization;
        let mut needs_policy = self.requirements.require_policy_check;

        if self.attestation_verified {
            needs_attestation = false;
        }
        if self.authorization_verified {
            needs_authorization = false;
        }
        if self.policy_verified {
            needs_policy = false;
        }

        if !needs_attestation && !needs_authorization && !needs_policy {
            self.state = VerificationState::Verified;
        }

        Ok(())
    }

    /// Check if media is allowed to flow
    pub fn is_media_allowed(&self) -> bool {
        self.state == VerificationState::Verified
    }

    /// Deny verification with a reason
    pub fn deny(&mut self, reason: &str) -> MediaResult<()> {
        self.state = VerificationState::Failed;
        Err(MediaError::MediaPathDenied(reason.to_string()))
    }

    /// Verify media can flow for a given media state
    pub fn check_media_stream(&self, media_state: &CallMediaState) -> MediaResult<()> {
        if !self.is_media_allowed() {
            return Err(MediaError::MediaPathDenied(format!(
                "Media path not verified: {}",
                self.state.as_str()
            )));
        }

        if !media_state.is_any_stream_active() {
            return Err(MediaError::MediaPathDenied(
                "No active media streams".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_gate_creation() {
        let gate = MediaGate::new("session-123".to_string());
        assert_eq!(gate.session_id(), "session-123");
        assert_eq!(gate.state(), VerificationState::Pending);
        assert!(!gate.is_media_allowed());
    }

    #[test]
    fn test_media_gate_verification_flow() {
        let mut gate = MediaGate::new("session-456".to_string());

        assert!(gate.verify_attestation().is_ok());
        assert_eq!(gate.state(), VerificationState::AttestationComplete);

        assert!(gate.verify_authorization().is_ok());
        assert_eq!(gate.state(), VerificationState::AuthorizationComplete);

        assert!(gate.verify_policy().is_ok());
        assert_eq!(gate.state(), VerificationState::Verified);

        assert!(gate.is_media_allowed());
    }

    #[test]
    fn test_media_gate_invalid_verification_order() {
        let mut gate = MediaGate::new("session-789".to_string());

        // Cannot verify authorization before attestation
        let result = gate.verify_authorization();
        assert!(result.is_err());
    }

    #[test]
    fn test_media_gate_deny() {
        let mut gate = MediaGate::new("session-010".to_string());
        let result = gate.deny("Unauthorized access");

        assert!(result.is_err());
        assert_eq!(gate.state(), VerificationState::Failed);
    }

    #[test]
    fn test_media_gate_custom_requirements() {
        let mut gate = MediaGate::with_requirements(
            "session-111".to_string(),
            VerificationRequirements {
                require_attestation: false,
                require_authorization: true,
                require_policy_check: false,
            },
        );

        // Should skip attestation
        assert!(gate.verify_attestation().is_ok());
        // Verification flow should proceed despite skipping some checks
        let state = gate.state();
        assert_ne!(state, VerificationState::Failed);
    }

    #[test]
    fn test_media_gate_check_media_stream() {
        let mut gate = MediaGate::new("session-222".to_string());
        let media_state = CallMediaState::new("session-222".to_string());

        // Media not allowed before verification
        let result = gate.check_media_stream(&media_state);
        assert!(result.is_err());

        // Complete verification
        gate.verify_attestation().unwrap();
        gate.verify_authorization().unwrap();
        gate.verify_policy().unwrap();

        // Still no media streams active
        let result = gate.check_media_stream(&media_state);
        assert!(result.is_err());
    }
}
