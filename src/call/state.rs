//! Call state machine - implements all 10 states and transitions.
//! Ensures state changes are valid and atomic.

use crate::call::error::{CallError, CallResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// All 10 states in the call lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CallState {
    /// Initial state - no call in progress
    Idle,

    /// Local UEP policy check running
    LocalPolicyCheck,

    /// Call offer sent to remote device
    OfferSent,

    /// Call offer received from remote device
    OfferReceived,

    /// Verification pipeline running (5-stage auth chain)
    Verifying,

    /// Authorization check running
    Authorizing,

    /// Both devices agreed to call - proceeding to media negotiation
    Accepted,

    /// Media negotiation in progress (ICE, DTLS)
    MediaNegotiation,

    /// Call active - media flowing
    Connected,

    /// Call ended (terminal state)
    EndCall,
}

impl fmt::Display for CallState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallState::Idle => write!(f, "Idle"),
            CallState::LocalPolicyCheck => write!(f, "LocalPolicyCheck"),
            CallState::OfferSent => write!(f, "OfferSent"),
            CallState::OfferReceived => write!(f, "OfferReceived"),
            CallState::Verifying => write!(f, "Verifying"),
            CallState::Authorizing => write!(f, "Authorizing"),
            CallState::Accepted => write!(f, "Accepted"),
            CallState::MediaNegotiation => write!(f, "MediaNegotiation"),
            CallState::Connected => write!(f, "Connected"),
            CallState::EndCall => write!(f, "EndCall"),
        }
    }
}

impl CallState {
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            CallState::Idle => "idle",
            CallState::LocalPolicyCheck => "local_policy_check",
            CallState::OfferSent => "offer_sent",
            CallState::OfferReceived => "offer_received",
            CallState::Verifying => "verifying",
            CallState::Authorizing => "authorizing",
            CallState::Accepted => "accepted",
            CallState::MediaNegotiation => "media_negotiation",
            CallState::Connected => "connected",
            CallState::EndCall => "ended",
        }
    }

    /// Check if a transition from `self` to `next` is valid.
    /// Returns error if transition is invalid.
    pub fn validate_transition(&self, next: CallState) -> CallResult<()> {
        let valid = match (*self, next) {
            // From Idle
            (CallState::Idle, CallState::LocalPolicyCheck) => true,
            (CallState::Idle, CallState::OfferReceived) => true,
            (CallState::Idle, CallState::EndCall) => true,

            // From LocalPolicyCheck
            (CallState::LocalPolicyCheck, CallState::OfferSent) => true,
            (CallState::LocalPolicyCheck, CallState::EndCall) => true,

            // From OfferSent
            (CallState::OfferSent, CallState::Verifying) => true,
            (CallState::OfferSent, CallState::EndCall) => true,

            // From OfferReceived
            (CallState::OfferReceived, CallState::Verifying) => true,
            (CallState::OfferReceived, CallState::EndCall) => true,

            // From Verifying
            (CallState::Verifying, CallState::Authorizing) => true,
            (CallState::Verifying, CallState::EndCall) => true,

            // From Authorizing
            (CallState::Authorizing, CallState::Accepted) => true,
            (CallState::Authorizing, CallState::EndCall) => true,

            // From Accepted
            (CallState::Accepted, CallState::MediaNegotiation) => true,
            (CallState::Accepted, CallState::EndCall) => true,

            // From MediaNegotiation
            (CallState::MediaNegotiation, CallState::Connected) => true,
            (CallState::MediaNegotiation, CallState::EndCall) => true,

            // From Connected
            (CallState::Connected, CallState::EndCall) => true,

            // From EndCall (terminal - no transitions out)
            (CallState::EndCall, _) => false,

            // All other transitions are invalid
            _ => false,
        };

        if valid {
            Ok(())
        } else {
            Err(CallError::InvalidStateTransition {
                from: self.to_string(),
                to: next.to_string(),
            })
        }
    }

    /// Returns true if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        *self == CallState::EndCall
    }

    /// Get all reachable states from current state
    pub fn reachable_from(&self) -> Vec<CallState> {
        match self {
            CallState::Idle => vec![
                CallState::LocalPolicyCheck,
                CallState::OfferReceived,
                CallState::EndCall,
            ],
            CallState::LocalPolicyCheck => vec![CallState::OfferSent, CallState::EndCall],
            CallState::OfferSent => vec![CallState::Verifying, CallState::EndCall],
            CallState::OfferReceived => vec![CallState::Verifying, CallState::EndCall],
            CallState::Verifying => vec![CallState::Authorizing, CallState::EndCall],
            CallState::Authorizing => vec![CallState::Accepted, CallState::EndCall],
            CallState::Accepted => vec![CallState::MediaNegotiation, CallState::EndCall],
            CallState::MediaNegotiation => vec![CallState::Connected, CallState::EndCall],
            CallState::Connected => vec![CallState::EndCall],
            CallState::EndCall => vec![], // No transitions out of terminal state
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        // Happy path: Idle -> LocalPolicyCheck -> OfferSent -> Verifying -> Authorizing -> Accepted -> MediaNegotiation -> Connected -> EndCall
        let states = [
            CallState::Idle,
            CallState::LocalPolicyCheck,
            CallState::OfferSent,
            CallState::Verifying,
            CallState::Authorizing,
            CallState::Accepted,
            CallState::MediaNegotiation,
            CallState::Connected,
            CallState::EndCall,
        ];

        for i in 0..states.len() - 1 {
            assert!(states[i].validate_transition(states[i + 1]).is_ok());
        }
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot jump directly from Idle to Connected
        assert!(CallState::Idle
            .validate_transition(CallState::Connected)
            .is_err());

        // Cannot transition out of EndCall
        assert!(CallState::EndCall
            .validate_transition(CallState::Idle)
            .is_err());

        // Cannot go backwards
        assert!(CallState::Verifying
            .validate_transition(CallState::OfferSent)
            .is_err());
    }

    #[test]
    fn test_terminal_state() {
        assert!(CallState::EndCall.is_terminal());
        assert!(!CallState::Connected.is_terminal());
        assert!(!CallState::Idle.is_terminal());
    }

    #[test]
    fn test_all_states_reachable() {
        // Verify no orphaned states (all non-terminal states have outgoing edges)
        for state in &[
            CallState::Idle,
            CallState::LocalPolicyCheck,
            CallState::OfferSent,
            CallState::OfferReceived,
            CallState::Verifying,
            CallState::Authorizing,
            CallState::Accepted,
            CallState::MediaNegotiation,
            CallState::Connected,
        ] {
            assert!(
                !state.reachable_from().is_empty(),
                "State {} has no outgoing edges",
                state
            );
        }
    }

    #[test]
    fn test_receiver_path() {
        // Receiver path: Idle -> OfferReceived -> Verifying -> Authorizing -> Accepted -> MediaNegotiation -> Connected -> EndCall
        assert!(CallState::Idle
            .validate_transition(CallState::OfferReceived)
            .is_ok());
        assert!(CallState::OfferReceived
            .validate_transition(CallState::Verifying)
            .is_ok());
        assert!(CallState::Verifying
            .validate_transition(CallState::Authorizing)
            .is_ok());
    }

    #[test]
    fn test_early_rejection() {
        // Can go to EndCall from any state (except EndCall itself)
        for state in &[
            CallState::Idle,
            CallState::LocalPolicyCheck,
            CallState::OfferSent,
            CallState::OfferReceived,
            CallState::Verifying,
            CallState::Authorizing,
            CallState::Accepted,
            CallState::MediaNegotiation,
            CallState::Connected,
        ] {
            assert!(state.validate_transition(CallState::EndCall).is_ok());
        }
    }
}
