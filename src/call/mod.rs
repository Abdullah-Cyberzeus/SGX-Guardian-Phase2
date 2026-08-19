//! Call module - Secure peer-to-peer voice/video calling framework.
//!
//! Implements the Phase 1-4 architecture for call signaling, state management,
//! session tracking, media encryption, and UEP policy enforcement over Nebula overlay network.

pub mod error;
pub mod group;
pub mod history;
pub mod identity;
pub mod media_state;
pub mod nebula_signaling;
pub mod policy;
pub mod protocol;
pub mod session;
pub mod signal_hub;
pub mod signaling;
pub mod state;
pub mod uep_gate;
pub mod verify;

pub use error::{CallError, CallResult};
pub use group::{
    GroupCallState, GroupEvent, GroupMemberState, GroupParticipant, GroupRole, GroupSession,
    GroupSessionManager, GroupWireMessage, ModerationAction, MAX_GROUP_PARTICIPANTS,
};
pub use history::{CallHistoryRecord, CallHistoryStore};
pub use identity::{DidPeerIdentityResolver, PeerIdentityResolver, TrustedPeerIdentity};
pub use media_state::{
    AudioStream, CallMediaState, MediaStreamState, ScreenShareStream, VideoStream,
};
pub use nebula_signaling::NebulaSignaling;
pub use policy::{AllowAllEnforcer, CallPolicyEnforcer, PolicyEnforcer, SharedEnforcer};
pub use protocol::{ReplayProtector, SignalKind, SignalingEnvelope, CALL_PROTOCOL_VERSION};
pub use session::{
    CallParticipant, CallSession, CallSessionEvent, CallSessionStatus, CallStateTransition,
    SessionManager,
};
pub use signal_hub::{BrowserSignal, CallSignalHub, QualityReport};
pub use signaling::{CallAnswer, CallOffer, MediaType};
pub use state::CallState;
pub use uep_gate::{
    check_call_authorization, extract_role_from_subject, UepGateError, UepGateResult,
};
pub use verify::{MediaGate, VerificationRequirements, VerificationState};
