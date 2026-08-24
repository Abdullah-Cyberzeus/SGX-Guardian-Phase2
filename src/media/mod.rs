//! Media Engine - WebRTC, ICE, DTLS, and SRTP support
//!
//! Provides secure, peer-to-peer media streaming over Nebula overlay network.
//! Integrates WebRTC peer connection, ICE candidate gathering, DTLS encryption,
//! and SRTP media encryption with codec support (Opus for audio, VP9/AV1 for video).

pub mod codecs;
pub mod dtls;
pub mod errors;
pub mod ice;
pub mod srtp;
pub mod webrtc_engine;

pub use codecs::{AudioCodec, CodecCapability, VideoCodec};
pub use dtls::{DtlsContext, DtlsHandshakeState};
pub use ice::{IceAgent, IceCandidate, IceConnectionState, IceGatheringState};
pub use srtp::{SrtpKeyMaterial, SrtpSession};
pub use webrtc_engine::{PeerConnectionBuilder, PeerConnectionState, WebRtcEngine};

use anyhow::Result;

/// MediaEngine coordinates all media operations
pub struct MediaEngine {
    webrtc: WebRtcEngine,
    ice: IceAgent,
}

impl MediaEngine {
    /// Create a new media engine
    pub fn new(peer_id: String) -> Result<Self> {
        Ok(MediaEngine {
            webrtc: WebRtcEngine::new(peer_id.clone()),
            ice: IceAgent::new(peer_id),
        })
    }

    /// Get reference to WebRTC engine
    pub fn webrtc(&self) -> &WebRtcEngine {
        &self.webrtc
    }

    /// Get mutable reference to WebRTC engine
    pub fn webrtc_mut(&mut self) -> &mut WebRtcEngine {
        &mut self.webrtc
    }

    /// Get reference to ICE agent
    pub fn ice(&self) -> &IceAgent {
        &self.ice
    }

    /// Get mutable reference to ICE agent
    pub fn ice_mut(&mut self) -> &mut IceAgent {
        &mut self.ice
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_engine_creation() {
        let engine = MediaEngine::new("test-peer".to_string());
        assert!(engine.is_ok());

        let engine = engine.unwrap();
        assert_eq!(engine.webrtc().peer_id(), "test-peer");
        assert_eq!(engine.ice().peer_id(), "test-peer");
    }

    #[test]
    fn media_engine_mutable_components_drive_video_connection_lifecycle() {
        let mut engine = MediaEngine::new("video-peer".into()).unwrap();
        engine.webrtc_mut().start_connecting().unwrap();
        engine.webrtc_mut().mark_connected().unwrap();
        engine
            .webrtc_mut()
            .create_media_stream("camera".into(), false, true)
            .unwrap();
        assert!(engine
            .webrtc()
            .get_media_stream("camera")
            .unwrap()
            .video_enabled());

        engine.ice_mut().start_gathering().unwrap();
        engine
            .ice_mut()
            .add_remote_candidate(IceCandidate::new(
                "candidate:2 1 UDP 1 192.168.100.2 5000 typ host",
                0,
            ))
            .unwrap();
        assert_eq!(
            engine.ice().connection_state(),
            IceConnectionState::Connected
        );
    }
}
