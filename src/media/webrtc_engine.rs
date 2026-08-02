//! WebRTC Peer Connection Engine
//!
//! Encapsulates WebRTC peer connection lifecycle, state management,
//! and media stream handling.

use crate::media::errors::{MediaError, MediaResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// State of a WebRTC peer connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerConnectionState {
    /// New connection, not yet initialized
    New,
    /// Connecting state
    Connecting,
    /// Connected and ready for media
    Connected,
    /// Disconnected but not closed
    Disconnected,
    /// Failed to establish
    Failed,
    /// Closed and cleaned up
    Closed,
}

impl PeerConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerConnectionState::New => "new",
            PeerConnectionState::Connecting => "connecting",
            PeerConnectionState::Connected => "connected",
            PeerConnectionState::Disconnected => "disconnected",
            PeerConnectionState::Failed => "failed",
            PeerConnectionState::Closed => "closed",
        }
    }
}

/// Configuration for peer connection creation
#[derive(Debug, Clone)]
pub struct PeerConnectionConfig {
    /// Enable audio
    pub enable_audio: bool,
    /// Enable video
    pub enable_video: bool,
    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,
    /// Enable data channel
    pub enable_data_channel: bool,
    /// ICE transport policy (prefer relay, prefer direct, etc)
    pub ice_transport_policy: String,
}

impl Default for PeerConnectionConfig {
    fn default() -> Self {
        PeerConnectionConfig {
            enable_audio: true,
            enable_video: true,
            stun_servers: vec![
                "stun:stun1.nebula.local:3478".to_string(),
                "stun:stun2.nebula.local:3478".to_string(),
            ],
            enable_data_channel: true,
            ice_transport_policy: "all".to_string(), // all, relay, direct
        }
    }
}

/// Builder for WebRTC peer connections
pub struct PeerConnectionBuilder {
    peer_id: String,
    config: PeerConnectionConfig,
}

impl PeerConnectionBuilder {
    pub fn new(peer_id: impl Into<String>) -> Self {
        PeerConnectionBuilder {
            peer_id: peer_id.into(),
            config: PeerConnectionConfig::default(),
        }
    }

    pub fn enable_audio(mut self, enabled: bool) -> Self {
        self.config.enable_audio = enabled;
        self
    }

    pub fn enable_video(mut self, enabled: bool) -> Self {
        self.config.enable_video = enabled;
        self
    }

    pub fn enable_data_channel(mut self, enabled: bool) -> Self {
        self.config.enable_data_channel = enabled;
        self
    }

    pub fn add_stun_server(mut self, server: impl Into<String>) -> Self {
        self.config.stun_servers.push(server.into());
        self
    }

    pub fn ice_transport_policy(mut self, policy: impl Into<String>) -> Self {
        self.config.ice_transport_policy = policy.into();
        self
    }

    pub fn build(self) -> MediaResult<WebRtcEngine> {
        Ok(WebRtcEngine {
            peer_id: self.peer_id,
            state: PeerConnectionState::New,
            config: self.config,
            media_streams: HashMap::new(),
            remote_candidates: Vec::new(),
            local_candidates: Vec::new(),
        })
    }
}

/// WebRTC Peer Connection Engine
pub struct WebRtcEngine {
    peer_id: String,
    state: PeerConnectionState,
    config: PeerConnectionConfig,
    media_streams: HashMap<String, MediaStreamInfo>,
    remote_candidates: Vec<String>,
    local_candidates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MediaStreamInfo {
    id: String,
    audio_enabled: bool,
    video_enabled: bool,
}

impl MediaStreamInfo {
    /// Get stream id
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Check if audio is enabled on this stream
    pub fn audio_enabled(&self) -> bool {
        self.audio_enabled
    }

    /// Check if video is enabled on this stream
    pub fn video_enabled(&self) -> bool {
        self.video_enabled
    }
}

impl WebRtcEngine {
    /// Create a new WebRTC engine with default config
    pub fn new(peer_id: impl Into<String>) -> Self {
        PeerConnectionBuilder::new(peer_id)
            .build()
            .expect("default config is valid")
    }

    /// Get peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Get current connection state
    pub fn state(&self) -> PeerConnectionState {
        self.state
    }

    /// Transition to connecting state
    pub fn start_connecting(&mut self) -> MediaResult<()> {
        match self.state {
            PeerConnectionState::New => {
                self.state = PeerConnectionState::Connecting;
                Ok(())
            }
            _ => Err(MediaError::InvalidState(format!(
                "Cannot transition from {:?} to Connecting",
                self.state
            ))),
        }
    }

    /// Mark connection as established
    pub fn mark_connected(&mut self) -> MediaResult<()> {
        if self.state == PeerConnectionState::Connecting {
            self.state = PeerConnectionState::Connected;
            Ok(())
        } else {
            Err(MediaError::InvalidState(
                "Can only mark connected from Connecting state".to_string(),
            ))
        }
    }

    /// Add a local ICE candidate
    pub fn add_local_candidate(&mut self, candidate: String) -> MediaResult<()> {
        self.local_candidates.push(candidate);
        Ok(())
    }

    /// Add a remote ICE candidate
    pub fn add_remote_candidate(&mut self, candidate: String) -> MediaResult<()> {
        self.remote_candidates.push(candidate);
        Ok(())
    }

    /// Get all local ICE candidates
    pub fn local_candidates(&self) -> &[String] {
        &self.local_candidates
    }

    /// Get all remote ICE candidates
    pub fn remote_candidates(&self) -> &[String] {
        &self.remote_candidates
    }

    /// Create a media stream
    pub fn create_media_stream(
        &mut self,
        stream_id: String,
        audio: bool,
        video: bool,
    ) -> MediaResult<()> {
        self.media_streams.insert(
            stream_id.clone(),
            MediaStreamInfo {
                id: stream_id,
                audio_enabled: audio && self.config.enable_audio,
                video_enabled: video && self.config.enable_video,
            },
        );
        Ok(())
    }

    /// Get media stream info by id
    pub fn get_media_stream(&self, stream_id: &str) -> Option<&MediaStreamInfo> {
        self.media_streams.get(stream_id)
    }

    /// Get number of active media streams
    pub fn media_stream_count(&self) -> usize {
        self.media_streams.len()
    }

    /// Close peer connection
    pub fn close(&mut self) -> MediaResult<()> {
        self.state = PeerConnectionState::Closed;
        self.media_streams.clear();
        self.local_candidates.clear();
        self.remote_candidates.clear();
        Ok(())
    }

    /// Check if audio is enabled
    pub fn is_audio_enabled(&self) -> bool {
        self.config.enable_audio
    }

    /// Check if video is enabled
    pub fn is_video_enabled(&self) -> bool {
        self.config.enable_video
    }

    /// Get configuration
    pub fn config(&self) -> &PeerConnectionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_connection_creation() {
        let engine = WebRtcEngine::new("test-peer");
        assert_eq!(engine.peer_id(), "test-peer");
        assert_eq!(engine.state(), PeerConnectionState::New);
        assert!(engine.is_audio_enabled());
        assert!(engine.is_video_enabled());
    }

    #[test]
    fn test_peer_connection_builder() {
        let engine = PeerConnectionBuilder::new("builder-peer")
            .enable_audio(true)
            .enable_video(false)
            .build()
            .unwrap();

        assert!(engine.is_audio_enabled());
        assert!(!engine.is_video_enabled());
    }

    #[test]
    fn test_state_transitions() {
        let mut engine = WebRtcEngine::new("test");

        assert!(engine.start_connecting().is_ok());
        assert_eq!(engine.state(), PeerConnectionState::Connecting);

        assert!(engine.mark_connected().is_ok());
        assert_eq!(engine.state(), PeerConnectionState::Connected);
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut engine = WebRtcEngine::new("test");
        engine.start_connecting().unwrap();
        engine.mark_connected().unwrap();

        // Cannot transition from Connected to Connecting
        assert!(engine.start_connecting().is_err());
    }

    #[test]
    fn test_ice_candidates() {
        let mut engine = WebRtcEngine::new("test");

        engine
            .add_local_candidate("candidate:1 1 UDP".to_string())
            .unwrap();
        engine
            .add_remote_candidate("candidate:2 1 UDP".to_string())
            .unwrap();

        assert_eq!(engine.local_candidates().len(), 1);
        assert_eq!(engine.remote_candidates().len(), 1);
    }

    #[test]
    fn test_media_stream_creation() {
        let mut engine = WebRtcEngine::new("test");
        let result = engine.create_media_stream("stream-1".to_string(), true, true);
        assert!(result.is_ok());

        let stream = engine.get_media_stream("stream-1").unwrap();
        assert_eq!(stream.id(), "stream-1");
        assert!(stream.audio_enabled());
        assert!(stream.video_enabled());
    }

    #[test]
    fn test_close_peer_connection() {
        let mut engine = WebRtcEngine::new("test");
        engine
            .add_local_candidate("candidate:1".to_string())
            .unwrap();
        engine
            .create_media_stream("stream-1".to_string(), true, true)
            .unwrap();

        assert!(engine.close().is_ok());
        assert_eq!(engine.state(), PeerConnectionState::Closed);
        assert_eq!(engine.local_candidates().len(), 0);
        assert_eq!(engine.media_stream_count(), 0);
    }
}
