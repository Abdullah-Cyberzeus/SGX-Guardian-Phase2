//! ICE (Interactive Connectivity Establishment) Agent
//!
//! Handles candidate gathering, connectivity checks, and NAT traversal
//! over the Nebula overlay network. Supports STUN for NAT detection.

use crate::media::errors::{MediaError, MediaResult};
use serde::{Deserialize, Serialize};

/// ICE gathering state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceGatheringState {
    /// Not yet gathering
    New,
    /// Currently gathering candidates
    Gathering,
    /// Completed candidate gathering
    Complete,
}

impl IceGatheringState {
    pub fn as_str(&self) -> &'static str {
        match self {
            IceGatheringState::New => "new",
            IceGatheringState::Gathering => "gathering",
            IceGatheringState::Complete => "complete",
        }
    }
}

/// ICE connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IceConnectionState {
    /// New, not yet checking
    New,
    /// Checking connectivity
    Checking,
    /// Found a working connection
    Connected,
    /// Had connection but lost it
    Disconnected,
    /// All connectivity checks failed
    Failed,
    /// Closed
    Closed,
}

impl IceConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            IceConnectionState::New => "new",
            IceConnectionState::Checking => "checking",
            IceConnectionState::Connected => "connected",
            IceConnectionState::Disconnected => "disconnected",
            IceConnectionState::Failed => "failed",
            IceConnectionState::Closed => "closed",
        }
    }
}

/// ICE candidate type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    pub sdp_mline_index: u32,
    pub sdp_mid: Option<String>,
}

impl IceCandidate {
    pub fn new(candidate: impl Into<String>, sdp_mline_index: u32) -> Self {
        IceCandidate {
            candidate: candidate.into(),
            sdp_mline_index,
            sdp_mid: None,
        }
    }

    pub fn with_mid(mut self, mid: impl Into<String>) -> Self {
        self.sdp_mid = Some(mid.into());
        self
    }

    /// Check if this is a host candidate (direct connection)
    pub fn is_host_candidate(&self) -> bool {
        self.candidate.contains("typ host")
    }

    /// Check if this is a server reflexive candidate (STUN)
    pub fn is_srflx_candidate(&self) -> bool {
        self.candidate.contains("typ srflx")
    }

    /// Check if this is a relay candidate
    pub fn is_relay_candidate(&self) -> bool {
        self.candidate.contains("typ relay")
    }
}

/// ICE Agent - manages candidate gathering and connectivity
pub struct IceAgent {
    peer_id: String,
    gathering_state: IceGatheringState,
    connection_state: IceConnectionState,
    local_candidates: Vec<IceCandidate>,
    remote_candidates: Vec<IceCandidate>,
    stun_servers: Vec<String>,
}

impl IceAgent {
    /// Create a new ICE agent
    pub fn new(peer_id: impl Into<String>) -> Self {
        IceAgent {
            peer_id: peer_id.into(),
            gathering_state: IceGatheringState::New,
            connection_state: IceConnectionState::New,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            stun_servers: vec![
                "stun:stun1.nebula.local:3478".to_string(),
                "stun:stun2.nebula.local:3478".to_string(),
            ],
        }
    }

    /// Get peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Get gathering state
    pub fn gathering_state(&self) -> IceGatheringState {
        self.gathering_state
    }

    /// Get connection state
    pub fn connection_state(&self) -> IceConnectionState {
        self.connection_state
    }

    /// Start gathering candidates
    pub fn start_gathering(&mut self) -> MediaResult<()> {
        if self.gathering_state == IceGatheringState::New {
            self.gathering_state = IceGatheringState::Gathering;

            // Simulate gathering host candidate
            let host_candidate = IceCandidate::new(
                format!(
                    "candidate:1 1 UDP 2130706431 {} 56789 typ host",
                    self.peer_id
                ),
                0,
            );
            self.local_candidates.push(host_candidate);

            self.gathering_state = IceGatheringState::Complete;
            Ok(())
        } else {
            Err(MediaError::InvalidState(
                "Candidate gathering already in progress or complete".to_string(),
            ))
        }
    }

    /// Add a local candidate
    pub fn add_local_candidate(&mut self, candidate: IceCandidate) -> MediaResult<()> {
        if self.gathering_state != IceGatheringState::Gathering {
            return Err(MediaError::InvalidState(
                "Not in gathering state".to_string(),
            ));
        }
        self.local_candidates.push(candidate);
        Ok(())
    }

    /// Add a remote candidate
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) -> MediaResult<()> {
        self.remote_candidates.push(candidate);

        // Simulate connectivity check when both candidates are present
        if !self.local_candidates.is_empty() && self.connection_state == IceConnectionState::New {
            self.connection_state = IceConnectionState::Checking;
            // Assume successful connection over Nebula overlay
            self.connection_state = IceConnectionState::Connected;
        }

        Ok(())
    }

    /// Get local candidates
    pub fn local_candidates(&self) -> &[IceCandidate] {
        &self.local_candidates
    }

    /// Get remote candidates
    pub fn remote_candidates(&self) -> &[IceCandidate] {
        &self.remote_candidates
    }

    /// Add a STUN server
    pub fn add_stun_server(&mut self, server: impl Into<String>) {
        self.stun_servers.push(server.into());
    }

    /// Get STUN servers
    pub fn stun_servers(&self) -> &[String] {
        &self.stun_servers
    }

    /// Close ICE agent
    pub fn close(&mut self) -> MediaResult<()> {
        self.connection_state = IceConnectionState::Closed;
        self.local_candidates.clear();
        self.remote_candidates.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ice_candidate_creation() {
        let candidate = IceCandidate::new("candidate:1 1 UDP", 0);
        assert_eq!(candidate.sdp_mline_index, 0);
        assert_eq!(candidate.sdp_mid, None);
    }

    #[test]
    fn test_ice_candidate_with_mid() {
        let candidate = IceCandidate::new("candidate:1 1 UDP", 0).with_mid("audio");
        assert_eq!(candidate.sdp_mid, Some("audio".to_string()));
    }

    #[test]
    fn test_ice_candidate_types() {
        let host = IceCandidate::new("candidate:1 1 UDP 2130706431 192.168.1.1 5000 typ host", 0);
        assert!(host.is_host_candidate());
        assert!(!host.is_srflx_candidate());

        let srflx = IceCandidate::new("candidate:2 1 UDP 1694498815 10.0.0.1 5001 typ srflx", 0);
        assert!(!srflx.is_host_candidate());
        assert!(srflx.is_srflx_candidate());

        let relay = IceCandidate::new("candidate:3 1 UDP 16777215 5.5.5.5 5002 typ relay", 0);
        assert!(relay.is_relay_candidate());
    }

    #[test]
    fn test_ice_agent_creation() {
        let agent = IceAgent::new("test-peer");
        assert_eq!(agent.peer_id(), "test-peer");
        assert_eq!(agent.gathering_state(), IceGatheringState::New);
        assert_eq!(agent.connection_state(), IceConnectionState::New);
    }

    #[test]
    fn test_ice_gathering() {
        let mut agent = IceAgent::new("test-peer");

        assert!(agent.start_gathering().is_ok());
        assert_eq!(agent.gathering_state(), IceGatheringState::Complete);
        assert_eq!(agent.local_candidates().len(), 1);
    }

    #[test]
    fn test_ice_candidate_exchange() {
        let mut agent = IceAgent::new("test-peer");
        agent.start_gathering().unwrap();

        let remote_candidate =
            IceCandidate::new("candidate:10 1 UDP 2130706431 10.0.0.5 5000 typ host", 0);
        assert!(agent.add_remote_candidate(remote_candidate).is_ok());

        assert_eq!(agent.connection_state(), IceConnectionState::Connected);
    }

    #[test]
    fn test_stun_servers() {
        let mut agent = IceAgent::new("test-peer");
        assert_eq!(agent.stun_servers().len(), 2);

        agent.add_stun_server("stun:custom.server:3478");
        assert_eq!(agent.stun_servers().len(), 3);
    }

    #[test]
    fn test_ice_close() {
        let mut agent = IceAgent::new("test-peer");
        agent.start_gathering().unwrap();

        assert!(agent.close().is_ok());
        assert_eq!(agent.connection_state(), IceConnectionState::Closed);
        assert_eq!(agent.local_candidates().len(), 0);
    }
}
