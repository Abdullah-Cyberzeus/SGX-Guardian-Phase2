//! Media State Tracking for Call Sessions
//!
//! Tracks audio, video, and screen share status during calls.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Media stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaStreamState {
    /// Stream not active
    Inactive,
    /// Stream is active
    Active,
    /// Stream is paused
    Paused,
    /// Stream error occurred
    Error,
}

impl MediaStreamState {
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaStreamState::Inactive => "inactive",
            MediaStreamState::Active => "active",
            MediaStreamState::Paused => "paused",
            MediaStreamState::Error => "error",
        }
    }
}

/// Media statistics for a stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packet_loss_percent: f32,
    pub rtt_ms: u32,
    pub jitter_ms: u32,
}

impl Default for MediaStats {
    fn default() -> Self {
        MediaStats {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            packet_loss_percent: 0.0,
            rtt_ms: 0,
            jitter_ms: 0,
        }
    }
}

/// Audio stream state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioStream {
    pub state: MediaStreamState,
    pub codec: String,
    pub sample_rate: u32,
    pub channels: u8,
    pub bitrate_kbps: u16,
    pub stats: MediaStats,
}

impl AudioStream {
    pub fn new(codec: String, sample_rate: u32, channels: u8, bitrate_kbps: u16) -> Self {
        AudioStream {
            state: MediaStreamState::Inactive,
            codec,
            sample_rate,
            channels,
            bitrate_kbps,
            stats: MediaStats::default(),
        }
    }

    pub fn activate(&mut self) {
        self.state = MediaStreamState::Active;
    }

    pub fn pause(&mut self) {
        self.state = MediaStreamState::Paused;
    }

    pub fn deactivate(&mut self) {
        self.state = MediaStreamState::Inactive;
    }
}

/// Video stream state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoStream {
    pub state: MediaStreamState,
    pub codec: String,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub bitrate_kbps: u16,
    pub stats: MediaStats,
}

impl VideoStream {
    pub fn new(codec: String, width: u16, height: u16, fps: u8, bitrate_kbps: u16) -> Self {
        VideoStream {
            state: MediaStreamState::Inactive,
            codec,
            width,
            height,
            fps,
            bitrate_kbps,
            stats: MediaStats::default(),
        }
    }

    pub fn activate(&mut self) {
        self.state = MediaStreamState::Active;
    }

    pub fn pause(&mut self) {
        self.state = MediaStreamState::Paused;
    }

    pub fn deactivate(&mut self) {
        self.state = MediaStreamState::Inactive;
    }

    pub fn resolution(&self) -> String {
        format!("{}x{}", self.width, self.height)
    }
}

/// Screen share stream state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenShareStream {
    pub state: MediaStreamState,
    pub codec: String,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub bitrate_kbps: u16,
    pub stats: MediaStats,
}

impl ScreenShareStream {
    pub fn new(codec: String, width: u16, height: u16, fps: u8, bitrate_kbps: u16) -> Self {
        ScreenShareStream {
            state: MediaStreamState::Inactive,
            codec,
            width,
            height,
            fps,
            bitrate_kbps,
            stats: MediaStats::default(),
        }
    }

    pub fn activate(&mut self) {
        self.state = MediaStreamState::Active;
    }

    pub fn pause(&mut self) {
        self.state = MediaStreamState::Paused;
    }

    pub fn deactivate(&mut self) {
        self.state = MediaStreamState::Inactive;
    }
}

/// Complete media state for a call session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallMediaState {
    pub session_id: String,
    pub audio: Option<AudioStream>,
    pub video: Option<VideoStream>,
    pub screen_share: Option<ScreenShareStream>,
    pub last_updated: u64,
}

impl CallMediaState {
    pub fn new(session_id: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        CallMediaState {
            session_id,
            audio: None,
            video: None,
            screen_share: None,
            last_updated: now,
        }
    }

    pub fn add_audio(&mut self, audio: AudioStream) {
        self.audio = Some(audio);
        self.update_timestamp();
    }

    pub fn add_video(&mut self, video: VideoStream) {
        self.video = Some(video);
        self.update_timestamp();
    }

    pub fn add_screen_share(&mut self, screen_share: ScreenShareStream) {
        self.screen_share = Some(screen_share);
        self.update_timestamp();
    }

    pub fn is_audio_active(&self) -> bool {
        self.audio
            .as_ref()
            .map(|a| a.state == MediaStreamState::Active)
            .unwrap_or(false)
    }

    pub fn is_video_active(&self) -> bool {
        self.video
            .as_ref()
            .map(|v| v.state == MediaStreamState::Active)
            .unwrap_or(false)
    }

    pub fn is_screen_share_active(&self) -> bool {
        self.screen_share
            .as_ref()
            .map(|s| s.state == MediaStreamState::Active)
            .unwrap_or(false)
    }

    pub fn is_any_stream_active(&self) -> bool {
        self.is_audio_active() || self.is_video_active() || self.is_screen_share_active()
    }

    fn update_timestamp(&mut self) {
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_stream() {
        let mut audio = AudioStream::new("opus".to_string(), 48000, 2, 128);
        assert_eq!(audio.state, MediaStreamState::Inactive);

        audio.activate();
        assert_eq!(audio.state, MediaStreamState::Active);

        audio.pause();
        assert_eq!(audio.state, MediaStreamState::Paused);

        audio.deactivate();
        assert_eq!(audio.state, MediaStreamState::Inactive);
    }

    #[test]
    fn test_video_stream() {
        let mut video = VideoStream::new("vp9".to_string(), 1280, 720, 30, 2500);
        assert_eq!(video.state, MediaStreamState::Inactive);
        assert_eq!(video.resolution(), "1280x720");

        video.activate();
        assert_eq!(video.state, MediaStreamState::Active);

        video.deactivate();
        assert_eq!(video.state, MediaStreamState::Inactive);
    }

    #[test]
    fn test_screen_share_stream() {
        let mut screen = ScreenShareStream::new("vp9".to_string(), 1920, 1080, 15, 3000);
        assert_eq!(screen.state, MediaStreamState::Inactive);

        screen.activate();
        assert_eq!(screen.state, MediaStreamState::Active);
    }

    #[test]
    fn test_call_media_state() {
        let mut media_state = CallMediaState::new("session-123".to_string());
        assert_eq!(media_state.session_id, "session-123");
        assert!(!media_state.is_any_stream_active());

        let mut audio = AudioStream::new("opus".to_string(), 48000, 2, 128);
        audio.activate();
        media_state.add_audio(audio);

        assert!(media_state.is_audio_active());
        assert!(media_state.is_any_stream_active());
    }

    #[test]
    fn test_call_media_state_multiple_streams() {
        let mut media_state = CallMediaState::new("session-456".to_string());

        let mut audio = AudioStream::new("opus".to_string(), 48000, 2, 128);
        audio.activate();
        media_state.add_audio(audio);

        let mut video = VideoStream::new("vp9".to_string(), 1280, 720, 30, 2500);
        video.activate();
        media_state.add_video(video);

        assert!(media_state.is_audio_active());
        assert!(media_state.is_video_active());
        assert!(media_state.is_any_stream_active());
    }

    #[test]
    fn test_media_stats() {
        let mut stats = MediaStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.packet_loss_percent, 0.0);

        stats.bytes_sent = 1024 * 100;
        assert_eq!(stats.bytes_sent, 102400);
    }
}
