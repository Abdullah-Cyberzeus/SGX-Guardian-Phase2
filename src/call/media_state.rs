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

    #[test]
    fn media_stream_state_labels_cover_every_state() {
        for (state, label) in [
            (MediaStreamState::Inactive, "inactive"),
            (MediaStreamState::Active, "active"),
            (MediaStreamState::Paused, "paused"),
            (MediaStreamState::Error, "error"),
        ] {
            assert_eq!(state.as_str(), label);
        }
    }

    #[test]
    fn video_pause_resume_and_deactivate_lifecycle() {
        let mut video = VideoStream::new("av1".into(), 3840, 2160, 60, 8000);
        assert_eq!(video.resolution(), "3840x2160");
        video.activate();
        assert_eq!(video.state, MediaStreamState::Active);
        video.pause();
        assert_eq!(video.state, MediaStreamState::Paused);
        video.activate();
        assert_eq!(video.state, MediaStreamState::Active);
        video.deactivate();
        assert_eq!(video.state, MediaStreamState::Inactive);
    }

    #[test]
    fn screen_share_pause_resume_and_deactivate_lifecycle() {
        let mut screen = ScreenShareStream::new("vp9".into(), 2560, 1440, 30, 5000);
        screen.activate();
        screen.pause();
        assert_eq!(screen.state, MediaStreamState::Paused);
        screen.activate();
        assert_eq!(screen.state, MediaStreamState::Active);
        screen.deactivate();
        assert_eq!(screen.state, MediaStreamState::Inactive);
    }

    #[test]
    fn inactive_and_error_video_streams_do_not_report_active_media() {
        let mut state = CallMediaState::new("video-session".into());
        state.add_video(VideoStream::new("h264".into(), 1280, 720, 30, 2000));
        assert!(!state.is_video_active());
        assert!(!state.is_any_stream_active());

        state.video.as_mut().unwrap().state = MediaStreamState::Error;
        assert!(!state.is_video_active());
        state.video.as_mut().unwrap().activate();
        assert!(state.is_video_active());
        assert!(state.is_any_stream_active());
    }

    #[test]
    fn media_state_and_statistics_round_trip_through_json() {
        let mut state = CallMediaState::new("serialize-video".into());
        let mut video = VideoStream::new("vp9".into(), 1920, 1080, 30, 4000);
        video.stats = MediaStats {
            bytes_sent: 10_000,
            bytes_received: 20_000,
            packets_sent: 100,
            packets_received: 98,
            packet_loss_percent: 2.0,
            rtt_ms: 35,
            jitter_ms: 4,
        };
        video.activate();
        state.add_video(video);

        let encoded = serde_json::to_string(&state).unwrap();
        let decoded: CallMediaState = serde_json::from_str(&encoded).unwrap();
        let decoded_video = decoded.video.unwrap();
        assert_eq!(decoded_video.codec, "vp9");
        assert_eq!(decoded_video.stats.bytes_received, 20_000);
        assert_eq!(decoded_video.stats.packets_received, 98);
        assert_eq!(decoded_video.stats.rtt_ms, 35);
        assert_eq!(decoded_video.stats.jitter_ms, 4);
    }
}
