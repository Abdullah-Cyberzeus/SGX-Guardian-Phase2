//! Codec Support - Audio and Video Codecs
//!
//! Defines codec capabilities and parameters for media encoding/decoding.

use serde::{Deserialize, Serialize};

/// Audio codec types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudioCodec {
    /// Opus codec (recommended)
    Opus,
    /// G.711 (basic fallback)
    G711,
}

impl AudioCodec {
    pub fn as_str(&self) -> &'static str {
        match self {
            AudioCodec::Opus => "opus",
            AudioCodec::G711 => "g711",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "opus" => Some(AudioCodec::Opus),
            "g711" => Some(AudioCodec::G711),
            _ => None,
        }
    }

    pub fn sample_rate(&self) -> u32 {
        match self {
            AudioCodec::Opus => 48000,
            AudioCodec::G711 => 8000,
        }
    }

    pub fn channels(&self) -> u8 {
        match self {
            AudioCodec::Opus => 2,
            AudioCodec::G711 => 1,
        }
    }
}

/// Video codec types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCodec {
    /// VP9 (modern, efficient)
    VP9,
    /// AV1 (next-gen, high compression)
    AV1,
    /// H.264 (fallback)
    H264,
}

impl VideoCodec {
    pub fn as_str(&self) -> &'static str {
        match self {
            VideoCodec::VP9 => "vp9",
            VideoCodec::AV1 => "av1",
            VideoCodec::H264 => "h264",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "vp9" => Some(VideoCodec::VP9),
            "av1" => Some(VideoCodec::AV1),
            "h264" => Some(VideoCodec::H264),
            _ => None,
        }
    }

    pub fn supports_bitrate_control(&self) -> bool {
        match self {
            VideoCodec::VP9 => true,
            VideoCodec::AV1 => true,
            VideoCodec::H264 => true,
        }
    }
}

/// Codec capability with parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CodecCapability {
    Audio {
        codec: AudioCodec,
        sample_rate: u32,
        channels: u8,
        bitrate_kbps: u16,
    },
    Video {
        codec: VideoCodec,
        width: u16,
        height: u16,
        fps: u8,
        bitrate_kbps: u16,
    },
}

impl CodecCapability {
    /// Create audio codec capability with defaults
    pub fn audio(codec: AudioCodec) -> Self {
        CodecCapability::Audio {
            codec,
            sample_rate: codec.sample_rate(),
            channels: codec.channels(),
            bitrate_kbps: match codec {
                AudioCodec::Opus => 128,
                AudioCodec::G711 => 64,
            },
        }
    }

    /// Create video codec capability with defaults
    pub fn video(codec: VideoCodec) -> Self {
        CodecCapability::Video {
            codec,
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: match codec {
                VideoCodec::VP9 => 2500,
                VideoCodec::AV1 => 1500,
                VideoCodec::H264 => 2000,
            },
        }
    }

    pub fn bitrate_kbps(&self) -> u16 {
        match self {
            CodecCapability::Audio { bitrate_kbps, .. } => *bitrate_kbps,
            CodecCapability::Video { bitrate_kbps, .. } => *bitrate_kbps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_codec_opus() {
        let codec = AudioCodec::Opus;
        assert_eq!(codec.as_str(), "opus");
        assert_eq!(codec.sample_rate(), 48000);
        assert_eq!(codec.channels(), 2);
    }

    #[test]
    fn test_audio_codec_g711() {
        let codec = AudioCodec::G711;
        assert_eq!(codec.as_str(), "g711");
        assert_eq!(codec.sample_rate(), 8000);
        assert_eq!(codec.channels(), 1);
    }

    #[test]
    fn test_audio_codec_from_str() {
        assert_eq!(AudioCodec::parse_str("opus"), Some(AudioCodec::Opus));
        assert_eq!(AudioCodec::parse_str("g711"), Some(AudioCodec::G711));
        assert_eq!(AudioCodec::parse_str("unknown"), None);
    }

    #[test]
    fn test_video_codec_vp9() {
        let codec = VideoCodec::VP9;
        assert_eq!(codec.as_str(), "vp9");
        assert!(codec.supports_bitrate_control());
    }

    #[test]
    fn test_video_codec_av1() {
        let codec = VideoCodec::AV1;
        assert_eq!(codec.as_str(), "av1");
        assert!(codec.supports_bitrate_control());
    }

    #[test]
    fn test_video_codec_from_str() {
        assert_eq!(VideoCodec::parse_str("vp9"), Some(VideoCodec::VP9));
        assert_eq!(VideoCodec::parse_str("av1"), Some(VideoCodec::AV1));
        assert_eq!(VideoCodec::parse_str("h264"), Some(VideoCodec::H264));
        assert_eq!(VideoCodec::parse_str("invalid"), None);
    }

    #[test]
    fn test_codec_capability_audio() {
        let cap = CodecCapability::audio(AudioCodec::Opus);
        match cap {
            CodecCapability::Audio {
                codec,
                sample_rate,
                channels,
                bitrate_kbps,
            } => {
                assert_eq!(codec, AudioCodec::Opus);
                assert_eq!(sample_rate, 48000);
                assert_eq!(channels, 2);
                assert_eq!(bitrate_kbps, 128);
            }
            _ => panic!("Expected Audio capability"),
        }
    }

    #[test]
    fn test_codec_capability_video() {
        let cap = CodecCapability::video(VideoCodec::VP9);
        match cap {
            CodecCapability::Video {
                codec,
                width,
                height,
                fps,
                bitrate_kbps,
            } => {
                assert_eq!(codec, VideoCodec::VP9);
                assert_eq!(width, 1280);
                assert_eq!(height, 720);
                assert_eq!(fps, 30);
                assert_eq!(bitrate_kbps, 2500);
            }
            _ => panic!("Expected Video capability"),
        }
    }

    #[test]
    fn test_codec_capability_bitrate() {
        let audio = CodecCapability::audio(AudioCodec::Opus);
        assert_eq!(audio.bitrate_kbps(), 128);

        let video = CodecCapability::video(VideoCodec::VP9);
        assert_eq!(video.bitrate_kbps(), 2500);
    }

    #[test]
    fn all_video_codecs_expose_names_bitrate_control_and_defaults() {
        let cases = [
            (VideoCodec::VP9, "vp9", 2500),
            (VideoCodec::AV1, "av1", 1500),
            (VideoCodec::H264, "h264", 2000),
        ];

        for (codec, name, expected_bitrate) in cases {
            assert_eq!(codec.as_str(), name);
            assert!(codec.supports_bitrate_control());
            match CodecCapability::video(codec) {
                CodecCapability::Video {
                    codec: actual,
                    width,
                    height,
                    fps,
                    bitrate_kbps,
                } => {
                    assert_eq!(actual, codec);
                    assert_eq!((width, height, fps), (1280, 720, 30));
                    assert_eq!(bitrate_kbps, expected_bitrate);
                }
                CodecCapability::Audio { .. } => panic!("expected video capability"),
            }
        }
    }

    #[test]
    fn audio_capability_defaults_cover_fallback_codec() {
        match CodecCapability::audio(AudioCodec::G711) {
            CodecCapability::Audio {
                codec,
                sample_rate,
                channels,
                bitrate_kbps,
            } => {
                assert_eq!(codec, AudioCodec::G711);
                assert_eq!((sample_rate, channels, bitrate_kbps), (8000, 1, 64));
            }
            CodecCapability::Video { .. } => panic!("expected audio capability"),
        }
    }

    #[test]
    fn codec_capabilities_round_trip_through_json() {
        for capability in [
            CodecCapability::video(VideoCodec::VP9),
            CodecCapability::video(VideoCodec::AV1),
            CodecCapability::video(VideoCodec::H264),
            CodecCapability::audio(AudioCodec::Opus),
        ] {
            let encoded = serde_json::to_string(&capability).unwrap();
            let decoded: CodecCapability = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded.bitrate_kbps(), capability.bitrate_kbps());
        }
    }
}

pub mod mod_inner {
    pub use super::*;
}
