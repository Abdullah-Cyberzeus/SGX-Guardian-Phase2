//! SRTP (Secure Real-Time Protocol) - Media Stream Encryption
//!
//! Encrypts and decrypts audio/video streams using keys derived from DTLS.

use crate::media::errors::{MediaError, MediaResult};
use std::num::Wrapping;

/// SRTP key material derived from DTLS
pub struct SrtpKeyMaterial {
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
}

impl SrtpKeyMaterial {
    pub fn new(master_key: Vec<u8>, master_salt: Vec<u8>) -> MediaResult<Self> {
        if master_key.len() != 16 {
            return Err(MediaError::SrtpSetupFailed(
                "Master key must be 16 bytes".to_string(),
            ));
        }
        if master_salt.len() != 12 {
            return Err(MediaError::SrtpSetupFailed(
                "Master salt must be 12 bytes".to_string(),
            ));
        }

        Ok(SrtpKeyMaterial {
            master_key,
            master_salt,
        })
    }
}

/// SRTP session for encrypting/decrypting media
pub struct SrtpSession {
    master_key: Vec<u8>,
    salt: Vec<u8>,
    packet_counter: Wrapping<u64>,
}

impl SrtpSession {
    /// Create a new SRTP session
    pub fn new(key_material: SrtpKeyMaterial) -> MediaResult<Self> {
        Ok(SrtpSession {
            master_key: key_material.master_key,
            salt: key_material.master_salt,
            packet_counter: Wrapping(0),
        })
    }

    /// Encrypt RTP packet (simplified - XOR with key material)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> MediaResult<Vec<u8>> {
        let nonce = self.derive_nonce()?;

        // Simple encryption: XOR plaintext with key material
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= self.master_key[i % self.master_key.len()];
            *byte ^= nonce[i % nonce.len()];
        }

        Ok(ciphertext)
    }

    /// Decrypt RTP packet
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> MediaResult<Vec<u8>> {
        // Reset counter to match encryption
        self.packet_counter -= Wrapping(1);
        let nonce = self.derive_nonce()?;
        self.packet_counter += Wrapping(1);

        // Decryption: XOR ciphertext with same key material
        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= self.master_key[i % self.master_key.len()];
            *byte ^= nonce[i % nonce.len()];
        }

        Ok(plaintext)
    }

    /// Derive nonce from packet counter and salt
    fn derive_nonce(&mut self) -> MediaResult<Vec<u8>> {
        // Simple XOR of counter and salt for nonce
        let counter_bytes = self.packet_counter.0.to_be_bytes();
        let mut nonce = vec![0u8; 12];

        // Mix counter into salt
        for (i, byte) in counter_bytes.iter().enumerate() {
            if i < nonce.len() {
                nonce[i] ^= byte;
            }
        }

        for (i, salt_byte) in self.salt.iter().enumerate() {
            if i < nonce.len() {
                nonce[i] ^= salt_byte;
            }
        }

        // Increment counter for next packet
        self.packet_counter += Wrapping(1);

        Ok(nonce)
    }

    /// Get packet counter
    pub fn packet_counter(&self) -> u64 {
        self.packet_counter.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srtp_key_material_creation() {
        let key = vec![0u8; 16];
        let salt = vec![0u8; 12];
        let material = SrtpKeyMaterial::new(key, salt);
        assert!(material.is_ok());
    }

    #[test]
    fn test_srtp_key_material_invalid_key_size() {
        let key = vec![0u8; 15]; // Wrong size
        let salt = vec![0u8; 12];
        let material = SrtpKeyMaterial::new(key, salt);
        assert!(material.is_err());
    }

    #[test]
    fn test_srtp_key_material_invalid_salt_size() {
        let key = vec![0u8; 16];
        let salt = vec![0u8; 11]; // Wrong size
        let material = SrtpKeyMaterial::new(key, salt);
        assert!(material.is_err());
    }

    #[test]
    fn test_srtp_session_creation() {
        let key = vec![0u8; 16];
        let salt = vec![0u8; 12];
        let material = SrtpKeyMaterial::new(key, salt).unwrap();
        let session = SrtpSession::new(material);
        assert!(session.is_ok());
    }

    #[test]
    fn test_srtp_encryption_decryption() {
        let key = vec![1u8; 16];
        let salt = vec![2u8; 12];
        let material = SrtpKeyMaterial::new(key, salt).unwrap();
        let mut session = SrtpSession::new(material).unwrap();

        let plaintext = b"Hello, World!";
        let encrypted = session.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext.to_vec());

        // Decrypt with the same session (counter in sync)
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_srtp_packet_counter() {
        let key = vec![0u8; 16];
        let salt = vec![0u8; 12];
        let material = SrtpKeyMaterial::new(key, salt).unwrap();
        let mut session = SrtpSession::new(material).unwrap();

        assert_eq!(session.packet_counter(), 0);

        let _ = session.encrypt(b"packet1");
        assert_eq!(session.packet_counter(), 1);

        let _ = session.encrypt(b"packet2");
        assert_eq!(session.packet_counter(), 2);
    }

    #[test]
    fn empty_and_large_video_payloads_round_trip() {
        let material = SrtpKeyMaterial::new(vec![0x5a; 16], vec![0xa5; 12]).unwrap();
        let mut empty_session = SrtpSession::new(material).unwrap();
        let encrypted = empty_session.encrypt(&[]).unwrap();
        assert!(encrypted.is_empty());
        assert_eq!(empty_session.decrypt(&encrypted).unwrap(), Vec::<u8>::new());

        let material = SrtpKeyMaterial::new(vec![0x11; 16], vec![0x22; 12]).unwrap();
        let mut video_session = SrtpSession::new(material).unwrap();
        let video_packet: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let encrypted = video_session.encrypt(&video_packet).unwrap();
        assert_eq!(encrypted.len(), video_packet.len());
        assert_ne!(encrypted, video_packet);
        assert_eq!(video_session.decrypt(&encrypted).unwrap(), video_packet);
    }

    #[test]
    fn consecutive_packets_use_different_counter_material() {
        let material = SrtpKeyMaterial::new(vec![0x33; 16], vec![0x44; 12]).unwrap();
        let mut session = SrtpSession::new(material).unwrap();
        let first = session.encrypt(b"same video payload").unwrap();
        let second = session.encrypt(b"same video payload").unwrap();
        assert_ne!(first, second);
        assert_eq!(session.packet_counter(), 2);
    }
}
