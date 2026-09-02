//! VS14: bounded `VSHIFT_ALERT` protobuf-compatible message.
//!
//! This module constructs and validates a wire message from an already signed
//! VS13 policy.  It deliberately does not send the message (VS15), authorize
//! a receiving member (VS16), or apply a policy (VS17).

use super::{
    canonical_policy_bytes, sha256_hex, verify_signed_policy, ApprovalService, ReviewRecord,
    SignedVirtualShiftPolicy, VersionedPolicyCandidate,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const VSHIFT_ALERT_SCHEMA_VERSION: u32 = 1;
pub const MAX_VSHIFT_ALERT_BYTES: usize = 96 * 1024;
pub const MAX_POLICY_BLOB_BYTES: usize = 64 * 1024;
pub const MAX_JUSTIFICATION_BYTES: usize = 8 * 1024;
pub const MAX_ALERT_TTL_MS: u64 = 60 * 60 * 1000;

/// Rust representation of `proto/vshift_alert.proto`. Binary values are held
/// as hex in JSON persistence, while `encode` emits the protobuf `bytes`
/// fields required by the schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VShiftAlert {
    pub schema_version: u32,
    pub alert_id: String,
    pub circle_id: String,
    pub policy_version: u64,
    pub policy_blob: Vec<u8>,
    pub policy_hash_hex: String,
    pub guardian_signature_hex: String,
    pub guardian_public_key_hex: String,
    pub signer_id: String,
    pub signature_algorithm: String,
    pub anomaly_id: String,
    pub recommendation_id: String,
    pub anomaly_score: f64,
    pub confidence: f64,
    pub ai_justification: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Create an outbound-ready message from exactly one VS11-approved and
/// VS13-signed policy.  The caller chooses the unique alert ID and bounded
/// expiry; broadcasting is intentionally deferred to VS15.
pub fn vshift_alert_from_signed_policy(
    review: &ReviewRecord,
    signed: &SignedVirtualShiftPolicy,
    alert_id: impl Into<String>,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> anyhow::Result<VShiftAlert> {
    ApprovalService::require_approved(review)?;
    verify_signed_policy(signed)?;
    if signed.policy.source_recommendation_id != review.recommendation_id
        || signed.policy.source_anomaly_id != review.anomaly_id
    {
        anyhow::bail!("signed policy does not link to its approved review record");
    }
    let vs3 = review
        .proposal
        .get("vs3")
        .ok_or_else(|| anyhow::anyhow!("approved review is missing VS3 risk evidence"))?;
    let anomaly_score = required_number(vs3, "anomaly_score")?;
    let confidence = required_number(vs3, "confidence")?;
    let ai_justification = review
        .proposal
        .get("vs9")
        .and_then(|value| value.get("human_summary"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("approved review is missing VS9 human justification"))?
        .to_owned();
    let policy_blob = canonical_policy_bytes(&signed.policy)?;
    let alert = VShiftAlert {
        schema_version: VSHIFT_ALERT_SCHEMA_VERSION,
        alert_id: alert_id.into(),
        circle_id: signed.policy.circle_id.clone(),
        policy_version: signed.policy.policy_version,
        policy_blob,
        policy_hash_hex: signed.canonical_sha256.clone(),
        guardian_signature_hex: signed.signature_hex.clone(),
        guardian_public_key_hex: signed.public_key_hex.clone(),
        signer_id: signed.signer_id.clone(),
        signature_algorithm: signed.algorithm.clone(),
        anomaly_id: review.anomaly_id.clone(),
        recommendation_id: review.recommendation_id.clone(),
        anomaly_score,
        confidence,
        ai_justification,
        issued_at_ms,
        expires_at_ms,
    };
    alert.validate()?;
    Ok(alert)
}

impl VShiftAlert {
    /// Validate all locally knowable facts before this message is handed to
    /// VS15. VS16 repeats trust/freshness checks at each receiving member.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != VSHIFT_ALERT_SCHEMA_VERSION {
            anyhow::bail!("unsupported VSHIFT_ALERT schema {}", self.schema_version);
        }
        for (field, value) in [
            ("alert_id", &self.alert_id),
            ("circle_id", &self.circle_id),
            ("signer_id", &self.signer_id),
            ("anomaly_id", &self.anomaly_id),
            ("recommendation_id", &self.recommendation_id),
        ] {
            if value.trim().is_empty() || value.len() > 256 || value.contains(['\r', '\n']) {
                anyhow::bail!("VSHIFT_ALERT {field} is missing or unsafe");
            }
        }
        if self.policy_version == 0
            || self.policy_blob.is_empty()
            || self.policy_blob.len() > MAX_POLICY_BLOB_BYTES
        {
            anyhow::bail!("VSHIFT_ALERT policy version/blob is invalid or exceeds its size bound");
        }
        if self.signature_algorithm != "ed25519"
            || self.ai_justification.len() > MAX_JUSTIFICATION_BYTES
        {
            anyhow::bail!("VSHIFT_ALERT algorithm or justification is invalid");
        }
        if !self.anomaly_score.is_finite()
            || !self.confidence.is_finite()
            || !(0.0..=1.0).contains(&self.anomaly_score)
            || !(0.0..=1.0).contains(&self.confidence)
        {
            anyhow::bail!("VSHIFT_ALERT score/confidence must be finite values from 0 to 1");
        }
        if self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_ALERT_TTL_MS
        {
            anyhow::bail!("VSHIFT_ALERT expiry must be after issue time and within the configured maximum TTL");
        }

        // VS12 canonical bytes intentionally omit `canonical_sha256`, because
        // that value is the hash *of* these bytes. Reattach the envelope hash
        // solely to restore the typed policy representation for verification.
        let policy = policy_from_canonical_blob(&self.policy_blob, &self.policy_hash_hex)?;
        let canonical = canonical_policy_bytes(&policy)?;
        if canonical != self.policy_blob
            || policy.circle_id != self.circle_id
            || policy.policy_version != self.policy_version
            || policy.source_anomaly_id != self.anomaly_id
            || policy.source_recommendation_id != self.recommendation_id
        {
            anyhow::bail!("VSHIFT_ALERT fields do not match its exact policy blob");
        }
        let digest = sha256_hex(&self.policy_blob);
        if digest != self.policy_hash_hex || digest != policy.canonical_sha256 {
            anyhow::bail!("VSHIFT_ALERT policy hash does not match exact policy bytes");
        }
        let signed = SignedVirtualShiftPolicy {
            schema_version: 1,
            policy,
            signer_id: self.signer_id.clone(),
            algorithm: self.signature_algorithm.clone(),
            // The cryptographic verification has no dependency on this value;
            // a non-zero placeholder is sufficient because signed time is not
            // carried in the VS14 contract.
            signed_at_ms: 1,
            canonical_sha256: self.policy_hash_hex.clone(),
            signature_hex: self.guardian_signature_hex.clone(),
            public_key_hex: self.guardian_public_key_hex.clone(),
            status: "signed_not_broadcast".into(),
        };
        verify_signed_policy(&signed)
    }

    /// Encode the defined protobuf wire fields without a runtime dependency.
    /// Unknown fields are skipped by `decode`, so a later schema can extend it.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        let mut output = Vec::new();
        put_string(&mut output, 1, &self.alert_id);
        put_string(&mut output, 2, &self.circle_id);
        put_varint_field(&mut output, 3, self.policy_version);
        put_bytes(&mut output, 4, &self.policy_blob);
        put_bytes(
            &mut output,
            5,
            &hex_decode(&self.guardian_signature_hex, "Guardian signature")?,
        );
        put_bytes(
            &mut output,
            6,
            &hex_decode(&self.policy_hash_hex, "policy hash")?,
        );
        put_string(&mut output, 7, &self.anomaly_id);
        put_string(&mut output, 8, &self.recommendation_id);
        put_fixed64_field(&mut output, 9, self.anomaly_score.to_bits());
        put_fixed64_field(&mut output, 10, self.confidence.to_bits());
        put_string(&mut output, 11, &self.ai_justification);
        put_varint_field(&mut output, 12, self.issued_at_ms);
        put_varint_field(&mut output, 13, self.expires_at_ms);
        put_string(&mut output, 14, &self.signer_id);
        put_bytes(
            &mut output,
            15,
            &hex_decode(&self.guardian_public_key_hex, "Guardian public key")?,
        );
        put_string(&mut output, 16, &self.signature_algorithm);
        put_varint_field(&mut output, 17, u64::from(self.schema_version));
        if output.len() > MAX_VSHIFT_ALERT_BYTES {
            anyhow::bail!("encoded VSHIFT_ALERT exceeds maximum size");
        }
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> anyhow::Result<Self> {
        if input.is_empty() || input.len() > MAX_VSHIFT_ALERT_BYTES {
            anyhow::bail!("VSHIFT_ALERT input is empty or exceeds maximum size");
        }
        let mut reader = WireReader::new(input);
        let mut fields = DecodedFields::default();
        while !reader.is_finished() {
            let tag = reader.varint()?;
            let number = tag >> 3;
            let wire_type = tag & 0x07;
            if number == 0 {
                anyhow::bail!("VSHIFT_ALERT contains invalid field number zero");
            }
            match number {
                1 => fields
                    .alert_id
                    .set_string(reader.length_bytes(wire_type)?, "alert_id")?,
                2 => fields
                    .circle_id
                    .set_string(reader.length_bytes(wire_type)?, "circle_id")?,
                3 => fields
                    .policy_version
                    .set_varint(reader.varint_for(wire_type)?, "policy_version")?,
                4 => fields
                    .policy_blob
                    .set_bytes(reader.length_bytes(wire_type)?, "policy_blob")?,
                5 => fields
                    .signature
                    .set_bytes(reader.length_bytes(wire_type)?, "guardian_signature")?,
                6 => fields
                    .policy_hash
                    .set_bytes(reader.length_bytes(wire_type)?, "policy_hash")?,
                7 => fields
                    .anomaly_id
                    .set_string(reader.length_bytes(wire_type)?, "anomaly_id")?,
                8 => fields
                    .recommendation_id
                    .set_string(reader.length_bytes(wire_type)?, "recommendation_id")?,
                9 => fields
                    .anomaly_score
                    .set_fixed64(reader.fixed64(wire_type)?, "anomaly_score")?,
                10 => fields
                    .confidence
                    .set_fixed64(reader.fixed64(wire_type)?, "confidence")?,
                11 => fields
                    .justification
                    .set_string(reader.length_bytes(wire_type)?, "ai_justification")?,
                12 => fields
                    .issued_at
                    .set_varint(reader.varint_for(wire_type)?, "issued_at_ms")?,
                13 => fields
                    .expires_at
                    .set_varint(reader.varint_for(wire_type)?, "expires_at_ms")?,
                14 => fields
                    .signer_id
                    .set_string(reader.length_bytes(wire_type)?, "signer_id")?,
                15 => fields
                    .public_key
                    .set_bytes(reader.length_bytes(wire_type)?, "guardian_public_key")?,
                16 => fields
                    .algorithm
                    .set_string(reader.length_bytes(wire_type)?, "signature_algorithm")?,
                17 => fields
                    .schema_version
                    .set_varint(reader.varint_for(wire_type)?, "schema_version")?,
                _ => reader.skip_unknown(wire_type)?,
            }
        }
        let alert = fields.into_alert()?;
        alert.validate()?;
        Ok(alert)
    }
}

/// Persist both readable audit JSON and the exact protobuf wire bytes that
/// VS15 will later transmit. This function never performs a network call.
pub fn write_vshift_alert(
    root: impl AsRef<Path>,
    alert: &VShiftAlert,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    if alert.alert_id.contains(['/', '\\']) || matches!(alert.alert_id.as_str(), "." | "..") {
        anyhow::bail!("VSHIFT_ALERT ID must be file-name-safe");
    }
    let bytes = alert.encode()?;
    let directory = root.as_ref().join(&alert.alert_id);
    std::fs::create_dir_all(&directory)?;
    let json_path = directory.join("vshift_alert.json");
    let protobuf_path = directory.join("vshift_alert.pb");
    std::fs::write(&json_path, serde_json::to_string_pretty(alert)?)?;
    std::fs::write(&protobuf_path, bytes)?;
    Ok((json_path, protobuf_path))
}

fn required_number(value: &serde_json::Value, field: &str) -> anyhow::Result<f64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_f64)
        .filter(|number| number.is_finite() && (0.0..=1.0).contains(number))
        .ok_or_else(|| anyhow::anyhow!("approved review has invalid VS3 {field}"))
}

fn policy_from_canonical_blob(
    policy_blob: &[u8],
    canonical_sha256: &str,
) -> anyhow::Result<VersionedPolicyCandidate> {
    let mut value: serde_json::Value = serde_json::from_slice(policy_blob)
        .map_err(|_| anyhow::anyhow!("VSHIFT_ALERT policy blob is not JSON"))?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("VSHIFT_ALERT policy blob is not a policy object"))?
        .insert(
            "canonical_sha256".into(),
            serde_json::Value::String(canonical_sha256.to_owned()),
        );
    serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("VSHIFT_ALERT policy blob is not a candidate policy"))
}

fn hex_decode(value: &str, description: &str) -> anyhow::Result<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        anyhow::bail!("{description} must be non-empty hexadecimal");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| anyhow::anyhow!("{description} is not hexadecimal"))
        })
        .collect()
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn put_key(output: &mut Vec<u8>, field: u64, wire_type: u64) {
    put_varint(output, (field << 3) | wire_type);
}
fn put_varint_field(output: &mut Vec<u8>, field: u64, value: u64) {
    put_key(output, field, 0);
    put_varint(output, value);
}
fn put_fixed64_field(output: &mut Vec<u8>, field: u64, value: u64) {
    put_key(output, field, 1);
    output.extend_from_slice(&value.to_le_bytes());
}
fn put_string(output: &mut Vec<u8>, field: u64, value: &str) {
    put_bytes(output, field, value.as_bytes());
}
fn put_bytes(output: &mut Vec<u8>, field: u64, value: &[u8]) {
    put_key(output, field, 2);
    put_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}
fn put_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

struct WireReader<'a> {
    data: &'a [u8],
    index: usize,
}
impl<'a> WireReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }
    fn is_finished(&self) -> bool {
        self.index == self.data.len()
    }
    fn varint(&mut self) -> anyhow::Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .data
                .get(self.index)
                .ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))?;
            self.index += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        anyhow::bail!("protobuf varint exceeds 64 bits")
    }
    fn varint_for(&mut self, wire_type: u64) -> anyhow::Result<u64> {
        if wire_type != 0 {
            anyhow::bail!("protobuf field expected varint");
        }
        self.varint()
    }
    fn fixed64(&mut self, wire_type: u64) -> anyhow::Result<u64> {
        if wire_type != 1 {
            anyhow::bail!("protobuf field expected fixed64");
        }
        let bytes = self
            .data
            .get(self.index..self.index + 8)
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf fixed64"))?;
        self.index += 8;
        Ok(u64::from_le_bytes(bytes.try_into().expect("fixed 8 bytes")))
    }
    fn length_bytes(&mut self, wire_type: u64) -> anyhow::Result<Vec<u8>> {
        if wire_type != 2 {
            anyhow::bail!("protobuf field expected length-delimited data");
        }
        let length = usize::try_from(self.varint()?)
            .map_err(|_| anyhow::anyhow!("protobuf length overflow"))?;
        if length > MAX_VSHIFT_ALERT_BYTES {
            anyhow::bail!("protobuf field exceeds message size bound");
        }
        let bytes = self
            .data
            .get(self.index..self.index + length)
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf field"))?;
        self.index += length;
        Ok(bytes.to_vec())
    }
    fn skip_unknown(&mut self, wire_type: u64) -> anyhow::Result<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => {
                self.index = self
                    .index
                    .checked_add(8)
                    .filter(|end| *end <= self.data.len())
                    .ok_or_else(|| anyhow::anyhow!("truncated unknown fixed64 field"))?;
            }
            2 => {
                let _ = self.length_bytes(2)?;
            }
            5 => {
                self.index = self
                    .index
                    .checked_add(4)
                    .filter(|end| *end <= self.data.len())
                    .ok_or_else(|| anyhow::anyhow!("truncated unknown fixed32 field"))?;
            }
            _ => anyhow::bail!("unsupported protobuf wire type {wire_type}"),
        }
        Ok(())
    }
}

#[derive(Default)]
struct Once<T>(Option<T>);
impl<T> Once<T> {
    fn set(&mut self, value: T, field: &str) -> anyhow::Result<()> {
        if self.0.replace(value).is_some() {
            anyhow::bail!("duplicate protobuf field {field}");
        }
        Ok(())
    }
}
impl Once<Vec<u8>> {
    fn set_bytes(&mut self, value: Vec<u8>, field: &str) -> anyhow::Result<()> {
        self.set(value, field)
    }
}
impl Once<String> {
    fn set_string(&mut self, value: Vec<u8>, field: &str) -> anyhow::Result<()> {
        self.set(
            String::from_utf8(value)
                .map_err(|_| anyhow::anyhow!("protobuf {field} is not UTF-8"))?,
            field,
        )
    }
}
impl Once<u64> {
    fn set_varint(&mut self, value: u64, field: &str) -> anyhow::Result<()> {
        self.set(value, field)
    }
    fn set_fixed64(&mut self, value: u64, field: &str) -> anyhow::Result<()> {
        self.set(value, field)
    }
}
impl<T> Once<T> {
    fn take(self, field: &str) -> anyhow::Result<T> {
        self.0
            .ok_or_else(|| anyhow::anyhow!("missing required protobuf field {field}"))
    }
}

#[derive(Default)]
struct DecodedFields {
    alert_id: Once<String>,
    circle_id: Once<String>,
    policy_version: Once<u64>,
    policy_blob: Once<Vec<u8>>,
    signature: Once<Vec<u8>>,
    policy_hash: Once<Vec<u8>>,
    anomaly_id: Once<String>,
    recommendation_id: Once<String>,
    anomaly_score: Once<u64>,
    confidence: Once<u64>,
    justification: Once<String>,
    issued_at: Once<u64>,
    expires_at: Once<u64>,
    signer_id: Once<String>,
    public_key: Once<Vec<u8>>,
    algorithm: Once<String>,
    schema_version: Once<u64>,
}
impl DecodedFields {
    fn into_alert(self) -> anyhow::Result<VShiftAlert> {
        Ok(VShiftAlert {
            schema_version: u32::try_from(self.schema_version.take("schema_version")?)
                .map_err(|_| anyhow::anyhow!("schema_version overflow"))?,
            alert_id: self.alert_id.take("alert_id")?,
            circle_id: self.circle_id.take("circle_id")?,
            policy_version: self.policy_version.take("policy_version")?,
            policy_blob: self.policy_blob.take("policy_blob")?,
            policy_hash_hex: hex_encode(&self.policy_hash.take("policy_hash")?),
            guardian_signature_hex: hex_encode(&self.signature.take("guardian_signature")?),
            guardian_public_key_hex: hex_encode(&self.public_key.take("guardian_public_key")?),
            signer_id: self.signer_id.take("signer_id")?,
            signature_algorithm: self.algorithm.take("signature_algorithm")?,
            anomaly_id: self.anomaly_id.take("anomaly_id")?,
            recommendation_id: self.recommendation_id.take("recommendation_id")?,
            anomaly_score: f64::from_bits(self.anomaly_score.take("anomaly_score")?),
            confidence: f64::from_bits(self.confidence.take("confidence")?),
            ai_justification: self.justification.take("ai_justification")?,
            issued_at_ms: self.issued_at.take("issued_at_ms")?,
            expires_at_ms: self.expires_at.take("expires_at_ms")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::virtual_shift::{
        canonical_policy_bytes, sha256_hex, GuardianKeyManager, VersionedPolicyCandidate,
    };

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn signed_fixture() -> SignedVirtualShiftPolicy {
        let root = std::env::temp_dir().join(format!(
            "vshift_vs14_{}_{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("guardian.json");
        std::fs::write(
            &config,
            r#"{"schema_version":1,"guardian_id":"guardian-test","algorithm":"ed25519"}"#,
        )
        .unwrap();
        let manager = GuardianKeyManager::from_config(&config, root.join("keys")).unwrap();
        let mut policy = VersionedPolicyCandidate {
            schema_version: 1,
            policy_id: "vshift-circle-v22-test".into(),
            circle_id: "circle-test".into(),
            parent_policy_version: 21,
            policy_version: 22,
            source_recommendation_id: "rec-1".into(),
            source_anomaly_id: "anom-1".into(),
            actions: vec![],
            rules: vec![],
            applicable_members: vec!["nodeB".into()],
            canonical_sha256: String::new(),
            status: "candidate_not_signed".into(),
        };
        let bytes = canonical_policy_bytes(&policy).unwrap();
        policy.canonical_sha256 = sha256_hex(&bytes);
        let (signature_hex, public_key_hex) = manager.sign(&bytes).unwrap();
        let _ = std::fs::remove_dir_all(root);
        SignedVirtualShiftPolicy {
            schema_version: 1,
            policy,
            signer_id: manager.guardian_id().into(),
            algorithm: "ed25519".into(),
            signed_at_ms: 10,
            canonical_sha256: sha256_hex(&bytes),
            signature_hex,
            public_key_hex,
            status: "signed_not_broadcast".into(),
        }
    }
    fn alert() -> VShiftAlert {
        let signed = signed_fixture();
        VShiftAlert {
            schema_version: 1,
            alert_id: "alert-1".into(),
            circle_id: signed.policy.circle_id.clone(),
            policy_version: signed.policy.policy_version,
            policy_blob: canonical_policy_bytes(&signed.policy).unwrap(),
            policy_hash_hex: signed.canonical_sha256.clone(),
            guardian_signature_hex: signed.signature_hex,
            guardian_public_key_hex: signed.public_key_hex,
            signer_id: signed.signer_id,
            signature_algorithm: signed.algorithm,
            anomaly_id: "anom-1".into(),
            recommendation_id: "rec-1".into(),
            anomaly_score: 0.91,
            confidence: 0.82,
            ai_justification: "test justification".into(),
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
        }
    }
    #[test]
    fn protobuf_encode_decode_round_trip_preserves_complete_signed_alert() {
        let value = alert();
        assert_eq!(
            VShiftAlert::decode(&value.encode().unwrap()).unwrap(),
            value
        );
    }
    #[test]
    fn altered_signed_policy_or_signature_is_rejected() {
        let mut value = alert();
        value.policy_blob[0] ^= 1;
        assert!(value.validate().is_err());
        let mut value = alert();
        value.guardian_signature_hex.replace_range(0..2, "00");
        assert!(value.validate().is_err());
    }
    #[test]
    fn expiry_and_size_bounds_are_rejected() {
        let mut value = alert();
        value.expires_at_ms = value.issued_at_ms;
        assert!(value.validate().is_err());
        let mut value = alert();
        value.ai_justification = "x".repeat(MAX_JUSTIFICATION_BYTES + 1);
        assert!(value.validate().is_err());
    }
}
