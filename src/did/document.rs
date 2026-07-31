//! W3C DID Core 1.0 DID Document model for `did:guardian`.
//! JSON-LD is serialized as regular JSON with `@context`.

use crate::did::errors::DidError;
use crate::did::Did;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CONTEXT_DID_V1: &str = "https://www.w3.org/ns/did/v1";
pub const CONTEXT_JWS_2020: &str = "https://w3id.org/security/suites/jws-2020/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    pub service: Vec<ServiceEndpoint>,
    #[serde(rename = "sgx:nodeName", skip_serializing_if = "Option::is_none")]
    pub sgx_node_name: Option<String>,
    #[serde(rename = "sgx:created")]
    pub sgx_created: String,
    #[serde(rename = "sgx:updated")]
    pub sgx_updated: String,
    #[serde(rename = "sgx:versionId")]
    pub sgx_version_id: u32,
    #[serde(rename = "sgx:methodSpecVersion")]
    pub sgx_method_spec_version: String,
    #[serde(rename = "sgx:status", skip_serializing_if = "Option::is_none")]
    pub sgx_status: Option<String>,
    #[serde(
        rename = "sgx:revokedVerificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub sgx_revoked_vm: Vec<RevokedVm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub vm_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Jwk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub svc_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedVm {
    pub id: String,
    #[serde(rename = "revokedAt")]
    pub revoked_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub created: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

pub struct DocBuildInput<'a> {
    pub did: &'a str,
    pub node_name: Option<&'a str>,
    pub current_dkp_version: u32,
    pub current_dkp_pubkey_der: &'a [u8],
    pub overlay_ip_cidr: Option<&'a str>,
    pub attestation_bind: Option<(&'a str, u16)>,
    pub cert_bootstrap_bind: Option<(&'a str, u16)>,
    pub revoked: Vec<RevokedVm>,
    pub previous_version_id: u32,
    pub created_at: Option<String>,
    pub status: Option<String>,
}

impl DidDocument {
    pub fn build(input: DocBuildInput<'_>) -> Result<Self, DidError> {
        let now = Utc::now().to_rfc3339();
        let (x_bytes, y_bytes) = extract_xy_from_pubkey(input.current_dkp_pubkey_der)?;
        let vm_id = format!("{}#dkp-v{}", input.did, input.current_dkp_version);

        let vm = VerificationMethod {
            id: vm_id.clone(),
            vm_type: "JsonWebKey2020".into(),
            controller: input.did.to_string(),
            public_key_jwk: Jwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: general_purpose::URL_SAFE_NO_PAD.encode(x_bytes),
                y: general_purpose::URL_SAFE_NO_PAD.encode(y_bytes),
                kid: format!("dkp-v{}", input.current_dkp_version),
            },
        };

        let mut services = Vec::new();
        if let Some(cidr) = input.overlay_ip_cidr {
            services.push(ServiceEndpoint {
                id: format!("{}#sgx-mesh", input.did),
                svc_type: "SGXNebulaMesh".into(),
                service_endpoint: format!("nebula://{}", cidr),
            });
        }
        if let Some((ip, port)) = input.attestation_bind {
            services.push(ServiceEndpoint {
                id: format!("{}#sgx-attestation", input.did),
                svc_type: "SGXAttestation".into(),
                service_endpoint: format!("tcp://{}:{}", ip, port),
            });
        }
        if let Some((ip, port)) = input.cert_bootstrap_bind {
            services.push(ServiceEndpoint {
                id: format!("{}#sgx-cert-bootstrap", input.did),
                svc_type: "SGXCertBootstrap".into(),
                service_endpoint: format!("tcp://{}:{}", ip, port),
            });
        }

        let created = input.created_at.unwrap_or_else(|| now.clone());
        Ok(Self {
            context: vec![CONTEXT_DID_V1.into(), CONTEXT_JWS_2020.into()],
            id: input.did.to_string(),
            controller: input.did.to_string(),
            verification_method: vec![vm],
            authentication: vec![vm_id.clone()],
            assertion_method: vec![vm_id],
            service: services,
            sgx_node_name: input.node_name.map(String::from),
            sgx_created: created,
            sgx_updated: now,
            sgx_version_id: input.previous_version_id + 1,
            sgx_method_spec_version: "1.0".into(),
            sgx_status: input.status.or_else(|| Some("active".into())),
            sgx_revoked_vm: input.revoked,
            proof: None,
        })
    }

    pub fn without_proof(&self) -> Self {
        let mut c = self.clone();
        c.proof = None;
        c
    }

    /// Compare signed-meaning content while ignoring publish-only metadata.
    pub fn substantively_equal(&self, other: &DidDocument) -> bool {
        let mut a = self.without_proof();
        let mut b = other.without_proof();
        a.sgx_updated.clear();
        b.sgx_updated.clear();
        a.sgx_version_id = 0;
        b.sgx_version_id = 0;
        match (a.canonical_bytes_for_sign(), b.canonical_bytes_for_sign()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, DidError> {
        let v: Value = serde_json::to_value(self.without_proof())?;
        let sorted = sort_value(&v);
        let s = serde_json::to_string(&sorted)?;
        Ok(s.into_bytes())
    }

    pub fn did(&self) -> Result<Did, DidError> {
        Did::parse(&self.id)
    }

    pub fn primary_public_key_bytes(&self) -> Option<Vec<u8>> {
        let vm = self.verification_method.first()?;
        let jwk = &vm.public_key_jwk;
        if jwk.kty != "EC" || jwk.crv != "P-256" {
            return None;
        }
        let x = general_purpose::URL_SAFE_NO_PAD
            .decode(jwk.x.as_bytes())
            .ok()?;
        let y = general_purpose::URL_SAFE_NO_PAD
            .decode(jwk.y.as_bytes())
            .ok()?;
        if x.len() != 32 || y.len() != 32 {
            return None;
        }
        let mut out = Vec::with_capacity(65);
        out.push(0x04);
        out.extend_from_slice(&x);
        out.extend_from_slice(&y);
        Some(out)
    }
}

fn extract_xy_from_pubkey(pubkey: &[u8]) -> Result<([u8; 32], [u8; 32]), DidError> {
    let point = if pubkey.len() == 65 && pubkey.first() == Some(&0x04) {
        pubkey
    } else if pubkey.len() == 91 {
        &pubkey[26..]
    } else if pubkey.len() > 65 && pubkey[pubkey.len() - 65] == 0x04 {
        &pubkey[pubkey.len() - 65..]
    } else {
        return Err(DidError::InvalidFormat(format!(
            "Unsupported pubkey length {} for DID document",
            pubkey.len()
        )));
    };

    if point.len() != 65 || point[0] != 0x04 {
        return Err(DidError::InvalidFormat(
            "Public key must be uncompressed P-256 point (04 || X || Y)".into(),
        ));
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&point[1..33]);
    y.copy_from_slice(&point[33..65]);
    Ok((x, y))
}

fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), sort_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
        _ => v.clone(),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const SAMPLE_PUBKEY: [u8; 65] = {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        let mut i = 1;
        while i < 65 {
            bytes[i] = i as u8;
            i += 1;
        }
        bytes
    };

    fn build_input(did: &'static str) -> DocBuildInput<'static> {
        DocBuildInput {
            did,
            node_name: Some("nodeA"),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &SAMPLE_PUBKEY,
            overlay_ip_cidr: None,
            attestation_bind: None,
            cert_bootstrap_bind: None,
            revoked: vec![],
            previous_version_id: 0,
            created_at: None,
            status: None,
        }
    }

    #[test]
    fn build_sets_defaults_and_verification_method() {
        let doc = DidDocument::build(build_input("did:guardian:abc")).expect("build");
        assert_eq!(doc.id, "did:guardian:abc");
        assert_eq!(doc.controller, "did:guardian:abc");
        assert_eq!(doc.sgx_version_id, 1);
        assert_eq!(doc.sgx_status.as_deref(), Some("active"));
        assert!(doc.service.is_empty());
        assert_eq!(doc.verification_method.len(), 1);
        let vm = &doc.verification_method[0];
        assert_eq!(vm.id, "did:guardian:abc#dkp-v1");
        assert_eq!(vm.public_key_jwk.kty, "EC");
        assert_eq!(vm.public_key_jwk.crv, "P-256");
        assert_eq!(doc.authentication, vec![vm.id.clone()]);
        assert_eq!(doc.assertion_method, vec![vm.id.clone()]);
    }

    #[test]
    fn build_adds_optional_service_endpoints() {
        let mut input = build_input("did:guardian:svc");
        input.overlay_ip_cidr = Some("10.10.0.5/24");
        input.attestation_bind = Some(("10.10.0.5", 9000));
        input.cert_bootstrap_bind = Some(("10.10.0.5", 9001));
        let doc = DidDocument::build(input).expect("build");
        assert_eq!(doc.service.len(), 3);
        assert!(doc
            .service
            .iter()
            .any(|svc| svc.svc_type == "SGXNebulaMesh"
                && svc.service_endpoint.contains("10.10.0.5/24")));
        assert!(doc
            .service
            .iter()
            .any(|svc| svc.svc_type == "SGXAttestation" && svc.service_endpoint.contains("9000")));
        assert!(
            doc.service
                .iter()
                .any(|svc| svc.svc_type == "SGXCertBootstrap"
                    && svc.service_endpoint.contains("9001"))
        );
    }

    #[test]
    fn without_proof_clears_proof_field() {
        let mut doc = DidDocument::build(build_input("did:guardian:proof")).expect("build");
        doc.proof = Some(Proof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "ecdsa-2019".to_string(),
            verification_method: "did:guardian:proof#dkp-v1".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "sig".to_string(),
        });
        assert!(doc.without_proof().proof.is_none());
        // Original document is untouched.
        assert!(doc.proof.is_some());
    }

    #[test]
    fn substantively_equal_ignores_publish_metadata_but_detects_real_changes() {
        let doc_a = DidDocument::build(build_input("did:guardian:eq")).expect("build");
        let mut doc_b = doc_a.clone();
        doc_b.sgx_updated = "some-other-timestamp".to_string();
        doc_b.sgx_version_id = 42;
        assert!(doc_a.substantively_equal(&doc_b));

        doc_b.sgx_node_name = Some("different-name".to_string());
        assert!(!doc_a.substantively_equal(&doc_b));
    }

    #[test]
    fn canonical_bytes_for_sign_is_deterministic() {
        let doc = DidDocument::build(build_input("did:guardian:canon")).expect("build");
        let first = doc.canonical_bytes_for_sign().expect("canonical");
        let second = doc.canonical_bytes_for_sign().expect("canonical");
        assert_eq!(first, second);
    }

    #[test]
    fn primary_public_key_bytes_roundtrip_and_rejects_bad_curve() {
        let doc = DidDocument::build(build_input("did:guardian:pk")).expect("build");
        let bytes = doc.primary_public_key_bytes().expect("primary key bytes");
        assert_eq!(bytes, SAMPLE_PUBKEY.to_vec());

        let mut bad_curve = doc.clone();
        bad_curve.verification_method[0].public_key_jwk.crv = "P-384".to_string();
        assert!(bad_curve.primary_public_key_bytes().is_none());
    }

    #[test]
    fn extract_xy_from_pubkey_accepts_65_and_91_byte_forms() {
        let (x, y) = extract_xy_from_pubkey(&SAMPLE_PUBKEY).expect("65-byte form");
        assert_eq!(x, SAMPLE_PUBKEY[1..33]);
        assert_eq!(y, SAMPLE_PUBKEY[33..65]);

        let mut der_91 = vec![0u8; 26];
        der_91.extend_from_slice(&SAMPLE_PUBKEY);
        let (x91, y91) = extract_xy_from_pubkey(&der_91).expect("91-byte form");
        assert_eq!(x91, x);
        assert_eq!(y91, y);
    }

    #[test]
    fn extract_xy_from_pubkey_rejects_unsupported_lengths() {
        assert!(extract_xy_from_pubkey(&[0u8; 10]).is_err());
        assert!(extract_xy_from_pubkey(&[0u8; 65]).is_err()); // missing 0x04 prefix
    }

    #[test]
    fn sort_value_orders_object_keys_recursively() {
        let value: Value = serde_json::json!({
            "b": 1,
            "a": {"z": 1, "y": 2},
            "c": [{"b": 1, "a": 2}]
        });
        let sorted = sort_value(&value);
        let rendered = serde_json::to_string(&sorted).unwrap();
        assert_eq!(rendered, r#"{"a":{"y":2,"z":1},"b":1,"c":[{"a":2,"b":1}]}"#);
    }
}
