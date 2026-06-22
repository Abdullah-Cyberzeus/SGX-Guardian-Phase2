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
