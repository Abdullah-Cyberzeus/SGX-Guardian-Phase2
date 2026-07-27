use crate::did::document::Proof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const VC_CONTEXT_CORE: &str = "https://www.w3.org/2018/credentials/v1";
pub const VC_CONTEXT_JWS_2020: &str = "https://w3id.org/security/suites/jws-2020/v1";
pub const VC_CONTEXT_STATUS_LIST_2021: &str = "https://w3id.org/vc/status-list/2021/v1";
pub const VC_CONTEXT_SGX_CIRCLE: &str = "https://schemas.cyberzeus.io/sgx/v1/circle-membership";

pub const TYPE_VC: &str = "VerifiableCredential";
pub const TYPE_CIRCLE_MEMBERSHIP: &str = "CircleMembershipCredential";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CredentialRole {
    Owner,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum MembershipStatus {
    #[default]
    Active,
    Suspended,
    Revoked,
}

impl MembershipStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl std::fmt::Display for MembershipStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSubject {
    pub id: String,
    pub role: CredentialRole,
    pub permissions: Vec<String>,
    pub join_date: String,
    pub circle_id: String,
    pub node_hint: Option<String>,
    pub membership_status: MembershipStatus,
    pub(crate) membership_status_explicit: bool,
}

impl CredentialSubject {
    pub fn new(
        id: String,
        role: CredentialRole,
        permissions: Vec<String>,
        join_date: String,
        circle_id: String,
        node_hint: Option<String>,
        membership_status: MembershipStatus,
    ) -> Self {
        Self {
            id,
            role,
            permissions,
            join_date,
            circle_id,
            node_hint,
            membership_status,
            membership_status_explicit: true,
        }
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|granted| granted == permission)
    }

    pub fn has_all_permissions(&self, permissions: &[&str]) -> bool {
        permissions
            .iter()
            .all(|permission| self.has_permission(permission))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSubjectSer<'a> {
    id: &'a str,
    role: &'a CredentialRole,
    permissions: &'a [String],
    join_date: &'a str,
    circle_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_hint: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership_status: Option<&'a MembershipStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSubjectDe {
    id: String,
    role: CredentialRole,
    permissions: Vec<String>,
    join_date: String,
    circle_id: String,
    #[serde(default)]
    node_hint: Option<String>,
    #[serde(default)]
    membership_status: Option<MembershipStatus>,
}

impl Serialize for CredentialSubject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CredentialSubjectSer {
            id: &self.id,
            role: &self.role,
            permissions: &self.permissions,
            join_date: &self.join_date,
            circle_id: &self.circle_id,
            node_hint: self.node_hint.as_ref(),
            membership_status: (self.membership_status_explicit
                || !self.membership_status.is_active())
            .then_some(&self.membership_status),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CredentialSubjectDe::deserialize(deserializer)?;
        let membership_status_explicit = wire.membership_status.is_some();
        Ok(Self {
            id: wire.id,
            role: wire.role,
            permissions: wire.permissions,
            join_date: wire.join_date,
            circle_id: wire.circle_id,
            node_hint: wire.node_hint,
            membership_status: wire.membership_status.unwrap_or_default(),
            membership_status_explicit,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    pub status_purpose: String,
    pub status_list_index: String,
    pub status_list_credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub vc_type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_status: CredentialStatus,
    pub proof: Proof,
}

impl VerifiableCredential {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match DateTime::parse_from_rfc3339(&self.expiration_date) {
            Ok(exp) => now > exp.with_timezone(&Utc),
            Err(_) => true,
        }
    }

    pub fn subject_did(&self) -> &str {
        &self.credential_subject.id
    }

    pub fn issuer_did(&self) -> &str {
        &self.issuer
    }

    pub fn has_active_membership_status(&self) -> bool {
        self.credential_subject.membership_status.is_active()
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.credential_subject.has_permission(permission)
    }

    pub fn has_all_permissions(&self, permissions: &[&str]) -> bool {
        self.credential_subject.has_all_permissions(permissions)
    }

    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }
}

pub(crate) fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), sort_json_keys(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(sort_json_keys).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn sample_subject() -> CredentialSubject {
        CredentialSubject::new(
            "did:guardian:subject".to_string(),
            CredentialRole::Member,
            vec!["mesh:join".to_string(), "did:resolve".to_string()],
            "2026-01-01T00:00:00Z".to_string(),
            "circle-1".to_string(),
            None,
            MembershipStatus::Active,
        )
    }

    fn sample_vc() -> VerifiableCredential {
        VerifiableCredential {
            context: vec![VC_CONTEXT_CORE.to_string()],
            id: "urn:uuid:vc-1".to_string(),
            vc_type: vec![TYPE_VC.to_string(), TYPE_CIRCLE_MEMBERSHIP.to_string()],
            issuer: "did:guardian:issuer".to_string(),
            issuance_date: "2026-01-01T00:00:00Z".to_string(),
            expiration_date: "2026-06-01T00:00:00Z".to_string(),
            credential_subject: sample_subject(),
            credential_status: CredentialStatus {
                id: "did:guardian:issuer/status-list#1".to_string(),
                status_type: "StatusList2021Entry".to_string(),
                status_purpose: "revocation".to_string(),
                status_list_index: "1".to_string(),
                status_list_credential: "did:guardian:issuer/status-list".to_string(),
            },
            proof: Proof::default(),
        }
    }

    #[test]
    fn membership_status_is_active_and_display() {
        assert!(MembershipStatus::Active.is_active());
        assert!(!MembershipStatus::Suspended.is_active());
        assert!(!MembershipStatus::Revoked.is_active());
        assert_eq!(MembershipStatus::Active.to_string(), "active");
        assert_eq!(MembershipStatus::Suspended.to_string(), "suspended");
        assert_eq!(MembershipStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn credential_subject_permission_helpers() {
        let subject = sample_subject();
        assert!(subject.has_permission("mesh:join"));
        assert!(!subject.has_permission("vc:issue"));
        assert!(subject.has_all_permissions(&["mesh:join", "did:resolve"]));
        assert!(!subject.has_all_permissions(&["mesh:join", "vc:issue"]));
    }

    #[test]
    fn vc_accessor_helpers_delegate_to_subject() {
        let vc = sample_vc();
        assert_eq!(vc.subject_did(), "did:guardian:subject");
        assert_eq!(vc.issuer_did(), "did:guardian:issuer");
        assert!(vc.has_active_membership_status());
        assert!(vc.has_permission("mesh:join"));
        assert!(vc.has_all_permissions(&["mesh:join", "did:resolve"]));
    }

    #[test]
    fn is_expired_compares_against_expiration_date() {
        let vc = sample_vc();
        let before = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let after = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(!vc.is_expired(before));
        assert!(vc.is_expired(after));
    }

    #[test]
    fn is_expired_treats_malformed_expiration_date_as_expired() {
        let mut vc = sample_vc();
        vc.expiration_date = "not-a-date".to_string();
        assert!(vc.is_expired(chrono::Utc::now()));
    }

    #[test]
    fn canonical_bytes_for_sign_ignore_proof_but_detect_field_changes() {
        let mut vc = sample_vc();
        let baseline = vc.canonical_bytes_for_sign().expect("canonical");

        vc.proof = Proof {
            verification_method: "did:guardian:issuer#dkp-v1".to_string(),
            proof_value: "signature".to_string(),
            ..Proof::default()
        };
        assert_eq!(baseline, vc.canonical_bytes_for_sign().expect("canonical"));

        vc.expiration_date = "2027-01-01T00:00:00Z".to_string();
        assert_ne!(baseline, vc.canonical_bytes_for_sign().expect("canonical"));
    }

    #[test]
    fn credential_subject_serde_omits_membership_status_when_implicit_active() {
        let subject = CredentialSubject::new(
            "did:guardian:s".to_string(),
            CredentialRole::Member,
            vec![],
            "2026-01-01T00:00:00Z".to_string(),
            "circle-1".to_string(),
            None,
            MembershipStatus::Active,
        );
        let mut implicit = subject.clone();
        implicit.membership_status_explicit = false;
        let json = serde_json::to_value(&implicit).unwrap();
        assert!(json.get("membershipStatus").is_none());

        let json_explicit = serde_json::to_value(&subject).unwrap();
        assert!(json_explicit.get("membershipStatus").is_some());
    }

    #[test]
    fn sort_json_keys_orders_nested_objects_and_arrays() {
        let value = serde_json::json!({
            "b": 1,
            "a": {"z": 1, "y": 2},
            "c": [{"b": 1, "a": 2}]
        });
        let sorted = sort_json_keys(&value);
        let rendered = serde_json::to_string(&sorted).unwrap();
        assert_eq!(rendered, r#"{"a":{"y":2,"z":1},"b":1,"c":[{"a":2,"b":1}]}"#);
    }
}
