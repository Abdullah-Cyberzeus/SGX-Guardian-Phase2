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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MembershipStatus {
    Active,
    Suspended,
    Revoked,
}

impl Default for MembershipStatus {
    fn default() -> Self {
        Self::Active
    }
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
        Ok(serde_json::to_vec(&sort_json_keys(&value))?)
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
