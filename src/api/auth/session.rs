use crate::api::auth::ecdsa::normalize_p256_signature;
use crate::api::auth::store::{SessionRec, User};
use crate::key_manager::KeyManager;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const JWT_HEADER_JSON: &str = r#"{"alg":"ES256","typ":"JWT"}"#;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub circle_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_registration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_fingerprint: Option<String>,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: String,
}

pub async fn issue(
    signer: Arc<KeyManager>,
    device_did: &str,
    user: &User,
    ttl: Duration,
) -> Result<(String, Claims, SessionRec)> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user.user_id.clone(),
        role: user.role.as_str().to_string(),
        scopes: if user.scopes.is_empty() {
            crate::api::auth::authorization::default_scopes(user.role.as_str())
        } else {
            user.scopes.clone()
        },
        circle_ids: user.circle_ids.clone(),
        browser_registration_id: user.browser_registration_id.clone(),
        guardian_fingerprint: user.guardian_fingerprint.clone(),
        iss: device_did.to_string(),
        iat: now,
        exp: now + ttl.as_secs() as i64,
        jti: Uuid::new_v4().to_string(),
    };
    let encoded_header = URL_SAFE_NO_PAD.encode(JWT_HEADER_JSON.as_bytes());
    let encoded_claims = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).map_err(|e| anyhow!("jwt claims serialize: {}", e))?);
    let signing_input = format!("{}.{}", encoded_header, encoded_claims);
    let signing_bytes = signing_input.clone().into_bytes();
    let signature = tokio::task::spawn_blocking(move || signer.sign(&signing_bytes))
        .await
        .map_err(|e| anyhow!("jwt signing task failed: {}", e))??;
    let signature =
        normalize_p256_signature(&signature).map_err(|e| anyhow!("jwt signature: {}", e))?;

    let token = format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature));
    let session = SessionRec {
        jti: claims.jti.clone(),
        user_id: claims.sub.clone(),
        issued_at: claims.iat,
        expires_at: claims.exp,
        revoked: false,
    };
    Ok((token, claims, session))
}

pub fn verify(public_key: &[u8], token: &str) -> Result<Claims> {
    let mut parts = token.split('.');
    let encoded_header = parts.next().ok_or_else(|| anyhow!("missing jwt header"))?;
    let encoded_claims = parts.next().ok_or_else(|| anyhow!("missing jwt claims"))?;
    let encoded_sig = parts
        .next()
        .ok_or_else(|| anyhow!("missing jwt signature"))?;
    if parts.next().is_some() {
        return Err(anyhow!("jwt has too many segments"));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|e| anyhow!("jwt header decode: {}", e))?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|e| anyhow!("jwt header json: {}", e))?;
    if header.alg != "ES256" {
        return Err(anyhow!("unsupported jwt alg {}", header.alg));
    }
    if !header.typ.is_empty() && header.typ != "JWT" {
        return Err(anyhow!("unsupported jwt typ {}", header.typ));
    }

    let signing_input = format!("{}.{}", encoded_header, encoded_claims);
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_sig)
        .map_err(|e| anyhow!("jwt signature decode: {}", e))?;
    let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key);
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| anyhow!("jwt signature verification failed"))?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(encoded_claims)
        .map_err(|e| anyhow!("jwt claims decode: {}", e))?;
    serde_json::from_slice(&claims_bytes).map_err(|e| anyhow!("jwt claims json: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn jwt_round_trip_verifies() {
        let td = TempDir::new().expect("tempdir");
        let key_path = td.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path"))
                .expect("load or generate key"),
        );
        let user = User {
            user_id: "user-1".into(),
            name: "Admin".into(),
            email: "admin@example.com".into(),
            pw_hash: "phc".into(),
            role: crate::api::auth::store::UserRole::Owner,
            scopes: vec![crate::api::auth::authorization::scope::ADMIN_ALL.into()],
            circle_ids: Vec::new(),
            browser_registration_id: None,
            guardian_fingerprint: None,
            registration_expires_at: None,
            invite_id: None,
            created_at: "2026-06-29T00:00:00Z".into(),
            status: "active".into(),
            failed_attempts: 0,
            locked_until: None,
            last_failed_at: None,
            oidc_sub: None,
        };

        let (token, claims, _) = issue(
            signer.clone(),
            "did:guardian:test",
            &user,
            Duration::from_secs(300),
        )
        .await
        .expect("issue token");
        let verified = verify(&signer.pubkey_der().expect("pubkey"), &token).expect("verify");

        assert_eq!(verified, claims);
    }
}
