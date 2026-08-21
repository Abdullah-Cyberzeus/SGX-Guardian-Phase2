use crate::api::auth::store::UserRole;
use crate::api::state::AppState;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMemberState {
    Active,
    Inactive,
}

pub fn did_for_registration(registration_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sgx-guardian:pwa-browser-member:v1:");
    hasher.update(registration_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    crate::did::Did::from_id_bytes(&bytes).to_string()
}

pub fn did_from_session(
    session: &Option<axum::Extension<crate::api::auth::middleware::AuthenticatedSession>>,
) -> Option<String> {
    let axum::Extension(session) = session.as_ref()?;
    if session.claims.role != "member" {
        return None;
    }
    session
        .claims
        .browser_registration_id
        .as_deref()
        .map(did_for_registration)
}

pub async fn state_for_did(
    state: &AppState,
    did: &str,
    allowed_circle_ids: &std::collections::HashSet<String>,
) -> Result<Option<BrowserMemberState>, crate::api::error::ApiError> {
    let now = chrono::Utc::now().timestamp();
    let users = state.admin.users.list().await?;
    for user in users {
        if user.role != UserRole::Member
            || !user
                .circle_ids
                .iter()
                .any(|circle_id| allowed_circle_ids.contains(circle_id))
        {
            continue;
        }
        let Some(registration_id) = user.browser_registration_id.as_deref() else {
            continue;
        };
        if did_for_registration(registration_id) != did {
            continue;
        }
        let active = user.status == "active"
            && user
                .registration_expires_at
                .is_none_or(|expiry| expiry > now);
        return Ok(Some(if active {
            BrowserMemberState::Active
        } else {
            BrowserMemberState::Inactive
        }));
    }
    Ok(None)
}

pub async fn dids_for_circles(
    state: &AppState,
    allowed_circle_ids: &std::collections::HashSet<String>,
) -> Result<std::collections::HashSet<String>, crate::api::error::ApiError> {
    let now = chrono::Utc::now().timestamp();
    let users = state.admin.users.list().await?;
    Ok(users
        .into_iter()
        .filter(|user| {
            user.role == UserRole::Member
                && user.status == "active"
                && user
                    .registration_expires_at
                    .is_none_or(|expiry| expiry > now)
                && user
                    .circle_ids
                    .iter()
                    .any(|circle_id| allowed_circle_ids.contains(circle_id))
        })
        .filter_map(|user| {
            user.browser_registration_id
                .map(|id| did_for_registration(&id))
        })
        .collect())
}
