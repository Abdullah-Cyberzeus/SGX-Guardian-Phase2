use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use axum::http::Method;
use std::collections::HashSet;

pub mod scope {
    pub const ADMIN_ALL: &str = "admin:*";
    pub const GUARDIAN_READ: &str = "guardian:read";
    pub const CIRCLES_READ: &str = "circles:read";
    pub const MESSAGES_READ: &str = "messages:read";
    pub const MESSAGES_SEND: &str = "messages:send";
    pub const CALLS_USE: &str = "calls:use";
    pub const CONTACTS_READ: &str = "contacts:read";
    pub const CONTACTS_MANAGE: &str = "contacts:manage";
    pub const FILES_READ: &str = "files:read";
    pub const FILES_UPLOAD: &str = "files:upload";
    pub const NOTIFICATIONS_READ: &str = "notifications:read";
    pub const NOTIFICATIONS_MANAGE: &str = "notifications:manage";
    pub const SETTINGS_OWN: &str = "settings:own";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessDecision {
    Allowed,
    Denied { required_scope: &'static str },
}

/// DIDs that share at least one locally joined Circle with this Guardian.
/// The browser represents the Guardian, so Circle access is derived from the
/// Guardian's existing DID membership rather than inventing a browser DID.
pub fn local_circle_contact_dids(
    node_id: &str,
    guardian_did: &str,
) -> Result<HashSet<String>, String> {
    scoped_circle_contact_dids(node_id, guardian_did, &[])
}

/// Contacts sharing an active Guardian Circle that is also present in the
/// browser credential. Empty scope is reserved for administrative callers.
pub fn scoped_circle_contact_dids(
    node_id: &str,
    guardian_did: &str,
    allowed_circle_ids: &[String],
) -> Result<HashSet<String>, String> {
    let mut circle_ids = local_active_circle_ids(node_id, guardian_did)?;
    if !allowed_circle_ids.is_empty() {
        circle_ids.retain(|circle_id| allowed_circle_ids.contains(circle_id));
    }
    let issued = crate::vc::persistence::list_issued()
        .map_err(|error| format!("load issued memberships: {}", error))?;
    let peers = crate::vc::persistence::list_peers()
        .map_err(|error| format!("load peer memberships: {}", error))?;
    let mut contacts = issued
        .into_iter()
        .chain(peers)
        .filter(active_membership_credential)
        .filter(|vc| circle_ids.contains(&vc.credential_subject.circle_id))
        .map(|vc| vc.subject_did().to_string())
        .filter(|did| did != guardian_did)
        .collect::<HashSet<_>>();

    // Authoritative Circle snapshots also contain browser-member DIDs. They
    // do not have overlay peer VCs of their own, so a VC-only roster silently
    // drops them from messaging, calls, and file-transfer recipient lists.
    for circle_id in &circle_ids {
        let Ok(members) = crate::circle::members::list_members(node_id, circle_id) else {
            continue;
        };
        contacts.extend(
            members
                .into_iter()
                .filter(|member| {
                    matches!(
                        member.lifecycle_state,
                        crate::circle::members::MemberLifecycleState::Active
                    )
                })
                .map(|member| member.did)
                .filter(|did| did != guardian_did),
        );
    }

    Ok(contacts)
}

pub fn local_active_circle_ids(
    node_id: &str,
    guardian_did: &str,
) -> Result<HashSet<String>, String> {
    let known = crate::circle::store::load_or_seed(node_id)
        .map_err(|error| format!("load Circle registry: {:?}", error))?
        .circles
        .into_iter()
        .map(|circle| circle.circle_id)
        .collect::<HashSet<_>>();
    let own = crate::vc::persistence::list_own()
        .map_err(|error| format!("load own memberships: {}", error))?;
    let issued = crate::vc::persistence::list_issued()
        .map_err(|error| format!("load issued memberships: {}", error))?;
    Ok(own
        .into_iter()
        .chain(issued)
        .filter(active_membership_credential)
        .filter(|vc| vc.subject_did() == guardian_did)
        .map(|vc| vc.credential_subject.circle_id)
        .filter(|circle_id| known.contains(circle_id))
        .collect())
}

fn active_membership_credential(vc: &crate::vc::credential::VerifiableCredential) -> bool {
    vc.has_active_membership_status()
        && chrono::DateTime::parse_from_rfc3339(&vc.expiration_date)
            .map(|expires| expires > chrono::Utc::now())
            .unwrap_or(false)
        && !crate::crl::is_revoked(vc.subject_did())
}

pub fn audit_member_resource_denied(node_id: &str, actor: &str, resource: &str) {
    log_audit(
        node_id,
        AuditCategory::Identity,
        AuditSeverity::Warning,
        AuditAction::Rejected,
        &format!(
            "member resource authorization denied actor={} resource={}",
            actor, resource
        ),
    );
}

pub fn default_scopes(role: &str) -> Vec<String> {
    match role {
        "owner" | "admin" => vec![scope::ADMIN_ALL.to_string()],
        "member" => [
            scope::GUARDIAN_READ,
            scope::CIRCLES_READ,
            scope::MESSAGES_READ,
            scope::MESSAGES_SEND,
            scope::CALLS_USE,
            scope::CONTACTS_READ,
            scope::CONTACTS_MANAGE,
            scope::FILES_READ,
            scope::FILES_UPLOAD,
            scope::NOTIFICATIONS_READ,
            scope::NOTIFICATIONS_MANAGE,
            scope::SETTINGS_OWN,
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        _ => Vec::new(),
    }
}

/// A user's persisted `scopes` are set once at account creation from
/// `default_scopes(role)` and never revisited — there is no admin feature to
/// customize an individual member's scopes narrower than their role's
/// baseline. So when the role's default scope set gains a new capability,
/// an already-existing user's stored scopes silently fall behind and stay
/// stuck forever otherwise. Healing them to the union with the current
/// defaults keeps existing accounts in step with new baseline capabilities.
pub fn effective_scopes(role: &str, stored_scopes: &[String]) -> Vec<String> {
    if stored_scopes.is_empty() {
        return default_scopes(role);
    }
    let mut merged = stored_scopes.to_vec();
    for scope in default_scopes(role) {
        if !merged.contains(&scope) {
            merged.push(scope);
        }
    }
    merged
}

pub fn authorize(role: &str, scopes: &[String], method: &Method, path: &str) -> AccessDecision {
    if matches!(role, "owner" | "admin") {
        return AccessDecision::Allowed;
    }
    if role != "member" {
        return AccessDecision::Denied {
            required_scope: scope::ADMIN_ALL,
        };
    }

    let Some(required_scope) = member_required_scope(method, path) else {
        return AccessDecision::Denied {
            required_scope: scope::ADMIN_ALL,
        };
    };
    if scopes.iter().any(|candidate| candidate == required_scope) {
        AccessDecision::Allowed
    } else {
        AccessDecision::Denied { required_scope }
    }
}

fn member_required_scope(method: &Method, path: &str) -> Option<&'static str> {
    if matches!(
        path,
        "/api/v1/auth/session" | "/api/v1/auth/logout" | "/api/v1/auth/sessions/revoke-all"
    ) {
        return Some(scope::SETTINGS_OWN);
    }
    if method == Method::POST && path == "/api/v1/auth/session/refresh" {
        return Some(scope::SETTINGS_OWN);
    }
    if method == Method::PATCH && path == "/api/v1/auth/profile" {
        return Some(scope::SETTINGS_OWN);
    }
    if method == Method::DELETE && path == "/api/v1/pwa/registration" {
        return Some(scope::SETTINGS_OWN);
    }
    if method == Method::POST && path == "/api/v1/pwa/circles/join" {
        return Some(scope::CIRCLES_READ);
    }
    if method == Method::GET && path == "/api/v1/node/status" {
        return Some(scope::GUARDIAN_READ);
    }
    if method == Method::PATCH && path == "/api/v1/node/status" {
        return Some(scope::SETTINGS_OWN);
    }
    if method == Method::GET && path == "/api/v1/pwa/identity" {
        return Some(scope::GUARDIAN_READ);
    }
    if method == Method::GET && path == "/api/v1/pwa/health" {
        return Some(scope::GUARDIAN_READ);
    }
    if method == Method::GET && path == "/api/v1/pwa/contacts" {
        return Some(scope::CONTACTS_READ);
    }
    if path == "/api/v1/contacts" {
        return match *method {
            Method::GET => Some(scope::CONTACTS_READ),
            Method::POST => Some(scope::CONTACTS_MANAGE),
            _ => None,
        };
    }
    if path.starts_with("/api/v1/contacts/") {
        return match *method {
            Method::GET => Some(scope::CONTACTS_READ),
            Method::PATCH | Method::DELETE => Some(scope::CONTACTS_MANAGE),
            _ => None,
        };
    }

    if path == "/api/v1/circles" && method == Method::GET {
        return Some(scope::CIRCLES_READ);
    }
    if path.starts_with("/api/v1/circles/") {
        if method == Method::GET && is_member_circle_read(path) {
            return Some(if path.ends_with("/members") {
                scope::CONTACTS_READ
            } else {
                scope::CIRCLES_READ
            });
        }
        if method == Method::POST
            && matches!(
                path,
                "/api/v1/circles/join/preview" | "/api/v1/circles/join"
            )
        {
            return Some(scope::CIRCLES_READ);
        }
        return None;
    }

    if path.starts_with("/api/v1/chat/") {
        return match (method, path) {
            (&Method::GET, "/api/v1/chat/history" | "/api/v1/chat/ws") => {
                Some(scope::MESSAGES_READ)
            }
            (&Method::POST, "/api/v1/chat/send" | "/api/v1/chat/read") => {
                Some(scope::MESSAGES_SEND)
            }
            (&Method::POST, "/api/v1/chat/upload") => Some(scope::FILES_UPLOAD),
            (&Method::GET, _) if path.starts_with("/api/v1/chat/download/") => {
                Some(scope::FILES_READ)
            }
            _ => None,
        };
    }

    // These legacy device-level operations accept authoritative identity or
    // routing fields from their request bodies. Member browsers must use the
    // browser-safe, state-derived routes below instead.
    if matches!(
        path,
        "/api/v1/call/initiate"
            | "/api/v1/call/accept"
            | "/api/v1/call/reject"
            | "/api/v1/call/end"
            | "/api/v1/call/policy-check"
    ) {
        return None;
    }
    if path == "/api/v1/calls"
        || path.starts_with("/api/v1/calls/")
        || path.starts_with("/api/v1/call/")
        || path == "/api/v1/group-calls"
        || path.starts_with("/api/v1/group-calls/")
        || path.starts_with("/api/v1/group-call/")
    {
        return Some(scope::CALLS_USE);
    }

    if path.starts_with("/api/v1/vault/") {
        if method == Method::GET {
            return Some(scope::FILES_READ);
        }
        // Owner-only actions on a specific file (revoke/expiry) are handler-
        // enforced against `owner_did`, so members need the upload scope to
        // reach them at all — unlike the broader "manage shared Vault
        // metadata" mutations below, which stay admin/owner-only.
        if path.starts_with("/api/v1/vault/files/")
            && (method == Method::POST && path.ends_with("/revoke")
                || method == Method::PATCH && path.ends_with("/expiry"))
        {
            return Some(scope::FILES_UPLOAD);
        }
        return (method == Method::POST && path == "/api/v1/vault/upload")
            .then_some(scope::FILES_UPLOAD);
    }
    if path.starts_with("/api/v1/xfer/") {
        if method == Method::GET {
            return Some(scope::FILES_READ);
        }
        return (method == Method::POST
            && (path == "/api/v1/xfer/send" || path.ends_with("/cancel")))
        .then_some(scope::FILES_UPLOAD);
    }

    if path == "/api/v1/notifications"
        || path == "/api/v1/notifications/stream"
        || path == "/api/v1/notifications/unread-count"
    {
        return (method == Method::GET).then_some(scope::NOTIFICATIONS_READ);
    }
    if path.starts_with("/api/v1/notifications/") {
        if method == Method::GET {
            return Some(scope::NOTIFICATIONS_READ);
        }
        return (method == Method::POST
            && (path == "/api/v1/notifications/read-all" || path.ends_with("/read")))
        .then_some(scope::NOTIFICATIONS_MANAGE);
    }

    None
}

fn is_member_circle_read(path: &str) -> bool {
    let rest = path.trim_start_matches("/api/v1/circles/");
    let parts = rest.split('/').collect::<Vec<_>>();
    matches!(parts.as_slice(), [_circle_id] | [_circle_id, "members"])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_scopes() -> Vec<String> {
        default_scopes("member")
    }

    #[test]
    fn owner_and_admin_keep_full_existing_access() {
        for role in ["owner", "admin"] {
            assert_eq!(
                authorize(role, &[], &Method::POST, "/api/v1/policy/sign"),
                AccessDecision::Allowed
            );
            assert_eq!(
                authorize(role, &[], &Method::POST, "/api/v1/cert/approve"),
                AccessDecision::Allowed
            );
        }
    }

    #[test]
    fn member_can_use_communication_and_personal_routes() {
        let scopes = member_scopes();
        for (method, path) in [
            (Method::GET, "/api/v1/pwa/contacts"),
            (Method::GET, "/api/v1/circles/circle-a/members"),
            (Method::POST, "/api/v1/chat/send"),
            (Method::GET, "/api/v1/chat/history"),
            (Method::POST, "/api/v1/calls/initiate"),
            (Method::GET, "/api/v1/vault/files"),
            (Method::POST, "/api/v1/vault/upload"),
            (Method::POST, "/api/v1/notifications/read-all"),
            (Method::POST, "/api/v1/auth/session/refresh"),
            (Method::POST, "/api/v1/pwa/circles/join"),
            (Method::DELETE, "/api/v1/pwa/registration"),
        ] {
            assert_eq!(
                authorize("member", &scopes, &method, path),
                AccessDecision::Allowed,
                "member route should be allowed: {method} {path}"
            );
        }
    }

    #[test]
    fn member_cannot_administer_guardian_or_circle() {
        let scopes = member_scopes();
        for (method, path) in [
            (Method::POST, "/api/v1/cert/approve"),
            (Method::POST, "/api/v1/policy/sign"),
            (Method::POST, "/api/v1/transport/lock"),
            (Method::POST, "/api/v1/circles"),
            (Method::DELETE, "/api/v1/circles/circle-a/members/did:test"),
            (Method::POST, "/api/v1/devices/pair"),
            (Method::POST, "/api/v1/node/restart"),
            (Method::POST, "/api/v1/call/initiate"),
            (Method::POST, "/api/v1/call/policy-check"),
            (Method::PUT, "/api/v1/notifications/prefs"),
        ] {
            assert!(
                matches!(
                    authorize("member", &scopes, &method, path),
                    AccessDecision::Denied { .. }
                ),
                "member route should be denied: {method} {path}"
            );
        }
    }

    #[test]
    fn member_must_possess_the_required_scope() {
        assert_eq!(
            authorize(
                "member",
                &[scope::MESSAGES_READ.to_string()],
                &Method::POST,
                "/api/v1/chat/send"
            ),
            AccessDecision::Denied {
                required_scope: scope::MESSAGES_SEND
            }
        );
    }
}
