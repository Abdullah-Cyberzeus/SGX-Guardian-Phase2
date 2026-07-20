use crate::api::handlers;
use crate::api::state::AppState;
use axum::{
    routing::{get, patch, post},
    Router,
};
use std::sync::Arc;

pub fn crl_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/crl/revoke", post(handlers::crl::revoke))
        .route("/api/v1/crl/unrevoke", post(handlers::crl::unrevoke))
        .route("/api/v1/crl/list", get(handlers::crl::list))
        .route("/api/v1/crl/entry", get(handlers::crl::entry))
        .route("/api/v1/crl/check", get(handlers::crl::check))
        .route("/api/v1/crl/verify", post(handlers::crl::verify))
        .route("/api/v1/crl/root", get(handlers::crl::root))
        .route(
            "/api/v1/crl/gossip/status",
            get(handlers::crl::gossip_status),
        )
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
        .route(
            "/api/v1/crl/emergency/status",
            get(handlers::crl::emergency_status),
        )
        .route(
            "/api/v1/crl/emergency/broadcast",
            post(handlers::crl::emergency_broadcast),
        )
        .route(
            "/api/v1/crl/emergency/notifications",
            get(handlers::crl::emergency_notifications),
        )
        .route(
            "/api/v1/crl/emergency/debug/session",
            get(handlers::crl::emergency_debug_session_status)
                .post(handlers::crl::emergency_debug_session_seed),
        )
}

pub fn notify_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/notifications/stream",
            get(handlers::notify::stream),
        )
        .route("/api/v1/notifications", get(handlers::notify::history))
        .route(
            "/api/v1/notifications/unread-count",
            get(handlers::notify::unread_count),
        )
        .route(
            "/api/v1/notifications/{id}/read",
            post(handlers::notify::mark_read),
        )
        .route(
            "/api/v1/notifications/read-all",
            post(handlers::notify::mark_all_read),
        )
        .route(
            "/api/v1/notifications/prefs",
            get(handlers::notify::get_prefs).put(handlers::notify::put_prefs),
        )
}

pub fn circle_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/circles", get(handlers::circle::list).post(handlers::circle::create))
        .route(
            "/api/v1/circles/{id}",
            get(handlers::circle::detail).patch(handlers::circle::edit),
        )
        .route(
            "/api/v1/circles/{id}/archive",
            post(handlers::circle::archive),
        )
        .route(
            "/api/v1/circles/{id}/members",
            get(handlers::circle::list_members).post(handlers::circle::add_member),
        )
        .route(
            "/api/v1/circles/{id}/members/{did}",
            patch(handlers::circle::change_role).delete(handlers::circle::remove_member),
        )
        .route(
            "/api/v1/circles/{id}/invites",
            get(handlers::circle::list_invites).post(handlers::circle::mint_invite),
        )
        .route(
            "/api/v1/circles/{id}/invites/{invite_id}",
            axum::routing::delete(handlers::circle::revoke_invite),
        )
        .route(
            "/api/v1/circles/join/preview",
            post(handlers::circle::join_preview),
        )
        .route("/api/v1/circles/join", post(handlers::circle::join))
        .route("/api/v1/circles/redeem", post(handlers::circle::redeem))
}
