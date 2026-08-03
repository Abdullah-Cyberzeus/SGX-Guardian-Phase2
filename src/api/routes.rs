use crate::api::handlers;
use crate::api::state::AppState;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, patch, post},
    Router,
};
use std::sync::Arc;

const VAULT_UPLOAD_BODY_LIMIT_BYTES: usize = 64 * 1024 * 1024;

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
        .route(
            "/api/v1/crl/offline/status",
            get(handlers::crl::offline_status),
        )
        .route(
            "/api/v1/crl/offline/pending",
            get(handlers::crl::offline_pending),
        )
        .route(
            "/api/v1/crl/offline/sync",
            post(handlers::crl::offline_sync),
        )
}

pub fn geofence_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/geofence/zones",
            get(handlers::geofence::list_zones).post(handlers::geofence::create_zone),
        )
        .route(
            "/api/v1/geofence/zones/{id}",
            patch(handlers::geofence::edit_zone).delete(handlers::geofence::delete_zone),
        )
        .route(
            "/api/v1/geofence/zones/{id}/capture-rf",
            post(handlers::geofence::capture_rf),
        )
        .route(
            "/api/v1/geofence/location",
            get(handlers::geofence::get_location).post(handlers::geofence::report_location),
        )
        .route("/api/v1/geofence/status", get(handlers::geofence::status))
        .route("/api/v1/geofence/events", get(handlers::geofence::events))
        .route("/api/v1/geofence/alerts", get(handlers::geofence::alerts))
        .route(
            "/api/v1/geofence/zones/{id}/actions",
            get(handlers::geofence::get_actions).put(handlers::geofence::put_actions),
        )
        .route(
            "/api/v1/geofence/actions/test",
            post(handlers::geofence::test_actions),
        )
}

pub fn backup_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/backup/create", post(handlers::backup::create))
        .route("/api/v1/backup/history", get(handlers::backup::history))
        .route(
            "/api/v1/backup/download/{id}",
            get(handlers::backup::download),
        )
        .route(
            "/api/v1/backup/{id}",
            axum::routing::delete(handlers::backup::delete),
        )
        .route("/api/v1/backup/validate", post(handlers::backup::validate))
        .route("/api/v1/backup/restore", post(handlers::backup::restore))
}

pub fn restore_readonly_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/restore/validate",
            post(handlers::restore::validate),
        )
        .route("/api/v1/restore/status", get(handlers::restore::status))
}

pub fn restore_destructive_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/restore/apply", post(handlers::restore::apply))
        .route("/api/v1/restore/undo", post(handlers::restore::undo))
}

pub fn devices_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/managed-devices",
            get(handlers::devices::list).post(handlers::devices::add_manual),
        )
        .route(
            "/api/v1/managed-devices/summary",
            get(handlers::devices::summary),
        )
        .route(
            "/api/v1/managed-devices/{device_id}",
            get(handlers::devices::detail)
                .patch(handlers::devices::edit)
                .delete(handlers::devices::remove),
        )
        .route(
            "/api/v1/managed-devices/{device_id}/scan",
            post(handlers::devices::start_scan),
        )
        .route(
            "/api/v1/managed-devices/{device_id}/scan/{scan_id}",
            get(handlers::devices::scan_status),
        )
        .route(
            "/api/v1/managed-devices/{device_id}/block",
            post(handlers::devices::block),
        )
        .route(
            "/api/v1/managed-devices/{device_id}/reject",
            post(handlers::devices::reject),
        )
        .route(
            "/api/v1/managed-devices/{device_id}/unblock",
            post(handlers::devices::unblock),
        )
}

pub fn dusage_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/dusage/current", get(handlers::dusage::current))
        .route("/api/v1/dusage/history", get(handlers::dusage::history))
        .route(
            "/api/v1/dusage/quota",
            get(handlers::dusage::get_quota).put(handlers::dusage::put_quota),
        )
        .route("/api/v1/dusage/reset", post(handlers::dusage::reset))
}

pub fn xfer_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/xfer/send", post(handlers::xfer::send))
        .route("/api/v1/xfer/transfers", get(handlers::xfer::list))
        .route("/api/v1/xfer/transfers/{id}", get(handlers::xfer::detail))
        .route(
            "/api/v1/xfer/transfers/{id}/cancel",
            post(handlers::xfer::cancel),
        )
        .route("/api/v1/xfer/inbox", get(handlers::xfer::inbox))
}

pub fn vault_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/vault/overview", get(handlers::vault::overview))
        .route("/api/v1/vault/quota", get(handlers::vault::quota_status))
        .route("/api/v1/vault/tree", get(handlers::vault::tree))
        .route("/api/v1/vault/search", get(handlers::vault::search))
        .route(
            "/api/v1/vault/upload",
            post(handlers::vault::upload)
                .layer(DefaultBodyLimit::max(VAULT_UPLOAD_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/vault/folders",
            get(handlers::vault::list_folders).post(handlers::vault::create_folder),
        )
        .route(
            "/api/v1/vault/folders/{folder_id}",
            patch(handlers::vault::rename_or_move_folder).delete(handlers::vault::delete_folder),
        )
        .route("/api/v1/vault/files", get(handlers::vault::list))
        .route(
            "/api/v1/vault/files/{id}",
            get(handlers::vault::detail)
                .patch(handlers::vault::rename_or_move_file)
                .delete(handlers::vault::delete_file),
        )
        .route(
            "/api/v1/vault/files/{id}/download",
            get(handlers::vault::download),
        )
        .route(
            "/api/v1/vault/files/{id}/preview",
            get(handlers::vault::preview),
        )
        .route(
            "/api/v1/vault/files/{id}/star",
            post(handlers::vault::toggle_star),
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

pub fn rules_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/rules",
            get(handlers::rules::list).post(handlers::rules::create),
        )
        .route("/api/v1/rules/executions", get(handlers::rules::executions))
        .route(
            "/api/v1/rules/{id}",
            get(handlers::rules::detail)
                .patch(handlers::rules::edit)
                .delete(handlers::rules::delete),
        )
        .route(
            "/api/v1/rules/{id}/enable",
            post(handlers::rules::set_enabled),
        )
        .route("/api/v1/rules/{id}/test", post(handlers::rules::test))
}

pub fn circle_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/circles",
            get(handlers::circle::list).post(handlers::circle::create),
        )
        .route(
            "/api/v1/circles/{id}",
            get(handlers::circle::detail)
                .patch(handlers::circle::edit)
                .delete(handlers::circle::delete),
        )
        .route(
            "/api/v1/circles/{id}/archive",
            post(handlers::circle::archive),
        )
        .route(
            "/api/v1/circles/{id}/unarchive",
            post(handlers::circle::unarchive),
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
