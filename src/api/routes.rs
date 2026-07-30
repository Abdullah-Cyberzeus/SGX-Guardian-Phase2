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
