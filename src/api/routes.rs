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
        .route("/api/v1/vault/upload", post(handlers::vault::upload))
        .route(
            "/api/v1/vault/folders",
            post(handlers::vault::create_folder),
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

pub fn ha_api_router() -> Router<Arc<AppState>> {
    Router::new()
        // Integrations
        .route("/api/v1/ha/integrations", get(handlers::ha_integrations::list_integrations))
        .route("/api/v1/ha/integrations/{provider}/status", get(handlers::ha_integrations::get_integration_status))
        .route("/api/v1/ha/integrations/google_nest/oauth/auth_url", get(handlers::ha_integrations::get_nest_oauth_url))
        .route("/api/v1/ha/integrations/google_nest/oauth/callback", get(handlers::ha_integrations::nest_oauth_callback))
        .route("/api/v1/ha/integrations/{provider}/connect", post(handlers::ha_integrations::connect_integration))
        .route("/api/v1/ha/integrations/{provider}/disconnect", post(handlers::ha_integrations::disconnect_integration))

        // Devices
        .route("/api/v1/ha/devices", get(handlers::ha_devices::list_devices))
        .route("/api/v1/ha/devices/{id}", get(handlers::ha_devices::get_device))
        .route("/api/v1/ha/devices/{id}/state", get(handlers::ha_devices::get_device_state))
        .route("/api/v1/ha/devices/{id}/command", post(handlers::ha_devices::execute_device_command))
        .route("/api/v1/ha/devices/sync", post(handlers::ha_devices::sync_devices))

        // Automations
        .route(
            "/api/v1/ha/automations",
            get(handlers::ha_automations::list_automations).post(handlers::ha_automations::create_automation),
        )
        .route(
            "/api/v1/ha/automations/{id}",
            axum::routing::put(handlers::ha_automations::update_automation).delete(handlers::ha_automations::delete_automation),
        )
        .route("/api/v1/ha/automations/{id}/enable", post(handlers::ha_automations::enable_automation))
        .route("/api/v1/ha/automations/{id}/disable", post(handlers::ha_automations::disable_automation))

        // Telemetry & Health
        .route("/api/v1/ha/telemetry", get(handlers::ha_telemetry::list_telemetry))
        .route("/api/v1/ha/telemetry/{device_id}", get(handlers::ha_telemetry::get_device_telemetry))
        .route("/api/v1/ha/device-health", get(handlers::ha_telemetry::get_device_health))

        // Notifications
        .route("/api/v1/ha/notifications", get(handlers::ha_notifications::list_notifications))
        .route("/api/v1/ha/notifications/read", post(handlers::ha_notifications::mark_notifications_read))

        // Real-Time WebSocket
        .route("/api/v1/ha/ws", get(handlers::ha_websocket::websocket_handler))
}
