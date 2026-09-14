//! Shared HTTP host composition. The Task3 API is mounted here rather than
//! owning a separate routing engine; its existing authorised operator contract
//! (`x-operator-id` allow-list, also used by Task1 settings) remains in force.

use crate::network_ai::{api_router, NetworkAiApiState};
use axum::Router;

pub fn application_router(network_ai: NetworkAiApiState) -> Router {
    Router::new().merge(api_router(network_ai))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::NetworkAiConfig;

    #[test]
    fn mounts_network_ai_routes_in_application_host() {
        let state = NetworkAiApiState::new(
            "data/network_ai",
            "config/network_ai.example.json",
            NetworkAiConfig::default(),
            vec!["nodeA".into()],
        );
        let _host = application_router(state);
    }
}
