use crate::geofence::model::Fix;
use crate::geofence::persistence;
use crate::geofence::sources::LocationSource;
use async_trait::async_trait;

pub struct ManualSource;

#[async_trait]
impl LocationSource for ManualSource {
    fn id(&self) -> &'static str {
        "manual"
    }

    async fn current(&self) -> Option<Fix> {
        persistence::load_location_async()
            .await
            .ok()
            .flatten()
            .filter(|location| location.source == "manual")
            .map(|location| location.fix)
    }
}
