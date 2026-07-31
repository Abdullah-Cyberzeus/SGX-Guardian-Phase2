use crate::geofence::model::Fix;
use crate::geofence::persistence;
use crate::geofence::sources::LocationSource;
use async_trait::async_trait;

pub struct ReportedSource;

#[async_trait]
impl LocationSource for ReportedSource {
    fn id(&self) -> &'static str {
        "reported"
    }

    async fn current(&self) -> Option<Fix> {
        let reported = persistence::load_reported_location_async()
            .await
            .ok()
            .flatten();
        if let Some(location) = reported {
            return Some(location.fix);
        }
        persistence::load_location_async()
            .await
            .ok()
            .flatten()
            .filter(|location| location.source == "reported")
            .map(|location| location.fix)
    }
}
