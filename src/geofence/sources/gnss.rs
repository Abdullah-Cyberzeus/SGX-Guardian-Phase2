use crate::geofence::model::Fix;
use crate::geofence::sources::LocationSource;
use async_trait::async_trait;

pub struct GnssSource;

#[async_trait]
impl LocationSource for GnssSource {
    fn id(&self) -> &'static str {
        "gnss"
    }

    async fn current(&self) -> Option<Fix> {
        None
    }
}
