use crate::notify::model::NotificationEvent;
use std::sync::OnceLock;
use tokio::sync::broadcast;

static NOTIFY_BUS: OnceLock<broadcast::Sender<NotificationEvent>> = OnceLock::new();

fn bus() -> &'static broadcast::Sender<NotificationEvent> {
    NOTIFY_BUS.get_or_init(|| broadcast::channel(1024).0)
}

pub fn subscribe() -> broadcast::Receiver<NotificationEvent> {
    bus().subscribe()
}

pub fn publish(event: NotificationEvent) {
    let _ = bus().send(event);
}
