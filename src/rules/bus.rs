use crate::rules::model::RuleEvent;
use std::sync::OnceLock;
use tokio::sync::broadcast;

static RULE_EVENT_TAP: OnceLock<broadcast::Sender<RuleEvent>> = OnceLock::new();

fn tap() -> &'static broadcast::Sender<RuleEvent> {
    RULE_EVENT_TAP.get_or_init(|| broadcast::channel(1024).0)
}

pub fn subscribe() -> broadcast::Receiver<RuleEvent> {
    tap().subscribe()
}

pub fn publish(event: RuleEvent) {
    let _ = tap().send(event);
}
