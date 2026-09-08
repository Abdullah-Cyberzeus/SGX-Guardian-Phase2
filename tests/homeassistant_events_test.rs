use serde_json::json;
use sgx_guardian_client::homeassistant::events::{start_event_dispatcher, EventBus, HaEvent};
use tokio::sync::broadcast::error::TryRecvError;

#[tokio::test]
async fn new_bus_allows_subscription() {
    let bus = EventBus::new();
    let _rx = bus.subscribe();
}

macro_rules! event_delivery_tests {
    ($($name:ident => $event:expr, $check:pat),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let bus = EventBus::new();
                let mut rx = bus.subscribe();
                bus.publish($event);
                assert!(matches!(rx.recv().await.unwrap(), $check));
            }
        )+
    };
}

event_delivery_tests! {
    state_changed_event_is_delivered => HaEvent::StateChanged(json!({"entity_id":"light.a"})), HaEvent::StateChanged(_),
    device_registry_event_is_delivered => HaEvent::DeviceRegistryUpdated(json!({"device":"d"})), HaEvent::DeviceRegistryUpdated(_),
    entity_registry_event_is_delivered => HaEvent::EntityRegistryUpdated(json!({"entity":"e"})), HaEvent::EntityRegistryUpdated(_),
    unknown_event_is_delivered => HaEvent::Unknown(json!({"type":"x"})), HaEvent::Unknown(_),
    notification_event_is_delivered => HaEvent::NotificationCreated { id: "n".into(), title: "t".into(), message: "m".into(), severity: "info".into() }, HaEvent::NotificationCreated { .. },
}

#[tokio::test]
async fn publish_without_subscribers_does_not_panic() {
    EventBus::new().publish(HaEvent::Unknown(json!({"ok": true})));
}

#[tokio::test]
async fn subscriber_created_after_publish_does_not_receive_old_event() {
    let bus = EventBus::new();
    bus.publish(HaEvent::Unknown(json!({"old": true})));
    let mut rx = bus.subscribe();
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn multiple_subscribers_receive_same_event() {
    let bus = EventBus::new();
    let mut a = bus.subscribe();
    let mut b = bus.subscribe();
    bus.publish(HaEvent::StateChanged(json!({"state": "on"})));
    assert!(matches!(a.recv().await.unwrap(), HaEvent::StateChanged(_)));
    assert!(matches!(b.recv().await.unwrap(), HaEvent::StateChanged(_)));
}

#[tokio::test]
async fn state_changed_payload_is_preserved() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    bus.publish(HaEvent::StateChanged(
        json!({"data":{"entity_id":"sensor.a"}}),
    ));
    match rx.recv().await.unwrap() {
        HaEvent::StateChanged(value) => assert_eq!(value["data"]["entity_id"], "sensor.a"),
        _ => panic!("wrong event"),
    }
}

#[tokio::test]
async fn notification_fields_are_preserved() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    bus.publish(HaEvent::NotificationCreated {
        id: "id".into(),
        title: "title".into(),
        message: "message".into(),
        severity: "critical".into(),
    });
    match rx.recv().await.unwrap() {
        HaEvent::NotificationCreated {
            id,
            title,
            message,
            severity,
        } => {
            assert_eq!(id, "id");
            assert_eq!(title, "title");
            assert_eq!(message, "message");
            assert_eq!(severity, "critical");
        }
        _ => panic!("wrong event"),
    }
}

#[tokio::test]
async fn cloned_event_can_be_published_twice() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    let event = HaEvent::Unknown(json!({"x": 1}));
    bus.publish(event.clone());
    bus.publish(event);
    assert!(rx.recv().await.is_ok());
    assert!(rx.recv().await.is_ok());
}

#[test]
fn debug_formats_each_event_variant() {
    let events = [
        HaEvent::StateChanged(json!({})),
        HaEvent::DeviceRegistryUpdated(json!({})),
        HaEvent::EntityRegistryUpdated(json!({})),
        HaEvent::Unknown(json!({})),
        HaEvent::NotificationCreated {
            id: "i".into(),
            title: "t".into(),
            message: "m".into(),
            severity: "s".into(),
        },
    ];
    for event in events {
        let rendered = format!("{event:?}");
        assert!(rendered.chars().any(|c| c.is_ascii_alphabetic()));
    }
}

#[tokio::test]
async fn dispatcher_start_returns_promptly() {
    start_event_dispatcher(EventBus::new()).await;
}

macro_rules! burst_tests {
    ($($name:ident => $count:expr),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let bus = EventBus::new();
                let mut rx = bus.subscribe();
                for idx in 0..$count {
                    bus.publish(HaEvent::Unknown(json!({ "idx": idx })));
                }
                for idx in 0..$count {
                    match rx.recv().await.unwrap() {
                        HaEvent::Unknown(value) => assert_eq!(value["idx"], idx),
                        _ => panic!("wrong event"),
                    }
                }
            }
        )+
    };
}

burst_tests! {
    burst_one_event_preserves_order => 1,
    burst_two_events_preserves_order => 2,
    burst_five_events_preserves_order => 5,
    burst_ten_events_preserves_order => 10,
}

#[tokio::test]
async fn independent_buses_do_not_cross_deliver() {
    let a = EventBus::new();
    let b = EventBus::new();
    let mut rx_b = b.subscribe();
    a.publish(HaEvent::Unknown(json!({"a": true})));
    assert!(matches!(rx_b.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn event_bus_arc_clone_shares_sender() {
    let bus = EventBus::new();
    let cloned = bus.clone();
    let mut rx = bus.subscribe();
    cloned.publish(HaEvent::Unknown(json!({"shared": true})));
    assert!(matches!(rx.recv().await.unwrap(), HaEvent::Unknown(_)));
}

#[tokio::test]
async fn receiver_can_be_dropped_before_publish() {
    let bus = EventBus::new();
    let rx = bus.subscribe();
    drop(rx);
    bus.publish(HaEvent::Unknown(json!({"ok": true})));
}

#[tokio::test]
async fn two_events_of_different_variants_keep_order() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    bus.publish(HaEvent::StateChanged(json!({"n": 1})));
    bus.publish(HaEvent::DeviceRegistryUpdated(json!({"n": 2})));
    assert!(matches!(rx.recv().await.unwrap(), HaEvent::StateChanged(_)));
    assert!(matches!(
        rx.recv().await.unwrap(),
        HaEvent::DeviceRegistryUpdated(_)
    ));
}

#[tokio::test]
async fn empty_json_payload_is_preserved() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    bus.publish(HaEvent::Unknown(json!({})));
    match rx.recv().await.unwrap() {
        HaEvent::Unknown(value) => assert_eq!(value, json!({})),
        _ => panic!("wrong event"),
    }
}

#[tokio::test]
async fn null_json_payload_is_preserved() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    bus.publish(HaEvent::Unknown(serde_json::Value::Null));
    match rx.recv().await.unwrap() {
        HaEvent::Unknown(value) => assert!(value.is_null()),
        _ => panic!("wrong event"),
    }
}

#[tokio::test]
async fn array_json_payload_is_preserved() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    bus.publish(HaEvent::Unknown(json!([1, 2, 3])));
    match rx.recv().await.unwrap() {
        HaEvent::Unknown(value) => assert_eq!(value.as_array().unwrap().len(), 3),
        _ => panic!("wrong event"),
    }
}

#[tokio::test]
async fn subscriber_receives_after_prior_empty_poll() {
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    bus.publish(HaEvent::Unknown(json!({"later": true})));
    assert!(rx.recv().await.is_ok());
}
