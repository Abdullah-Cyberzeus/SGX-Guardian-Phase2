use sgx_guardian_client::automation::presence::{PresenceState, PresenceTracker};

#[test]
fn presence_state_home_as_str() {
    assert_eq!(PresenceState::Home.as_str(), "home");
}

#[test]
fn presence_state_nobody_home_as_str() {
    assert_eq!(PresenceState::NobodyHome.as_str(), "nobody_home");
}

#[test]
fn presence_state_unknown_as_str() {
    assert_eq!(PresenceState::Unknown.as_str(), "unknown");
}

#[test]
fn presence_state_clone_and_eq() {
    assert_eq!(PresenceState::Home.clone(), PresenceState::Home);
}

#[test]
fn person_entity_is_presence_entity() {
    assert!(PresenceTracker::is_presence_entity("person.alice"));
}

#[test]
fn device_tracker_entity_is_presence_entity() {
    assert!(PresenceTracker::is_presence_entity("device_tracker.phone"));
}

#[test]
fn uppercase_person_prefix_is_not_presence_entity() {
    assert!(!PresenceTracker::is_presence_entity("Person.alice"));
}

#[test]
fn bare_person_prefix_is_not_presence_entity() {
    assert!(!PresenceTracker::is_presence_entity("person"));
}

#[test]
fn light_entity_is_not_presence_entity() {
    assert!(!PresenceTracker::is_presence_entity("light.kitchen"));
}

#[test]
fn empty_entity_is_not_presence_entity() {
    assert!(!PresenceTracker::is_presence_entity(""));
}

#[tokio::test]
async fn new_tracker_starts_unknown() {
    assert_eq!(
        PresenceTracker::new().get_presence_status().await,
        PresenceState::Unknown
    );
}

#[tokio::test]
async fn person_home_sets_home() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.alice", "home").await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Home);
}

#[tokio::test]
async fn device_tracker_on_sets_home() {
    let tracker = PresenceTracker::new();
    tracker
        .update_entity_state("device_tracker.phone", "on")
        .await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Home);
}

#[tokio::test]
async fn person_not_home_sets_nobody_home() {
    let tracker = PresenceTracker::new();
    tracker
        .update_entity_state("person.alice", "not_home")
        .await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn person_off_sets_nobody_home() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.alice", "off").await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn unknown_state_counts_as_nobody_home_once_tracked() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.alice", "unknown").await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn non_presence_update_is_ignored() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("light.kitchen", "home").await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Unknown);
}

#[tokio::test]
async fn any_home_person_wins_over_not_home() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.a", "not_home").await;
    tracker.update_entity_state("person.b", "home").await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Home);
}

#[tokio::test]
async fn any_on_device_tracker_wins_over_off() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("device_tracker.a", "off").await;
    tracker.update_entity_state("device_tracker.b", "on").await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Home);
}

#[tokio::test]
async fn updating_same_entity_replaces_state() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.a", "home").await;
    tracker.update_entity_state("person.a", "not_home").await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn updating_same_entity_back_home_restores_home() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.a", "not_home").await;
    tracker.update_entity_state("person.a", "home").await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Home);
}

#[tokio::test]
async fn home_matching_is_case_sensitive() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.a", "Home").await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn on_matching_is_case_sensitive() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("device_tracker.a", "ON").await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn empty_state_counts_as_nobody_home() {
    let tracker = PresenceTracker::new();
    tracker.update_entity_state("person.a", "").await;
    assert_eq!(
        tracker.get_presence_status().await,
        PresenceState::NobodyHome
    );
}

#[tokio::test]
async fn entity_with_prefix_and_extra_dot_is_tracked() {
    let tracker = PresenceTracker::new();
    tracker
        .update_entity_state("person.alice.phone", "home")
        .await;
    assert_eq!(tracker.get_presence_status().await, PresenceState::Home);
}

#[tokio::test]
async fn separate_trackers_are_isolated() {
    let a = PresenceTracker::new();
    let b = PresenceTracker::new();
    a.update_entity_state("person.a", "home").await;
    assert_eq!(a.get_presence_status().await, PresenceState::Home);
    assert_eq!(b.get_presence_status().await, PresenceState::Unknown);
}
