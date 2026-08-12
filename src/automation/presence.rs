use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq)]
pub enum PresenceState {
    Home,
    NobodyHome,
    Unknown,
}

impl PresenceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PresenceState::Home => "home",
            PresenceState::NobodyHome => "nobody_home",
            PresenceState::Unknown => "unknown",
        }
    }
}

pub struct PresenceTracker {
    tracked_entities: RwLock<HashMap<String, String>>,
}

impl PresenceTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tracked_entities: RwLock::new(HashMap::new()),
        })
    }

    /// Checks if an entity is a person or device tracker entity
    pub fn is_presence_entity(entity_id: &str) -> bool {
        entity_id.starts_with("person.") || entity_id.starts_with("device_tracker.")
    }

    /// Updates the state of a presence entity
    pub async fn update_entity_state(&self, entity_id: &str, state: &str) {
        if !Self::is_presence_entity(entity_id) {
            return;
        }

        let mut map = self.tracked_entities.write().await;
        map.insert(entity_id.to_string(), state.to_string());
    }

    /// Computes global presence state
    pub async fn get_presence_status(&self) -> PresenceState {
        let map = self.tracked_entities.read().await;
        if map.is_empty() {
            return PresenceState::Unknown;
        }

        let any_home = map.values().any(|s| s == "home" || s == "on");
        if any_home {
            PresenceState::Home
        } else {
            PresenceState::NobodyHome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_presence_transitions() {
        let tracker = PresenceTracker::new();
        assert_eq!(tracker.get_presence_status().await, PresenceState::Unknown);

        // Person 1 arrives home
        tracker.update_entity_state("person.ahsan", "home").await;
        assert_eq!(tracker.get_presence_status().await, PresenceState::Home);

        // Person 1 leaves
        tracker
            .update_entity_state("person.ahsan", "not_home")
            .await;
        assert_eq!(
            tracker.get_presence_status().await,
            PresenceState::NobodyHome
        );
    }
}
