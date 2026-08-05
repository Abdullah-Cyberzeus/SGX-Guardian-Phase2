use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tokio::time::{timeout, Duration};
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, PartialEq)]
pub enum CommandResult {
    Success,
    Timeout,
}

pub struct CommandTracker {
    // Map of entity_id -> map of command_id -> Sender
    pending: RwLock<HashMap<String, HashMap<String, oneshot::Sender<CommandResult>>>>,
}

impl CommandTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: RwLock::new(HashMap::new()),
        })
    }

    /// Registers a new command and returns a command ID and a Future that resolves
    /// when the command is acknowledged (via state change) or times out.
    pub async fn register_command(&self, entity_id: &str) -> (String, oneshot::Receiver<CommandResult>) {
        let cmd_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();

        let mut pending = self.pending.write().await;
        let entity_map = pending.entry(entity_id.to_string()).or_insert_with(HashMap::new);
        entity_map.insert(cmd_id.clone(), tx);

        (cmd_id, rx)
    }

    /// Wait for a registered command, with a built-in 15s timeout
    pub async fn wait_for_command(rx: oneshot::Receiver<CommandResult>) -> CommandResult {
        match timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(result)) => result,
            _ => CommandResult::Timeout,
        }
    }

    /// Called by the EventBus dispatcher when an entity state changes.
    /// This resolves any pending commands for that entity_id.
    pub async fn resolve_commands_for_entity(&self, entity_id: &str) {
        let mut pending = self.pending.write().await;
        if let Some(entity_map) = pending.remove(entity_id) {
            for (cmd_id, tx) in entity_map {
                if tx.send(CommandResult::Success).is_err() {
                    warn!("Failed to send CommandResult for cmd {}. Receiver dropped.", cmd_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_command_registration_and_resolution() {
        let tracker = CommandTracker::new();
        let entity_id = "light.test_light";

        let (cmd_id, rx) = tracker.register_command(entity_id).await;
        assert!(!cmd_id.is_empty());

        // Resolve commands
        tracker.resolve_commands_for_entity(entity_id).await;

        let result = CommandTracker::wait_for_command(rx).await;
        assert_eq!(result, CommandResult::Success);
    }
}
