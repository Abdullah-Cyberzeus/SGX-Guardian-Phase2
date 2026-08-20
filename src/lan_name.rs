//! Stable, human-readable LAN names shared by boards and Docker deployments.

/// Convert a configured node ID such as `nodeA` into a DNS-safe host label.
pub fn host_label(node_id: &str) -> String {
    let label: String = node_id
        .chars()
        .filter_map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                Some(character.to_ascii_lowercase())
            } else {
                None
            }
        })
        .collect();
    let label = label.trim_matches('-');
    if label.is_empty() {
        "guardian".into()
    } else {
        label.into()
    }
}

pub fn fqdn(node_id: &str) -> String {
    format!("{}.guardian", host_label(node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_guardian_names_are_dns_safe() {
        assert_eq!(host_label("nodeA"), "nodea");
        assert_eq!(fqdn("nodeB"), "nodeb.guardian");
        assert_eq!(fqdn(" Node_C "), "nodec.guardian");
    }
}
