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

    #[test]
    fn host_label_lowercases_ascii_letters_and_preserves_digits_and_hyphens() {
        assert_eq!(host_label("NODE-123"), "node-123");
        assert_eq!(host_label("MiXeD-Case-9"), "mixed-case-9");
        assert_eq!(host_label("a-b-c"), "a-b-c");
    }

    #[test]
    fn host_label_removes_non_dns_safe_characters() {
        assert_eq!(host_label("node_A"), "nodea");
        assert_eq!(host_label("node.example.com"), "nodeexamplecom");
        assert_eq!(host_label("node@example!com"), "nodeexamplecom");
        assert_eq!(host_label("node A\tB\nC"), "nodeabc");
    }

    #[test]
    fn host_label_trims_leading_and_trailing_hyphens_after_filtering() {
        assert_eq!(host_label("-node-"), "node");
        assert_eq!(host_label("---node---"), "node");
        assert_eq!(host_label("!#-node-#!"), "node");
        assert_eq!(host_label("a--b"), "a--b");
    }

    #[test]
    fn host_label_falls_back_to_guardian_for_empty_or_all_invalid_inputs() {
        assert_eq!(host_label(""), "guardian");
        assert_eq!(host_label("   "), "guardian");
        assert_eq!(host_label("___"), "guardian");
        assert_eq!(host_label("---"), "guardian");
        assert_eq!(host_label("!@#$%^&*()"), "guardian");
        assert_eq!(
            host_label("\u{0633}\u{0644}\u{0627}\u{0645}"),
            "guardian"
        );
    }

    #[test]
    fn host_label_handles_ascii_boundaries_and_unicode_by_filtering() {
        assert_eq!(host_label("A0Z9"), "a0z9");
        assert_eq!(host_label("\u{00f1}ode-A"), "ode-a");
        assert_eq!(host_label("node\u{1f4be}A"), "nodea");
        assert_eq!(host_label("\u{00e9}-Node-\u{00df}"), "node");
    }

    #[test]
    fn fqdn_uses_host_label_result_for_edge_cases() {
        assert_eq!(fqdn("NODE-123"), "node-123.guardian");
        assert_eq!(fqdn("___"), "guardian.guardian");
        assert_eq!(fqdn("-Node_C-"), "nodec.guardian");
    }
}
