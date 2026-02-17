use super::models::CircleMembership;

pub fn validate_circle_membership(membership: &CircleMembership) -> bool {
    // 🔐 Simulated VC validation logic

    if membership.is_valid && !membership.vc_hash.is_empty() {
        println!("✅ Circle membership validated for {}", membership.node_name);
        true
    } else {
        println!("❌ Invalid Circle membership for {}", membership.node_name);
        false
    }
}