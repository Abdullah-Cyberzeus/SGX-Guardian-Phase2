#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CircleMembership {
    pub node_name: String,
    pub circle_id: String,
    pub vc_hash: String,
    pub is_valid: bool,
}
