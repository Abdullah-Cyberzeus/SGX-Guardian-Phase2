use sgx_guardian_client::audit::hasher::AuditHashChain;
use sha2::{Digest, Sha256};

fn expected(previous: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[test]
fn new_chain_starts_at_genesis() {
    assert_eq!(AuditHashChain::new().last_hash(), "GENESIS");
}

#[test]
fn default_chain_starts_at_genesis() {
    assert_eq!(AuditHashChain::default().last_hash(), "GENESIS");
}

#[test]
fn set_last_hash_replaces_state() {
    let mut chain = AuditHashChain::new();
    chain.set_last_hash("abc".into());
    assert_eq!(chain.last_hash(), "abc");
}

#[test]
fn next_hash_matches_sha256_previous_plus_payload() {
    let mut chain = AuditHashChain::new();
    assert_eq!(chain.next_hash("payload"), expected("GENESIS", "payload"));
}

#[test]
fn next_hash_updates_last_hash() {
    let mut chain = AuditHashChain::new();
    let next = chain.next_hash("payload");
    assert_eq!(chain.last_hash(), next);
}

#[test]
fn identical_new_chains_are_deterministic() {
    assert_eq!(
        AuditHashChain::new().next_hash("payload"),
        AuditHashChain::new().next_hash("payload")
    );
}

#[test]
fn different_payloads_produce_different_hashes() {
    assert_ne!(
        AuditHashChain::new().next_hash("payload-a"),
        AuditHashChain::new().next_hash("payload-b")
    );
}

#[test]
fn different_previous_hashes_produce_different_hashes() {
    let mut a = AuditHashChain::new();
    let mut b = AuditHashChain::new();
    b.set_last_hash("other".into());
    assert_ne!(a.next_hash("payload"), b.next_hash("payload"));
}

#[test]
fn chained_hashes_depend_on_order() {
    let mut a = AuditHashChain::new();
    let first = a.next_hash("a");
    let second = a.next_hash("b");

    let mut b = AuditHashChain::new();
    b.next_hash("b");
    let reversed = b.next_hash("a");
    assert_ne!(second, reversed);
    assert_ne!(first, second);
}

#[test]
fn empty_payload_hashes_successfully() {
    assert_eq!(AuditHashChain::new().next_hash(""), expected("GENESIS", ""));
}

#[test]
fn whitespace_payload_is_distinct_from_empty() {
    assert_ne!(AuditHashChain::new().next_hash(" "), AuditHashChain::new().next_hash(""));
}

#[test]
fn newline_payload_is_distinct_from_space() {
    assert_ne!(AuditHashChain::new().next_hash("\n"), AuditHashChain::new().next_hash(" "));
}

#[test]
fn unicode_payload_hashes_deterministically() {
    assert_eq!(
        AuditHashChain::new().next_hash("policy-✓"),
        AuditHashChain::new().next_hash("policy-✓")
    );
}

#[test]
fn json_payload_hashes_deterministically() {
    let payload = r#"{"event":"audit","ok":true}"#;
    assert_eq!(AuditHashChain::new().next_hash(payload), expected("GENESIS", payload));
}

#[test]
fn long_payload_hashes_to_sha256_hex_length() {
    assert_eq!(AuditHashChain::new().next_hash(&"x".repeat(8192)).len(), 64);
}

#[test]
fn hash_is_lowercase_hex() {
    let hash = AuditHashChain::new().next_hash("payload");
    assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
}

#[test]
fn set_last_hash_to_empty_is_allowed() {
    let mut chain = AuditHashChain::new();
    chain.set_last_hash(String::new());
    assert_eq!(chain.next_hash("payload"), expected("", "payload"));
}

#[test]
fn set_last_hash_to_previous_output_resumes_chain() {
    let mut first = AuditHashChain::new();
    let checkpoint = first.next_hash("one");
    let expected_next = first.next_hash("two");

    let mut resumed = AuditHashChain::new();
    resumed.set_last_hash(checkpoint);
    assert_eq!(resumed.next_hash("two"), expected_next);
}

#[test]
fn clone_preserves_last_hash() {
    let mut chain = AuditHashChain::new();
    chain.next_hash("one");
    assert_eq!(chain.clone().last_hash(), chain.last_hash());
}

#[test]
fn debug_includes_struct_name() {
    assert!(format!("{:?}", AuditHashChain::new()).contains("AuditHashChain"));
}

#[test]
fn first_hash_after_manual_seed_uses_manual_seed() {
    let mut chain = AuditHashChain::new();
    chain.set_last_hash("seed".into());
    assert_eq!(chain.next_hash("payload"), expected("seed", "payload"));
}

#[test]
fn subsequent_hash_uses_previous_hash_not_genesis() {
    let mut chain = AuditHashChain::new();
    let first = chain.next_hash("first");
    assert_eq!(chain.next_hash("second"), expected(&first, "second"));
}

#[test]
fn multiple_empty_payloads_advance_chain() {
    let mut chain = AuditHashChain::new();
    let first = chain.next_hash("");
    let second = chain.next_hash("");
    assert_ne!(first, second);
}

#[test]
fn payload_case_changes_hash() {
    assert_ne!(AuditHashChain::new().next_hash("abc"), AuditHashChain::new().next_hash("ABC"));
}

#[test]
fn previous_hash_case_changes_hash() {
    let mut lower = AuditHashChain::new();
    lower.set_last_hash("abc".into());
    let mut upper = AuditHashChain::new();
    upper.set_last_hash("ABC".into());
    assert_ne!(lower.next_hash("payload"), upper.next_hash("payload"));
}

#[test]
fn last_hash_reference_tracks_latest_state() {
    let mut chain = AuditHashChain::new();
    chain.next_hash("one");
    let after_one = chain.last_hash().to_string();
    chain.next_hash("two");
    assert_ne!(chain.last_hash(), after_one);
}
