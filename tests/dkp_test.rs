use sgx_guardian_client::secure_element::pcr::PcrEngine;

#[test]
fn test_pcr_engine() {
    let mut engine = PcrEngine::new();
    assert!(!engine.all_measured());

    // Extend PCR 0
    let res = engine.extend_from_string(0, "test-measurement");
    assert!(res.is_ok());

    // Test snapshot
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.pcr_values.len(), 5);

    // Test composite digest
    let composite = engine.composite_digest();
    assert!(!composite.is_empty());
}
