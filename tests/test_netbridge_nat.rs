use sgx_guardian_client::netbridge::nat::NatManager;

#[test]
fn test_nat_manager_creation() {
    let manager = NatManager::new();
    assert!(!manager.is_enabled());
}

#[test]
fn test_disable_nat_when_not_enabled() {
    let manager = NatManager::new();
    // Disabling when not enabled should return Ok(()) without calling enforcement engine
    let res = manager.disable_nat();
    assert!(res.is_ok());
    assert!(!manager.is_enabled());
}
