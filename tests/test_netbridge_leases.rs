use sgx_guardian_client::netbridge::leases::LeaseManager;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_get_active_leases_empty() {
    let dir = tempdir().unwrap();
    let lease_path = dir.path().join("dnsmasq.leases");

    // File does not exist yet
    let manager = LeaseManager::new(lease_path.to_str().unwrap());
    let leases = manager
        .get_active_leases()
        .expect("Should not fail if file missing");
    assert_eq!(leases.len(), 0);
}

#[test]
fn test_get_active_leases_with_data() {
    let dir = tempdir().unwrap();
    let lease_path = dir.path().join("dnsmasq.leases");

    // Write mock lease data
    fs::write(
        &lease_path,
        "1718712345 dc:a6:32:01:23:45 192.168.200.124 work-laptop 01:dc:a6:32:01:23:45\n1718715000 aa:bb:cc:dd:ee:ff 192.168.200.125 mobile-phone *\n",
    )
    .unwrap();

    let manager = LeaseManager::new(lease_path.to_str().unwrap());
    let leases = manager.get_active_leases().expect("Failed to parse leases");

    assert_eq!(leases.len(), 2);

    assert_eq!(leases[0].expiry, 1718712345);
    assert_eq!(leases[0].mac_address, "dc:a6:32:01:23:45");
    assert_eq!(leases[0].ip_address, "192.168.200.124");
    assert_eq!(leases[0].hostname, "work-laptop");
    assert_eq!(leases[0].client_id, "01:dc:a6:32:01:23:45");

    assert_eq!(leases[1].expiry, 1718715000);
    assert_eq!(leases[1].mac_address, "aa:bb:cc:dd:ee:ff");
    assert_eq!(leases[1].ip_address, "192.168.200.125");
    assert_eq!(leases[1].hostname, "mobile-phone");
    assert_eq!(leases[1].client_id, "*");
}

#[test]
fn test_get_active_leases_malformed_line() {
    let dir = tempdir().unwrap();
    let lease_path = dir.path().join("dnsmasq.leases");

    // Write mock lease data with a malformed line
    fs::write(
        &lease_path,
        "1718712345 dc:a6:32:01:23:45 192.168.200.124 work-laptop 01:dc:a6:32:01:23:45\nmalformed_line_with_few_parts\n",
    )
    .unwrap();

    let manager = LeaseManager::new(lease_path.to_str().unwrap());
    let leases = manager.get_active_leases().expect("Failed to parse leases");

    // Should skip the malformed line and parse the valid one
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].hostname, "work-laptop");
}
