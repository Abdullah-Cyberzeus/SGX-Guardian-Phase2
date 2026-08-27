use sgx_guardian_client::did::document::Proof;
use sgx_guardian_client::vault::errors::VaultError;
use sgx_guardian_client::vault::folders::{FolderIndex, FolderNode};
use sgx_guardian_client::vault::namespace::VaultNamespace;

fn make_folder(id: &str, parent_id: &str, name: &str) -> FolderNode {
    FolderNode {
        folder_id: id.to_string(),
        parent_id: parent_id.to_string(),
        name: name.to_string(),
        created_at: "2026-08-27T00:00:00Z".to_string(),
    }
}

#[test]
fn test_vault_namespace_personal_and_circle_isolation() {
    let personal_ns = VaultNamespace::Personal;
    assert_eq!(personal_ns.storage_key(), "personal");
    assert!(personal_ns.is_personal());

    let circle_ns = VaultNamespace::parse("circle-engineering-alpha").unwrap();
    assert_eq!(circle_ns.storage_key(), "circle-engineering-alpha");
    assert!(!circle_ns.is_personal());

    let mut personal_index = FolderIndex::new(&personal_ns);
    let mut circle_index = FolderIndex::new(&circle_ns);

    personal_index
        .folders
        .push(make_folder("p1", "", "Personal Docs"));
    circle_index
        .folders
        .push(make_folder("c1", "", "Team Shared"));

    assert!(personal_index.contains_folder("p1"));
    assert!(!personal_index.contains_folder("c1"));

    assert!(circle_index.contains_folder("c1"));
    assert!(!circle_index.contains_folder("p1"));
}

#[test]
fn test_deep_folder_hierarchy_and_breadcrumbs_resolution() {
    let ns = VaultNamespace::Personal;
    let mut index = FolderIndex::new(&ns);

    // Build a 4-tier tree:
    // Root -> Projects -> 2026 -> Phase2
    index
        .folders
        .push(make_folder("node-root", "", "Projects"));
    index
        .folders
        .push(make_folder("node-2026", "node-root", "2026"));
    index
        .folders
        .push(make_folder("node-p2", "node-2026", "Phase2"));
    index
        .folders
        .push(make_folder("node-notes", "node-p2", "Meeting Notes"));

    // Breadcrumbs for leaf node
    let crumbs = index
        .breadcrumbs("node-notes")
        .expect("resolve breadcrumbs");
    assert_eq!(crumbs.len(), 4);
    assert_eq!(crumbs[0].name, "Projects");
    assert_eq!(crumbs[1].name, "2026");
    assert_eq!(crumbs[2].name, "Phase2");
    assert_eq!(crumbs[3].name, "Meeting Notes");

    // Children query for root
    let root_children = index.children_of("node-root");
    assert_eq!(root_children.len(), 1);
    assert_eq!(root_children[0].folder_id, "node-2026");

    // Query non-existent folder
    let err = index.breadcrumbs("missing-uuid");
    assert!(matches!(err, Err(VaultError::NotFound(_))));
}

#[test]
fn test_folder_index_canonical_signing_and_serde() {
    let ns = VaultNamespace::parse("circle-finance").unwrap();
    let mut index = FolderIndex::new(&ns);
    index.folders.push(make_folder("f1", "", "Reports"));
    index.proof = Proof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: "ecdsa-2019".into(),
        created: "2026-08-27T00:00:00Z".into(),
        verification_method: "did:guardian:node#key-1".into(),
        proof_purpose: "assertionMethod".into(),
        proof_value: "sig_mock_value".into(),
    };

    let without_proof = index.without_proof();
    assert!(without_proof.proof.proof_value.is_empty());
    assert_eq!(without_proof.folders.len(), 1);

    // Canonical bytes must be deterministic and exclude signature proof value
    let bytes1 = index.canonical_bytes_for_sign().unwrap();
    let bytes2 = without_proof.canonical_bytes_for_sign().unwrap();
    assert_eq!(bytes1, bytes2);

    // Full JSON roundtrip
    let json = serde_json::to_string(&index).expect("serialize folder index");
    let recovered: FolderIndex =
        serde_json::from_str(&json).expect("deserialize folder index");
    assert_eq!(recovered.namespace, "circle-finance");
    assert_eq!(recovered.folders.len(), 1);
    assert_eq!(recovered.folders[0].name, "Reports");
}
