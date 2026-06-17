use sgx_guardian_client::discovery::raw_store::RawXmlStore;
use tempfile::tempdir;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn raw_store_keeps_only_last_ten_files() {
    let dir = tempdir().unwrap();
    let state_dir = dir.path().join("discovery");

    for idx in 0..12 {
        RawXmlStore::persist(&state_dir, &format!("<nmaprun>{}</nmaprun>", idx)).unwrap();
        if idx < 11 {
            sleep(Duration::from_millis(1100)).await;
        }
    }

    let entries = RawXmlStore::list(&state_dir).unwrap();
    assert_eq!(entries.len(), 10);
}
