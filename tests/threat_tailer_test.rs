use std::io::Write;
use std::time::Duration;

use sgx_guardian_client::threat::eve_tailer::EveTailer;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

fn alert_line(id: u32, src: &str) -> String {
    alert_line_with_signature(id, src, "ET MALWARE EICAR Test")
}

fn alert_line_with_signature(id: u32, src: &str, signature: &str) -> String {
    format!(
        r#"{{"timestamp":"2026-06-04T10:00:00Z","event_type":"alert","src_ip":"{src}","src_port":4444,"dest_ip":"198.51.100.20","dest_port":80,"proto":"TCP","alert":{{"signature_id":{id},"signature":"{signature}","severity":1,"rev":1,"gid":1}}}}"#
    )
}

#[tokio::test]
async fn tailer_delivers_written_alerts() {
    let dir = tempdir().expect("tempdir");
    let eve_path = dir.path().join("eve.json");
    let offset_path = dir.path().join("offset.json");
    std::fs::write(
        &eve_path,
        format!(
            "{}\n{}\n{}\n",
            alert_line(1, "192.0.2.1"),
            alert_line(2, "192.0.2.2"),
            alert_line(3, "192.0.2.3")
        ),
    )
    .expect("seed eve");

    let (tx, mut rx) = mpsc::channel(8);
    let handle = tokio::spawn(
        EveTailer {
            path: eve_path.clone(),
            offset_file: offset_path,
            out: tx,
        }
        .run(),
    );

    for expected in [1, 2, 3] {
        let alert = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("within timeout")
            .expect("alert");
        assert_eq!(alert.signature_id, expected);
    }

    handle.abort();
}

#[tokio::test]
async fn tailer_resumes_from_persisted_offset_without_duplicates() {
    let dir = tempdir().expect("tempdir");
    let eve_path = dir.path().join("eve.json");
    let offset_path = dir.path().join("offset.json");
    std::fs::write(&eve_path, format!("{}\n", alert_line(10, "192.0.2.10"))).expect("seed eve");

    let (tx, mut rx) = mpsc::channel(8);
    let handle = tokio::spawn(
        EveTailer {
            path: eve_path.clone(),
            offset_file: offset_path.clone(),
            out: tx,
        }
        .run(),
    );

    let first = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("within timeout")
        .expect("alert");
    assert_eq!(first.signature_id, 10);
    sleep(Duration::from_millis(400)).await;
    handle.abort();

    std::fs::OpenOptions::new()
        .append(true)
        .open(&eve_path)
        .expect("open append")
        .write_all(format!("{}\n", alert_line(11, "192.0.2.11")).as_bytes())
        .expect("append");

    let (tx2, mut rx2) = mpsc::channel(8);
    let handle2 = tokio::spawn(
        EveTailer {
            path: eve_path,
            offset_file: offset_path,
            out: tx2,
        }
        .run(),
    );

    let second = timeout(Duration::from_secs(2), rx2.recv())
        .await
        .expect("within timeout")
        .expect("alert");
    assert_eq!(second.signature_id, 11);
    assert!(timeout(Duration::from_millis(600), rx2.recv())
        .await
        .is_err());
    handle2.abort();
}

#[tokio::test]
async fn tailer_detects_rotation_and_restarts_from_zero() {
    let dir = tempdir().expect("tempdir");
    let eve_path = dir.path().join("eve.json");
    let offset_path = dir.path().join("offset.json");
    let long_signature = format!("ET MALWARE {}", "EICAR ".repeat(80));
    std::fs::write(
        &eve_path,
        format!(
            "{}\n",
            alert_line_with_signature(21, "192.0.2.21", &long_signature)
        ),
    )
    .expect("seed eve");

    let (tx, mut rx) = mpsc::channel(8);
    let handle = tokio::spawn(
        EveTailer {
            path: eve_path.clone(),
            offset_file: offset_path,
            out: tx,
        }
        .run(),
    );

    let first = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("within timeout")
        .expect("alert");
    assert_eq!(first.signature_id, 21);
    sleep(Duration::from_millis(400)).await;

    std::fs::write(&eve_path, format!("{}\n", alert_line(22, "192.0.2.22"))).expect("rotate eve");
    let second = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("within timeout")
        .expect("alert");
    assert_eq!(second.signature_id, 22);
    handle.abort();
}
