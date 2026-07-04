use crate::threat::{error::ThreatResult, eve_parser, threat_alert::ThreatAlert};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

pub struct EveTailer {
    pub path: PathBuf,
    pub offset_file: PathBuf,
    pub out: Sender<ThreatAlert>,
}

impl EveTailer {
    pub async fn run(self) -> ThreatResult<()> {
        let mut offset = read_offset(&self.offset_file).unwrap_or(0);

        loop {
            if !self.path.exists() {
                sleep(Duration::from_secs(2)).await;
                continue;
            }

            let file = match File::open(&self.path).await {
                Ok(file) => file,
                Err(_) => {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            let meta = file.metadata().await?;
            if meta.len() < offset {
                offset = 0;
            }

            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(offset)).await?;

            let mut line_no = 0_u64;
            let mut buf = String::new();
            loop {
                buf.clear();
                let bytes_read = reader.read_line(&mut buf).await?;
                if bytes_read == 0 {
                    let _ = persist_offset(&self.offset_file, offset).await;
                    sleep(Duration::from_millis(250)).await;
                    let current_meta = tokio::fs::metadata(&self.path).await?;
                    if current_meta.len() < offset {
                        break;
                    }
                    continue;
                }

                offset += bytes_read as u64;
                line_no += 1;

                match eve_parser::parse_line(&buf, line_no) {
                    Ok(Some(alert)) => {
                        if self.out.send(alert).await.is_err() {
                            return Ok(());
                        }
                    }
                    Ok(None) => {}
                    Err(err) => tracing::warn!("eve parse error: {}", err),
                }

                if line_no.is_multiple_of(50) {
                    let _ = persist_offset(&self.offset_file, offset).await;
                }
            }
        }
    }
}

async fn persist_offset(path: &Path, offset: u64) -> ThreatResult<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, format!(r#"{{"offset":{offset}}}"#)).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn read_offset(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()?
        .get("offset")?
        .as_u64()
}
