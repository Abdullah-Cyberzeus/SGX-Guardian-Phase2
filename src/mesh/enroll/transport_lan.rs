//! P4.6 — LAN transport: submits an [`EnrollmentSubmission`] to a CA's
//! `/enroll` endpoint (`mesh::ca::server`) and polls `/enroll/{request_id}`
//! with capped exponential backoff until Approved/Rejected/Expired.
//!
//! The `(lan_endpoint, request_id)` pair is persisted immediately after a
//! successful submit, so a restart while `PENDING` resumes polling the same
//! request instead of submitting a duplicate one — [`load_pending`] is what
//! the caller checks at boot before deciding whether to build a fresh
//! submission at all.

use crate::mesh::ca::bundle::SignedEnrollmentBundle;
use crate::mesh::ca::requests::EnrollmentSubmission;
use crate::startup::GuardianPaths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("the CA rejected the request: {0}")]
    Rejected(String),
    #[error("the enrollment request expired before it was approved")]
    Expired,
    #[error("CA returned HTTP {0}")]
    BadStatus(u16),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingState {
    lan_endpoint: String,
    request_id: String,
}

fn pending_path(paths: &GuardianPaths) -> PathBuf {
    paths.var_root.join("mesh").join("enroll_pending.json")
}

pub fn save_pending(
    paths: &GuardianPaths,
    lan_endpoint: &str,
    request_id: &str,
) -> Result<(), TransportError> {
    let state = PendingState {
        lan_endpoint: lan_endpoint.to_string(),
        request_id: request_id.to_string(),
    };
    if let Some(parent) = pending_path(paths).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(pending_path(paths), serde_json::to_vec_pretty(&state)?)?;
    Ok(())
}

pub fn load_pending(paths: &GuardianPaths) -> Option<(String, String)> {
    let bytes = std::fs::read(pending_path(paths)).ok()?;
    let state: PendingState = serde_json::from_slice(&bytes).ok()?;
    Some((state.lan_endpoint, state.request_id))
}

pub fn clear_pending(paths: &GuardianPaths) {
    let _ = std::fs::remove_file(pending_path(paths));
}

#[derive(Deserialize)]
struct SubmitResponse {
    request_id: String,
}

fn http_client() -> Result<reqwest::Client, TransportError> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?)
}

pub async fn submit(
    lan_endpoint: &str,
    submission: &EnrollmentSubmission,
) -> Result<String, TransportError> {
    let client = http_client()?;
    let url = format!("http://{lan_endpoint}/enroll");
    let resp = client.post(&url).json(submission).send().await?;
    if !resp.status().is_success() {
        return Err(TransportError::BadStatus(resp.status().as_u16()));
    }
    let parsed: SubmitResponse = resp.json().await?;
    Ok(parsed.request_id)
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PollResponse {
    Pending,
    Approved { bundle: SignedEnrollmentBundle },
    Rejected { reason: Option<String> },
    Expired,
}

enum PollOutcome {
    StillPending,
    Approved(SignedEnrollmentBundle),
}

async fn poll_once(
    client: &reqwest::Client,
    lan_endpoint: &str,
    request_id: &str,
) -> Result<PollOutcome, TransportError> {
    let url = format!("http://{lan_endpoint}/enroll/{request_id}");
    let resp = client.get(&url).send().await?;
    if resp.status() == reqwest::StatusCode::ACCEPTED {
        // Approved but the bundle has not been issued yet — a narrow race
        // right at approval time. Treated exactly like still-pending; the
        // next poll tick almost always finds it issued.
        return Ok(PollOutcome::StillPending);
    }
    if !resp.status().is_success() {
        return Err(TransportError::BadStatus(resp.status().as_u16()));
    }
    match resp.json::<PollResponse>().await? {
        PollResponse::Pending => Ok(PollOutcome::StillPending),
        PollResponse::Approved { bundle } => Ok(PollOutcome::Approved(bundle)),
        PollResponse::Rejected { reason } => Err(TransportError::Rejected(
            reason.unwrap_or_else(|| "no reason given".to_string()),
        )),
        PollResponse::Expired => Err(TransportError::Expired),
    }
}

/// Polls with capped exponential backoff (2s → 4s → 8s → 16s → 30s, then
/// flat) until Approved, Rejected, Expired, a hard HTTP error, or `max_wait`
/// elapses. Callers that need to survive a process restart mid-wait persist
/// `(lan_endpoint, request_id)` via [`save_pending`] right after [`submit`]
/// succeeds, and on the next boot call this directly with the reloaded pair
/// instead of calling [`submit`] again — see [`load_pending`].
pub async fn poll_until_decided(
    lan_endpoint: &str,
    request_id: &str,
    max_wait: Duration,
) -> Result<SignedEnrollmentBundle, TransportError> {
    let client = http_client()?;
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut delay = Duration::from_secs(2);
    loop {
        match poll_once(&client, lan_endpoint, request_id).await {
            Ok(PollOutcome::Approved(bundle)) => return Ok(bundle),
            Ok(PollOutcome::StillPending) => {}
            Err(e) => return Err(e),
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(TransportError::Expired);
        }
        tokio::time::sleep(delay.min(deadline.saturating_duration_since(now))).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}
