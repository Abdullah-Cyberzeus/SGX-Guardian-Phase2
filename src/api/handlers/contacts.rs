use crate::api::{error::ApiError, state::AppState};
use crate::contacts::store::{self, Contact, ContactDraft, ContactPatch};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct ContactsResponse {
    pub contacts: Vec<Contact>,
    pub total: usize,
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct ContactMutationResponse {
    pub success: bool,
    pub contact: Contact,
}

#[derive(Serialize)]
pub struct ContactDeleteResponse {
    pub success: bool,
    pub did: String,
}

fn contacts_path(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.admin_dir).join("contacts.json")
}

pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<ContactsResponse>, ApiError> {
    let contacts = store::list(&contacts_path(&state)).await?;
    let total = contacts.len();
    Ok(Json(ContactsResponse {
        contacts,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<Contact>, ApiError> {
    Ok(Json(store::get(&contacts_path(&state), &did).await?))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(draft): Json<ContactDraft>,
) -> Result<Json<ContactMutationResponse>, ApiError> {
    let contact = store::create(&contacts_path(&state), draft).await?;
    Ok(Json(ContactMutationResponse {
        success: true,
        contact,
    }))
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(patch): Json<ContactPatch>,
) -> Result<Json<ContactMutationResponse>, ApiError> {
    let contact = store::update(&contacts_path(&state), &did, patch).await?;
    Ok(Json(ContactMutationResponse {
        success: true,
        contact,
    }))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<ContactDeleteResponse>, ApiError> {
    store::delete(&contacts_path(&state), &did).await?;
    Ok(Json(ContactDeleteResponse { success: true, did }))
}
