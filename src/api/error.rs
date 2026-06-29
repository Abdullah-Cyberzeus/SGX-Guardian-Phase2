//! Uniform API error envelope.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound(m) => {
                let body = Json(json!({ "error": { "code": "NOT_FOUND", "message": m } }));
                (StatusCode::NOT_FOUND, body).into_response()
            }
            ApiError::BadRequest(m) => {
                let body = Json(json!({ "error": { "code": "BAD_REQUEST", "message": m } }));
                (StatusCode::BAD_REQUEST, body).into_response()
            }
            ApiError::Unauthorized(m) => {
                let body = Json(json!({ "error": { "code": "UNAUTHORIZED", "message": m } }));
                (StatusCode::UNAUTHORIZED, body).into_response()
            }
            ApiError::Forbidden(m) => {
                let body = Json(json!({ "error": { "code": "FORBIDDEN", "message": m } }));
                (StatusCode::FORBIDDEN, body).into_response()
            }
            ApiError::Conflict(m) => {
                let body = Json(json!({ "error": { "code": "CONFLICT", "message": m } }));
                (StatusCode::CONFLICT, body).into_response()
            }
            ApiError::Internal(ref msg) => {
                eprintln!("API Internal Error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error", "code": "INTERNAL"})),
                )
                    .into_response()
            }
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Internal(format!("io: {}", e))
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("json: {}", e))
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}
